// Issue #114 / JAM-52: every other test in this crate exercises
// parse_packet/sniff_l7/FlowTable against fixture bytes passed directly to
// those functions (see protocol_regression.rs) — none of them ever open a
// real pcap::Capture handle, select a real device, or run the real TCP
// listener main.rs binds. This test does: it spawns the actual compiled
// capture-agent binary against the real `lo` interface, drives real TCP
// traffic across it, and asserts on the wire events that traffic produces.
//
// Requires CAP_NET_RAW/CAP_NET_ADMIN (or root) to open a live capture —
// #[ignore]d so a plain `cargo test` (the default CI "Test" step, and any
// contributor's local run) never needs elevated privilege. CI runs this
// explicitly via a dedicated step in .github/workflows/ci.yml; see
// CONTRIBUTING.md for how to run it locally.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Kills the spawned agent process on drop — including on a panicking
/// assertion — so a failed run never leaves a live-capturing process
/// behind. `Child::kill` is idempotent-safe to call on an already-exited
/// process (returns an error, which this ignores).
struct AgentGuard(Child);

impl Drop for AgentGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Reads a child's stream to completion on a background thread, handing the
/// full contents back over a channel — used to capture the agent's
/// stdout/stderr for a diagnostic dump if this test's assertions fail,
/// since there's no interactive terminal to inspect in CI.
fn drain_to_string(mut reader: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = reader.read_to_string(&mut buf);
        let _ = tx.send(buf);
    });
    rx
}

fn poll_until<T>(timeout: Duration, mut attempt: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = attempt() {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "requires CAP_NET_RAW/CAP_NET_ADMIN (or root) to open a live capture on `lo`; run via `cargo test --test live_loopback -- --ignored` after granting the built binary that capability (see CONTRIBUTING.md) — CI does this in a dedicated step"]
fn captures_real_loopback_traffic_and_emits_matching_wire_events() {
    let bin = env!("CARGO_BIN_EXE_capture-agent");
    let mut child = Command::new(bin)
        .env("CAPTURE_INTERFACE", "lo")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn capture-agent binary");

    let stdout_rx = drain_to_string(child.stdout.take().unwrap());
    let stderr_rx = drain_to_string(child.stderr.take().unwrap());
    let guard = AgentGuard(child);

    // The agent needs a moment to open the pcap handle and bind its TCP
    // listener — poll/retry with a bounded timeout rather than a fixed
    // sleep, so this isn't a flaky race against however long that happens
    // to take on a given CI runner.
    let wire_stream = poll_until(Duration::from_secs(15), || TcpStream::connect("127.0.0.1:9990").ok())
        .unwrap_or_else(|| panic!("{}", diagnostics("agent never opened its TCP listener", &stdout_rx, &stderr_rx)));
    wire_stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let mut wire_reader = BufReader::new(wire_stream);

    // Real, known traffic on `lo`: a plain TCP listener + one client
    // connection, both loopback-local, entirely within this test process —
    // no external server/tooling needed. The agent (capturing on `lo`)
    // should observe this exchange as a distinct flow.
    let traffic_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let traffic_port = traffic_listener.local_addr().unwrap().port();
    let accept_thread = std::thread::spawn(move || {
        if let Ok((mut sock, _)) = traffic_listener.accept() {
            let mut buf = [0u8; 64];
            let _ = sock.read(&mut buf);
        }
    });
    // Give the agent a moment to be mid-poll-loop before generating
    // traffic, then connect and write a payload real enough for l7
    // sniffing to have something to look at (though this test only asserts
    // on the connection's ports, not its classified protocol — that's
    // protocol_regression.rs's job).
    std::thread::sleep(Duration::from_millis(200));
    {
        let mut client = TcpStream::connect(("127.0.0.1", traffic_port)).expect("failed to connect to traffic listener");
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    }
    accept_thread.join().unwrap();

    let mut saw_matching_connection_update = false;
    let mut saw_system_stats = false;
    let mut saw_capture_stats = false;
    let mut seen_lines: Vec<String> = Vec::new();

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut line = String::new();
    while Instant::now() < deadline
        && !(saw_matching_connection_update && saw_system_stats && saw_capture_stats)
    {
        line.clear();
        match wire_reader.read_line(&mut line) {
            Ok(0) => break, // agent closed the connection
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                seen_lines.push(trimmed.to_string());
                let Ok(event) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                    continue;
                };
                match event.get("type").and_then(|t| t.as_str()) {
                    Some("connection_update") => {
                        let conn = &event["connection"];
                        let local_port = conn.get("localPort").and_then(|v| v.as_u64());
                        let remote_port = conn.get("remotePort").and_then(|v| v.as_u64());
                        if local_port == Some(traffic_port as u64) || remote_port == Some(traffic_port as u64) {
                            saw_matching_connection_update = true;
                        }
                    }
                    Some("system_stats") => saw_system_stats = true,
                    Some("capture_stats") => saw_capture_stats = true,
                    _ => {}
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                continue; // read timeout — just means no data yet, keep polling until the deadline
            }
            Err(e) => panic!("error reading from agent wire socket: {e}"),
        }
    }

    if !(saw_matching_connection_update && saw_system_stats && saw_capture_stats) {
        panic!(
            "{}\nlocal traffic port was {traffic_port}\nsaw_matching_connection_update={saw_matching_connection_update} saw_system_stats={saw_system_stats} saw_capture_stats={saw_capture_stats}\n{} wire lines seen:\n{}",
            diagnostics("did not observe the expected wire events within the timeout", &stdout_rx, &stderr_rx),
            seen_lines.len(),
            seen_lines.join("\n"),
        );
    }

    drop(guard); // explicit for readability — would also run on scope exit
}

fn diagnostics(message: &str, stdout_rx: &mpsc::Receiver<String>, stderr_rx: &mpsc::Receiver<String>) -> String {
    // Non-blocking best-effort: the agent is still running (its stdout/
    // stderr pipes won't EOF until it exits), so these channels won't have
    // anything yet in the common case — this is only useful once the
    // caller has already torn the process down. Kept simple since the
    // primary diagnostic value here is the wire event dump at the call
    // site, not these streams.
    let stdout = stdout_rx.try_recv().unwrap_or_default();
    let stderr = stderr_rx.try_recv().unwrap_or_default();
    format!("{message}\nagent stdout: {stdout}\nagent stderr: {stderr}")
}

/// Capture-to-file, end to end against the real binary and a real `lo`
/// capture (JAM-125 Task 14, closing out the epic's Testing section).
///
/// Every other capture-to-file test in this crate exercises `pcapng::Writer`
/// or `ring::RingState` against an in-memory buffer or a temp file the test
/// itself drives. None of them prove the whole path works: a
/// `start_capture_file` control message arriving over the wire socket,
/// reaching the writer thread, a real capture's frames being written, and a
/// real file existing on disk afterward that begins with a valid pcapng
/// Section Header Block.
///
/// Note the file must live OUTSIDE the agent's working directory:
/// `validate_capture_file_path` (main.rs) rejects a path resolving inside
/// it, and `cargo test` runs this with the crate root as cwd. `temp_dir()`
/// satisfies that, and also keeps the `.data/` rule satisfied.
#[test]
#[ignore = "requires CAP_NET_RAW/CAP_NET_ADMIN (or root) to open a live capture on `lo`; same CI step as captures_real_loopback_traffic_and_emits_matching_wire_events"]
fn a_live_capture_written_to_file_opens_cleanly_afterward() {
    let capture_path = std::env::temp_dir().join(format!("capture-agent-live-loopback-{}.pcapng", std::process::id()));
    let _ = std::fs::remove_file(&capture_path); // a previous failed run may have left one

    let bin = env!("CARGO_BIN_EXE_capture-agent");
    let mut child = Command::new(bin)
        .env("CAPTURE_INTERFACE", "lo")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn capture-agent binary");

    let stdout_rx = drain_to_string(child.stdout.take().unwrap());
    let stderr_rx = drain_to_string(child.stderr.take().unwrap());
    let guard = AgentGuard(child);

    let wire_stream = poll_until(Duration::from_secs(15), || TcpStream::connect("127.0.0.1:9990").ok())
        .unwrap_or_else(|| panic!("{}", diagnostics("agent never opened its TCP listener", &stdout_rx, &stderr_rx)));
    wire_stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    // Control messages go back over the same connection, so this needs a
    // second handle: the reader below owns the stream inside a BufReader.
    let mut control = wire_stream.try_clone().expect("failed to clone wire socket for control writes");
    let mut wire_reader = BufReader::new(wire_stream);

    writeln!(
        control,
        r#"{{"type":"start_capture_file","path":"{}"}}"#,
        capture_path.display()
    )
    .expect("failed to send start_capture_file");
    control.flush().unwrap();

    // Same known loopback traffic the sibling test generates — the frames
    // the writer should end up persisting.
    let traffic_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let traffic_port = traffic_listener.local_addr().unwrap().port();
    let accept_thread = std::thread::spawn(move || {
        if let Ok((mut sock, _)) = traffic_listener.accept() {
            let mut buf = [0u8; 64];
            let _ = sock.read(&mut buf);
        }
    });
    std::thread::sleep(Duration::from_millis(200));
    {
        let mut client = TcpStream::connect(("127.0.0.1", traffic_port)).expect("failed to connect to traffic listener");
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    }
    accept_thread.join().unwrap();

    // Phase 1: wait for the agent to report it is actively writing bytes.
    // Phase 2: stop, and wait for it to report it has stopped. Both are
    // read off the same per-tick capture_file_status snapshot.
    let mut wrote_bytes = false;
    let mut stop_sent = false;
    let mut stopped = false;
    let mut capture_file_error: Option<String> = None;
    let mut seen_lines: Vec<String> = Vec::new();

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut line = String::new();
    while Instant::now() < deadline && !stopped && capture_file_error.is_none() {
        line.clear();
        match wire_reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                seen_lines.push(trimmed.to_string());
                let Ok(event) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                    continue;
                };
                match event.get("type").and_then(|t| t.as_str()) {
                    // A rejected start is a hard failure, not something to
                    // time out on — surface the agent's own reason.
                    Some("capture_file_error") => {
                        capture_file_error =
                            Some(event.get("message").and_then(|m| m.as_str()).unwrap_or("(no message)").to_string());
                    }
                    Some("capture_file_status") => {
                        let status = &event["status"];
                        let writing = status.get("writing").and_then(|v| v.as_bool()).unwrap_or(false);
                        let bytes = status.get("bytesWritten").and_then(|v| v.as_u64()).unwrap_or(0);
                        if writing && bytes > 0 {
                            wrote_bytes = true;
                            if !stop_sent {
                                writeln!(control, r#"{{"type":"stop_capture_file"}}"#)
                                    .expect("failed to send stop_capture_file");
                                control.flush().unwrap();
                                stop_sent = true;
                            }
                        }
                        if stop_sent && !writing {
                            stopped = true;
                        }
                    }
                    _ => {}
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => panic!("error reading from agent wire socket: {e}"),
        }
    }

    // Tear the agent down before asserting, so the writer has flushed and
    // closed the file and the diagnostics helper can drain its pipes.
    drop(guard);

    let fail = |message: &str| -> String {
        format!(
            "{}\ncapture path: {}\nwrote_bytes={wrote_bytes} stop_sent={stop_sent} stopped={stopped}\n{} wire lines seen:\n{}",
            diagnostics(message, &stdout_rx, &stderr_rx),
            capture_path.display(),
            seen_lines.len(),
            seen_lines.join("\n"),
        )
    };

    if let Some(message) = capture_file_error {
        let rendered = fail(&format!("agent rejected start_capture_file: {message}"));
        let _ = std::fs::remove_file(&capture_path);
        panic!("{rendered}");
    }
    if !wrote_bytes {
        let rendered = fail("never saw capture_file_status reporting writing:true with bytesWritten > 0");
        let _ = std::fs::remove_file(&capture_path);
        panic!("{rendered}");
    }
    if !stopped {
        let rendered = fail("capture never reported writing:false after stop_capture_file");
        let _ = std::fs::remove_file(&capture_path);
        panic!("{rendered}");
    }

    // The point of this test: a real file, on disk, that really parses.
    let bytes = match std::fs::read(&capture_path) {
        Ok(b) => b,
        Err(e) => {
            let rendered = fail(&format!("capture file could not be read back: {e}"));
            panic!("{rendered}");
        }
    };
    let _ = std::fs::remove_file(&capture_path);

    assert!(
        bytes.len() > 28,
        "capture file is too small to contain even a Section Header Block ({} bytes)",
        bytes.len()
    );
    // A pcapng file opens with the Section Header Block: block type
    // 0x0A0D0D0A first, then the 4-byte block length, then the byte-order
    // magic 0x1A2B3C4D at offset 8. (The plan's sketch said the byte-order
    // magic was the *first* four bytes — it is not; the block type is.)
    assert_eq!(
        &bytes[0..4],
        &0x0A0D_0D0Au32.to_le_bytes(),
        "capture file does not start with the pcapng Section Header Block type"
    );
    assert_eq!(
        &bytes[8..12],
        &0x1A2B_3C4Du32.to_le_bytes(),
        "capture file's Section Header Block is missing its byte-order magic"
    );
}
