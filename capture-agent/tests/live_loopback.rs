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
