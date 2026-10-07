//! Actual binary replay coverage for JAM-194. Serialized fixed-port child processes.
#[path = "fixtures/agent_auth.rs"]
mod agent_auth;
#[path = "fixtures/third_party_capture.rs"]
mod third_party_capture;
use etherparse::PacketBuilder;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

static REPLAY_AGENT_LOCK: Mutex<()> = Mutex::new(());

fn dns_payload(id: u16, response: bool) -> Vec<u8> {
    let mut bytes = Vec::from(id.to_be_bytes());
    bytes.extend((if response { 0x8180u16 } else { 0x0100u16 }).to_be_bytes());
    bytes.extend(1u16.to_be_bytes()); // questions
    bytes.extend(0u16.to_be_bytes()); // answers
    bytes.extend(0u32.to_be_bytes()); // authority and additional
    bytes.extend([4, b't', b'e', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
    bytes.extend(1u16.to_be_bytes()); // A
    bytes.extend(1u16.to_be_bytes()); // IN
    bytes
}

fn ethernet_udp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
        .ipv4(src, dst, 64)
        .udp(src_port, dst_port)
        .write(&mut frame, payload)
        .unwrap();
    frame
}

fn timestamped_classic_pcap(label: &str) -> (third_party_capture::CaptureFile, Vec<u8>) {
    let local = [192, 0, 2, 1];
    let server = [198, 51, 100, 53];
    let query = ethernet_udp(local, server, 53000, 53, &dns_payload(0x1234, false));
    let response = ethernet_udp(server, local, 53, 53000, &dns_payload(0x1234, true));
    let unanswered = ethernet_udp(local, server, 53000, 53, &dns_payload(0x5678, false));
    let filler = ethernet_udp(local, server, 20000, 20001, b"padding");
    let final_packet = ethernet_udp(local, server, 20002, 20003, b"timestamp-target");
    let malformed = [0u8; 4];

    let mut bytes = Vec::new();
    bytes.extend(0xa1b2c3d4u32.to_le_bytes());
    bytes.extend(2u16.to_le_bytes());
    bytes.extend(4u16.to_le_bytes());
    bytes.extend([0; 8]);
    bytes.extend(65535u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    let mut append = |seconds: u32, micros: u32, frame: &[u8]| {
        bytes.extend(seconds.to_le_bytes());
        bytes.extend(micros.to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend(frame);
    };
    append(100, 0, &query);
    append(100, 500_000, &response);
    append(101, 0, &unanswered);
    // Keep fast replay alive long enough for the authenticated observer to
    // subscribe before the timestamp target and unanswered finding arrive.
    for _ in 0..50_000 {
        append(101, 1, &filler);
    }
    append(105, 500_000, &malformed);
    // Keep the finding limiter's elapsed-time window separate from the next
    // expiry finding, without advancing capture time past the DNS timeout.
    for _ in 0..50_000 {
        append(105, 500_001, &filler);
    }
    append(107, 0, &final_packet);
    (third_party_capture::write_capture(label, &bytes), final_packet)
}

#[derive(Debug, PartialEq, Eq)]
struct TimestampReplayResult {
    packet_timestamp: String,
    packet_id: String,
    malformed_timestamp: String,
    malformed_id: String,
    unanswered_timestamp: String,
    unanswered_id: String,
    dns_answered: u64,
    dns_unanswered: u64,
}

fn replay_timestamps(path: &Path, speed: &str, capture_target_packet: bool, final_packet: &[u8]) -> TimestampReplayResult {
    let auth = agent_auth::AuthFixture::new();
    let mut agent = Agent(Command::new(env!("CARGO_BIN_EXE_capture-agent"))
        .env("AGENT_TOKEN_FILE", auth.token_path())
        .env("REPLAY_FILE", path)
        .env("REPLAY_SPEED", speed)
        .env("REPLAY_LOCAL_ADDRS", "192.0.2.1")
        .env_remove("CAPTURE_INTERFACE")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap());
    let (finished_tx, finished_rx) = mpsc::channel();
    let stdout = agent.0.stdout.take().unwrap();
    let stdout_thread = std::thread::spawn(move || {
        let mut output = String::new();
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("replay finished") {
                let _ = finished_tx.send(());
            }
            output.push_str(&line);
            output.push('\n');
        }
        output
    });
    let stderr = agent.0.stderr.take().unwrap();
    let stderr_thread = std::thread::spawn(move || {
        BufReader::new(stderr).lines().map_while(Result::ok).collect::<Vec<_>>().join("\n")
    });

    let deadline = Instant::now() + Duration::from_secs(15);
    let stream = loop {
        match TcpStream::connect("127.0.0.1:9990") {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("agent did not listen: {error}"),
        }
    };
    let mut reader = auth.authenticate(stream);
    reader.get_mut().set_read_timeout(Some(Duration::from_millis(100))).unwrap();

    let expected_src = format!("192.0.2.1:{}", 20002);
    let mut result = TimestampReplayResult {
        packet_timestamp: String::new(),
        packet_id: String::new(),
        malformed_timestamp: String::new(),
        malformed_id: String::new(),
        unanswered_timestamp: String::new(),
        unanswered_id: String::new(),
        dns_answered: 0,
        dns_unanswered: 0,
    };
    let mut finished = false;
    let mut line = String::new();
    while Instant::now() < deadline {
        finished |= finished_rx.try_recv().is_ok();
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
                match event["type"].as_str() {
                    Some("packet") if event["packet"]["src"] == expected_src => {
                        result.packet_timestamp = event["packet"]["timestamp"].as_str().unwrap_or_default().to_string();
                        result.packet_id = event["packet"]["id"].as_str().unwrap_or_default().to_string();
                    }
                    Some("finding") if event["finding"]["code"] == "unanswered-request" => {
                        result.unanswered_timestamp = event["finding"]["timestamp"].as_str().unwrap_or_default().to_string();
                        result.unanswered_id = event["finding"]["id"].as_str().unwrap_or_default().to_string();
                    }
                    Some("finding") if event["finding"]["code"] == "malformed-frame" => {
                        result.malformed_timestamp = event["finding"]["timestamp"].as_str().unwrap_or_default().to_string();
                        result.malformed_id = event["finding"]["id"].as_str().unwrap_or_default().to_string();
                    }
                    Some("service_time_update") if finished => {
                        if let Some(dns) = event["summaries"].as_array().and_then(|items| items.iter().find(|item| item["protocol"] == "DNS")) {
                            result.dns_answered = dns["answered"].as_u64().unwrap_or(0);
                            result.dns_unanswered = dns["unanswered"].as_u64().unwrap_or(0);
                        }
                    }
                    _ => {}
                }
                if finished
                    && !result.unanswered_timestamp.is_empty()
                    && !result.malformed_timestamp.is_empty()
                    && (result.dns_answered, result.dns_unanswered) == (1, 1)
                    && (!capture_target_packet || !result.packet_timestamp.is_empty())
                {
                    break;
                }
            }
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(error) => panic!("wire read failed: {error}"),
        }
    }

    drop(agent);
    let stdout = stdout_thread.join().unwrap();
    let stderr = stderr_thread.join().unwrap();
    assert!(finished, "replay did not finish; stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(final_packet.len(), 58);
    assert!(!stderr.contains("replay failed:"), "{stderr}");
    result
}

fn exercise(path: &Path, expected_ports: &[u64], expect_failure: bool) {
    let auth = agent_auth::AuthFixture::new();
    let mut agent = Agent(Command::new(env!("CARGO_BIN_EXE_capture-agent"))
        .env("AGENT_TOKEN_FILE", auth.token_path())
        .env("REPLAY_FILE", path).env("REPLAY_SPEED", "fast")
        .env("REPLAY_LOCAL_ADDRS", "192.0.2.1,192.0.2.2,192.0.2.3,192.0.2.4")
        .env_remove("CAPTURE_INTERFACE").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap());
    let (terminal_tx, terminal_rx) = mpsc::channel();
    let stdout = agent.0.stdout.take().unwrap();
    let stdout_tx = terminal_tx.clone();
    let out_thread = std::thread::spawn(move || {
        let mut text = String::new();
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("replay finished") { let _ = stdout_tx.send(false); }
            text.push_str(&line); text.push('\n');
        }
        text
    });
    let stderr = agent.0.stderr.take().unwrap();
    let err_thread = std::thread::spawn(move || {
        let mut text = String::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.contains("replay failed:") { let _ = terminal_tx.send(true); }
            text.push_str(&line); text.push('\n');
        }
        text
    });
    let terminal = terminal_rx.recv_timeout(Duration::from_secs(10));
    let mut seen_ports = HashSet::new();
    if terminal == Ok(false) && !expect_failure {
        let deadline = Instant::now() + Duration::from_secs(6);
        let stream = loop {
            match TcpStream::connect("127.0.0.1:9990") {
                Ok(stream) => break Some(stream),
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => break None,
            }
        };
        if let Some(stream) = stream {
            stream.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
            let mut reader = auth.authenticate(stream);
            while Instant::now() < deadline && seen_ports.len() < expected_ports.len() {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                            if event["type"] == "connection_update" {
                                if let Some(port) = event["connection"]["localPort"].as_u64() {
                                    if expected_ports.contains(&port) { seen_ports.insert(port); }
                                }
                            }
                        }
                    }
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                    Err(e) => panic!("wire read: {e}"),
                }
            }
        }
    }
    drop(agent);
    let stdout = out_thread.join().unwrap(); let stderr = err_thread.join().unwrap();
    assert_eq!(terminal, Ok(expect_failure), "stdout: {stdout}\nstderr: {stderr}");
    if expect_failure {
        assert!(!stdout.contains("replay finished"), "{stdout}");
        assert!(stderr.contains("truncated pcapng block header"), "{stderr}");
    } else {
        assert_eq!(seen_ports, expected_ports.iter().copied().collect(), "stdout: {stdout}\nstderr: {stderr}");
        assert!(!stderr.contains("replay failed:"), "{stderr}");
        assert!(!stderr.contains("fixture secret"), "capture secrets must not be logged");
    }
}

fn reused_udp_tuple(label: &str) -> (third_party_capture::CaptureFile, u64, u16) {
    let mut frame = Vec::new();
    PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
        .ipv4([192, 0, 2, 1], [198, 51, 100, 10], 64)
        .udp(31001, 41001)
        .write(&mut frame, b"same tuple after idle timeout")
        .unwrap();
    let packet_len = u64::from(
        capture_agent::parse::parse_packet(&frame, capture_agent::parse::LinkType::Ethernet)
            .unwrap()
            .total_len,
    );

    let mut bytes = Vec::new();
    bytes.extend(0xa1b2c3d4u32.to_le_bytes());
    bytes.extend(2u16.to_le_bytes());
    bytes.extend(4u16.to_le_bytes());
    bytes.extend([0; 8]);
    bytes.extend(65535u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    for seconds in [0u32, 61] {
        bytes.extend(seconds.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend(&frame);
    }
    (third_party_capture::write_capture(label, &bytes), packet_len, 31001)
}

#[test]
#[ignore = "requires exclusive 127.0.0.1:9990; run cargo test --test replay_compatibility -- --ignored"]
fn binary_replay_ages_reused_udp_tuple_by_capture_time() {
    let _serial = REPLAY_AGENT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (capture, one_packet_bytes, local_port) = reused_udp_tuple("binary-reused-flow");
    let auth = agent_auth::AuthFixture::new();
    let mut agent = Agent(
        Command::new(env!("CARGO_BIN_EXE_capture-agent"))
            .env("AGENT_TOKEN_FILE", auth.token_path())
            .env("REPLAY_FILE", &capture.0)
            .env("REPLAY_SPEED", "fast")
            .env("REPLAY_LOCAL_ADDRS", "192.0.2.1")
            .env_remove("CAPTURE_INTERFACE")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let (replay_finished_tx, replay_finished_rx) = mpsc::channel();
    let stdout = agent.0.stdout.take().unwrap();
    let stdout_thread = std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("replay finished") {
                let _ = replay_finished_tx.send(());
            }
            lines.push(line);
        }
        lines.join("\n")
    });
    let stderr = agent.0.stderr.take().unwrap();
    let stderr_thread = std::thread::spawn(move || {
        BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
            .collect::<Vec<_>>()
            .join("\n")
    });

    let deadline = Instant::now() + Duration::from_secs(12);
    let stream = loop {
        match TcpStream::connect("127.0.0.1:9990") {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("agent did not listen: {error}"),
        }
    };
    let mut reader = auth.authenticate(stream);
    reader
        .get_mut()
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();

    let mut replay_finished = false;
    let mut final_tx_bytes_after_eof = None;
    while Instant::now() < deadline && final_tx_bytes_after_eof != Some(one_packet_bytes) {
        replay_finished |= replay_finished_rx.try_recv().is_ok();
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                    if event["type"] == "connection_update"
                        && event["connection"]["localPort"] == local_port
                        && replay_finished
                    {
                        final_tx_bytes_after_eof =
                            event["connection"]["txBytesTotal"].as_u64();
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("wire read failed: {error}"),
        }
    }

    drop(agent);
    let stdout = stdout_thread.join().unwrap();
    let stderr = stderr_thread.join().unwrap();
    assert!(replay_finished, "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        final_tx_bytes_after_eof,
        Some(one_packet_bytes),
        "post-EOF connection snapshot retained bytes from the expired flow; stdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
#[ignore = "requires exclusive 127.0.0.1:9990; run cargo test --test replay_compatibility replay_packet_and_unanswered_timestamps_are_capture_time_at_both_speeds -- --ignored --test-threads=1"]
fn replay_packet_and_unanswered_timestamps_are_capture_time_at_both_speeds() {
    let _serial = REPLAY_AGENT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (capture, final_packet) = timestamped_classic_pcap("analysis-clock");
    let fast = replay_timestamps(&capture.0, "fast", false, &final_packet);
    let realtime = replay_timestamps(&capture.0, "realtime", true, &final_packet);

    assert_eq!(fast.unanswered_timestamp, "107000");
    assert_eq!(fast.malformed_timestamp, "105500");
    assert!(realtime.packet_id.starts_with("pkt-107000-"));
    assert!(fast.malformed_id.starts_with("finding-105500-"));
    assert!(fast.unanswered_id.starts_with("finding-107000-"));
    let ids = [
        &realtime.packet_id,
        &fast.malformed_id,
        &fast.unanswered_id,
    ]
    .into_iter()
    .collect::<std::collections::HashSet<_>>();
    assert_eq!(ids.len(), 3, "packet and finding ids must remain unique");
    assert_eq!((fast.dns_answered, fast.dns_unanswered), (1, 1));
    assert_eq!(realtime.packet_timestamp, "107000");
    assert_eq!(realtime.malformed_timestamp, fast.malformed_timestamp);
    assert_eq!(realtime.unanswered_timestamp, fast.unanswered_timestamp);
    assert_eq!((realtime.dns_answered, realtime.dns_unanswered), (fast.dns_answered, fast.dns_unanswered));
}

#[test]
#[ignore = "requires exclusive 127.0.0.1:9990; run cargo test --test replay_compatibility -- --ignored"]
fn binary_replays_mixed_interfaces_sections_and_classic_raw_and_reports_malformed_tail() {
    let _serial = REPLAY_AGENT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mixed = third_party_capture::mixed_sections("binary-mixed");
    exercise(&mixed.0, &[3001, 3002, 3003], false);
    let raw = third_party_capture::raw_classic("binary-raw");
    exercise(&raw.0, &[3004], false);
    let mut bytes = std::fs::read(&mixed.0).unwrap(); bytes.extend([6, 0, 0]);
    let malformed = third_party_capture::write_capture("binary-malformed", &bytes);
    exercise(&malformed.0, &[], true);
}
