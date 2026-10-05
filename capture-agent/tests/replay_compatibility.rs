//! Actual binary replay coverage for JAM-194. Serialized fixed-port child processes.
#[path = "fixtures/agent_auth.rs"]
mod agent_auth;
#[path = "fixtures/third_party_capture.rs"]
mod third_party_capture;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
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

#[test]
#[ignore = "requires exclusive 127.0.0.1:9990; run cargo test --test replay_compatibility -- --ignored"]
fn binary_replays_mixed_interfaces_sections_and_classic_raw_and_reports_malformed_tail() {
    let mixed = third_party_capture::mixed_sections("binary-mixed");
    exercise(&mixed.0, &[3001, 3002, 3003], false);
    let raw = third_party_capture::raw_classic("binary-raw");
    exercise(&raw.0, &[3004], false);
    let mut bytes = std::fs::read(&mixed.0).unwrap(); bytes.extend([6, 0, 0]);
    let malformed = third_party_capture::write_capture("binary-malformed", &bytes);
    exercise(&malformed.0, &[], true);
}
