//! JAM-174: exercise the actual replay loop, including its warning latch and
//! detection before parsing. Fixtures encode independent caplen/original len.
use capture_agent::parse::{parse_packet, LinkType};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
#[path = "fixtures/replay_capture.rs"]
mod replay_capture;
use replay_capture::fixture;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn replay_stderr(path: &Path) -> String {
    let mut agent = Agent(
        Command::new(env!("CARGO_BIN_EXE_capture-agent"))
            .env("REPLAY_FILE", path)
            .env("REPLAY_SPEED", "fast")
            .env_remove("CAPTURE_INTERFACE")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let (finished_tx, finished_rx) = mpsc::channel();
    let stdout = agent.0.stdout.take().unwrap();
    let stdout_thread = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("replay finished") {
                let _ = finished_tx.send(());
            }
        }
    });
    let mut stderr = agent.0.stderr.take().unwrap();
    let stderr_thread = std::thread::spawn(move || {
        let mut text = String::new();
        stderr.read_to_string(&mut text).unwrap();
        text
    });
    let finished = finished_rx.recv_timeout(Duration::from_secs(10));
    drop(agent);
    stdout_thread.join().unwrap();
    let stderr = stderr_thread.join().unwrap();
    assert!(finished.is_ok(), "replay did not finish: {stderr}");
    stderr
}

#[test]
#[ignore = "requires exclusive access to 127.0.0.1:9990; stop any running agent and run cargo test --test replay_truncation -- --ignored"]
fn replay_reports_length_proven_truncation_once_and_avoids_snaplen_false_positives() {
    // One test serializes child processes that use the agent's fixed listener.
    let mut truncated = Vec::new();
    etherparse::PacketBuilder::ethernet2([0; 6], [1; 6])
        .ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64)
        .udp(1234, 4321)
        .write(&mut truncated, &[0x41; 100])
        .unwrap();
    assert_eq!(truncated.len(), 142);
    truncated.truncate(96);
    assert!(parse_packet(&truncated, LinkType::Ethernet).is_none());

    let mut decodable = Vec::new();
    etherparse::PacketBuilder::ethernet2([0; 6], [1; 6])
        .ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64)
        .udp(1234, 4321)
        .write(&mut decodable, b"data")
        .unwrap();
    decodable.resize(96, 0); // loss is beyond the IP datagram, so parsing succeeds
    assert!(parse_packet(&decodable, LinkType::Ethernet).is_some());

    for format in ["pcapng", "pcap"] {
        for (label, data, original_len, expected_warnings) in [
            ("truncated", truncated.as_slice(), 142, 1),
            ("decodable", decodable.as_slice(), 128, 1),
            ("complete", decodable.as_slice(), 96, 0),
            ("malformed-at-default-snaplen", &[0u8; 65535][..], 65535, 0),
        ] {
            let file = fixture(format, label, data, original_len);
            let stderr = replay_stderr(&file.0);
            let warnings = stderr.lines().filter(|line| line.contains("frames are being cut short")).count();
            assert_eq!(warnings, expected_warnings, "{format}/{label}: {stderr}");
            if expected_warnings != 0 {
                assert!(stderr.contains("incomplete — frames truncated at capture"), "{stderr}");
            }
        }
    }
}
