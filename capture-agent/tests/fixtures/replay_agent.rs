//! Shared by the replay tests that drive the real agent binary: a classic
//! pcap writer, temp files and agent processes cleaned up on drop, and a
//! spawn that waits for the replay to finish.
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

/// Every test that spawns an agent uses the fixed control port.
pub static AGENT_LOCK: Mutex<()> = Mutex::new(());

pub struct Agent(pub Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct TempFile(pub PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[path = "classic_pcap.rs"]
mod pcap;
pub use pcap::classic_pcap;

/// Writes `bytes` to a temp file unique per call: tests run in parallel and
/// each deletes its own file.
pub fn write_temp(prefix: &str, label: &str, bytes: &[u8]) -> TempFile {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("{prefix}-{label}-{}-{n}.pcap", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    TempFile(path)
}

/// Spawns `command` with stdout piped and returns once the agent reports
/// that the replay finished.
pub fn run_until_replayed(command: &mut Command, timeout: Duration) -> Agent {
    let mut agent = Agent(command.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap());
    let (finished_tx, finished_rx) = mpsc::channel();
    let stdout = agent.0.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("replay finished") {
                let _ = finished_tx.send(());
            }
        }
    });
    finished_rx.recv_timeout(timeout).expect("replay finished");
    agent
}
