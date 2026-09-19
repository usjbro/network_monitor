// capture-agent/examples/ipc_split_spike.rs
// Scratch binary, not part of the shipped agent. Answers issue #91's cost
// question: what would moving raw captured frames across a process boundary
// actually cost, in throughput and latency, at packet rates realistic for a
// home-network capture agent?
//
// Model: a privilege-separated design (baseline dumpcap/epan split) would
// have a privileged capture-only child holding the BPF handle and shipping
// raw frame bytes to an unprivileged parent doing all parsing/L7/decrypt.
// This spike isolates that one hop: two real OS processes (not threads --
// this measures actual process-boundary IPC, including scheduling, not an
// in-process shortcut) connected by the child's stdin/stdout pipes, sending
// length-prefixed frames with an embedded send timestamp so the receiving
// side can compute real one-way latency, not just aggregate throughput.
//
// Usage:
//   cargo run --release --example ipc_split_spike             # runs all scenarios, prints results
//   cargo run --release --example ipc_split_spike -- --child  # internal reader role, never run directly

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_nanos() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

/// Child role: reads [4-byte LE length][8-byte LE send-time-nanos][payload]
/// frames from stdin until EOF, computing one-way latency per frame against
/// its own wall clock (same machine, so directly comparable), then writes
/// one summary line to stdout.
fn run_child() {
    let mut stdin = std::io::stdin().lock();
    let mut len_buf = [0u8; 4];
    let mut ts_buf = [0u8; 8];
    let mut latencies_ns: Vec<u64> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut payload_buf = Vec::new();

    loop {
        if stdin.read_exact(&mut len_buf).is_err() {
            break; // EOF: parent closed its write end
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        stdin.read_exact(&mut ts_buf).expect("read send-time");
        let send_time = u64::from_le_bytes(ts_buf);
        payload_buf.resize(len, 0);
        stdin.read_exact(&mut payload_buf).expect("read payload");

        let recv_time = now_nanos();
        latencies_ns.push(recv_time.saturating_sub(send_time));
        total_bytes += (4 + 8 + len) as u64;
    }

    latencies_ns.sort_unstable();
    let n = latencies_ns.len().max(1);
    let pct = |p: f64| -> u64 { latencies_ns[((n - 1) as f64 * p) as usize] };
    let sum: u128 = latencies_ns.iter().map(|&x| x as u128).sum();
    let mean_ns = if latencies_ns.is_empty() { 0 } else { (sum / n as u128) as u64 };

    println!(
        "CHILD_RESULT frames={} bytes={} min_us={:.1} mean_us={:.1} p50_us={:.1} p99_us={:.1} max_us={:.1}",
        latencies_ns.len(),
        total_bytes,
        *latencies_ns.first().unwrap_or(&0) as f64 / 1000.0,
        mean_ns as f64 / 1000.0,
        pct(0.50) as f64 / 1000.0,
        pct(0.99) as f64 / 1000.0,
        *latencies_ns.last().unwrap_or(&0) as f64 / 1000.0,
    );
}

/// One scenario: send `payload_size`-byte frames for `duration` real time.
/// `target_pps: None` means unpaced (max achievable throughput); `Some(n)`
/// paces sends to approximate n frames/sec via short catch-up sleeps.
fn run_scenario(name: &str, payload_size: usize, duration: Duration, target_pps: Option<u64>) {
    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .arg("--child")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn child");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    let payload = vec![0xABu8; payload_size];
    let start = Instant::now();
    let mut sent: u64 = 0;

    while start.elapsed() < duration {
        let len_bytes = (payload_size as u32).to_le_bytes();
        let ts_bytes = now_nanos().to_le_bytes();
        stdin.write_all(&len_bytes).expect("write len");
        stdin.write_all(&ts_bytes).expect("write ts");
        stdin.write_all(&payload).expect("write payload");
        sent += 1;

        if let Some(pps) = target_pps {
            // thread::sleep()'s real-world granularity (tens of
            // microseconds on Linux) is coarser than a single frame's
            // interval at 50k pps (20us) -- sleeping every frame
            // massively overshoots and undershoots the target rate (a
            // first pass at this pacing loop measured ~12k pps instead
            // of 50k for exactly this reason). Sleep for most of the
            // remaining time budget, then spin-wait the last sliver for
            // precision -- the spin is cheap relative to a frame's
            // 20us budget and only runs when actually ahead of schedule.
            let expected_elapsed = Duration::from_secs_f64(sent as f64 / pps as f64);
            let actual_elapsed = start.elapsed();
            if actual_elapsed < expected_elapsed {
                let surplus = expected_elapsed - actual_elapsed;
                if surplus > Duration::from_micros(150) {
                    std::thread::sleep(surplus - Duration::from_micros(100));
                }
                while start.elapsed() < expected_elapsed {
                    std::hint::spin_loop();
                }
            }
        }
    }
    drop(stdin); // EOF to child

    let mut summary = String::new();
    stdout.read_to_string(&mut summary).expect("read child summary");
    let elapsed = start.elapsed();
    child.wait().expect("wait child");

    let achieved_pps = sent as f64 / elapsed.as_secs_f64();
    let mbps = (sent as f64 * payload_size as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
    println!(
        "{name}: sent={sent} elapsed={:.3}s achieved={:.0}pps ({:.1}Mbps) | {}",
        elapsed.as_secs_f64(),
        achieved_pps,
        mbps,
        summary.trim()
    );
}

fn main() {
    if std::env::args().any(|a| a == "--child") {
        run_child();
        return;
    }

    println!("IPC split-process spike (issue #91) -- capture-agent process boundary cost");
    println!("Each scenario: real two-process pipe, length-prefixed frames, measured one-way latency.\n");

    run_scenario("64B unpaced (max throughput, small-packet worst case)", 64, Duration::from_secs(2), None);
    run_scenario("64B @ 50,000 pps (aggressive small-packet rate)", 64, Duration::from_secs(2), Some(50_000));
    run_scenario("1500B unpaced (max throughput, bandwidth ceiling)", 1500, Duration::from_secs(2), None);
    run_scenario("1500B @ 50,000 pps (600 Mbps -- above home-gigabit sustained)", 1500, Duration::from_secs(2), Some(50_000));
}
