//! JAM-18 D1 benchmark: what IO-graph series add to per-frame cost.
//! Ignored by default (timing, not correctness). Run it with:
//!
//!     cargo test --release --locked --test io_graph_bench -- --ignored --nocapture
//!
//! "baseline" is parsing plus L7 sniffing, a subset of what the agent
//! already does for every frame (it also updates flows, reassembly and
//! transactions). That makes the reported ratio conservative: the real
//! relative cost is lower. "added" is what a series set costs on top,
//! building the browser's field tree once and evaluating every series.
//!
//! `io_series_end_to_end_replay_throughput` measures the real agent instead:
//! fast-replay wall time for the same file with 0, 1 and 8 series, and 8
//! series that each also aggregate a numeric field (Task 5, spec D10).
#[path = "fixtures/agent_auth.rs"]
mod agent_auth;

use capture_agent::display_filter::{compile_for_series, uint_value};
use capture_agent::fields::build_packet_fields;
use capture_agent::l7::sniff_l7;
use capture_agent::parse::{parse_packet, LinkType};
use etherparse::PacketBuilder;
use std::hint::black_box;
use std::time::Instant;

fn frames() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for i in 0..256u16 {
        let mut frame = Vec::new();
        match i % 4 {
            0 => {
                let mut dns = Vec::from(i.to_be_bytes());
                dns.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
                dns.extend([4, b't', b'e', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1]);
                PacketBuilder::ethernet2([0; 6], [1; 6]).ipv4([192, 0, 2, 1], [198, 51, 100, 53], 64).udp(53000, 53).write(&mut frame, &dns).unwrap();
            }
            1 => {
                let request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\n\r\n";
                PacketBuilder::ethernet2([0; 6], [1; 6]).ipv4([192, 0, 2, 1], [203, 0, 113, 7], 64).tcp(51000, 80, 1, 64240).write(&mut frame, request).unwrap();
            }
            2 => {
                PacketBuilder::ethernet2([0; 6], [1; 6]).ipv4([203, 0, 113, 7], [192, 0, 2, 1], 64).tcp(443, 51001, 9, 64240).write(&mut frame, &[0x17; 1200]).unwrap();
            }
            _ => {
                PacketBuilder::ethernet2([0; 6], [1; 6]).ipv4([192, 0, 2, 1], [192, 0, 2, 9], 64).udp(20000, 20001).write(&mut frame, b"filler").unwrap();
            }
        }
        out.push(frame);
    }
    out
}

const SERIES: [&str; 8] = [
    "",
    "dns",
    "tcp.dst_port == 443 or tcp.src_port == 443",
    "ip.src == \"192.0.2.1\"",
    "frame.len > 1000",
    "dns.qry.name contains \"example\"",
    "udp and not dns",
    "(tcp or udp) and frame.len < 200",
];

/// One aggregate field per series for the "8 + aggregates" runs.
const AGG_FIELDS: [&str; 8] = [
    "frame.len",
    "dns.id",
    "tcp.window_size",
    "ip.ttl",
    "frame.len",
    "dns.count.answers",
    "udp.dst_port",
    "tcp.seq",
];

fn per_frame_ns(frames: &[Vec<u8>], series: usize, aggregates: bool, rounds: usize) -> f64 {
    let compiled: Vec<_> = SERIES[..series].iter().map(|s| compile_for_series(s).unwrap()).collect();
    let start = Instant::now();
    let mut matched = 0u64;
    for _ in 0..rounds {
        for data in frames {
            let parsed = parse_packet(data, LinkType::Ethernet).unwrap();
            let l7 = sniff_l7(&parsed.payload, parsed.dst_port);
            if series > 0 {
                let tree = build_packet_fields(&parsed, &l7, LinkType::Ethernet, false);
                for (i, c) in compiled.iter().enumerate() {
                    let hit = c.matches(&tree, u32::from(parsed.total_len));
                    matched += hit as u64;
                    if aggregates && hit {
                        matched += uint_value(&tree, u32::from(parsed.total_len), AGG_FIELDS[i]).unwrap_or(0) & 1;
                    }
                }
            }
            black_box(&l7);
        }
    }
    black_box(matched);
    start.elapsed().as_nanos() as f64 / (rounds * frames.len()) as f64
}

#[test]
#[ignore]
fn io_series_per_frame_cost() {
    let frames = frames();
    let rounds = 2_000;
    per_frame_ns(&frames, 8, true, 200); // warm up
    let mut results = Vec::new();
    for (series, aggregates) in [(0usize, false), (1, false), (8, false), (8, true)] {
        // Best of five, to keep scheduler noise out of the comparison.
        let best = (0..5).map(|_| per_frame_ns(&frames, series, aggregates, rounds)).fold(f64::INFINITY, f64::min);
        results.push((series, aggregates, best));
    }
    let baseline = results[0].2;
    println!("JAM-18 IO graph per-frame cost ({} frames x {rounds} rounds, best of 5):", frames.len());
    for (series, aggregates, ns) in &results {
        let label = if *aggregates { " + aggregates" } else { "" };
        println!("  {series} series{label}: {ns:8.0} ns/frame  ({:.2}x baseline, +{:.0} ns)", ns / baseline, ns - baseline);
    }
    println!("  8-series / 0-series ratio: {:.2} (plan threshold: 2.00)", results[2].2 / baseline);
    println!("  aggregates add {:.0} ns/frame over 8 plain series", results[3].2 - results[2].2);
}

fn replay_seconds(path: &std::path::Path, series: usize, aggregates: bool) -> f64 {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    let auth = agent_auth::AuthFixture::new();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_capture-agent"));
    cmd.env("AGENT_TOKEN_FILE", auth.token_path())
        .env("REPLAY_FILE", path)
        .env("REPLAY_SPEED", "fast")
        .env("REPLAY_LOCAL_ADDRS", "192.0.2.1")
        .env_remove("CAPTURE_INTERFACE")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if series > 0 {
        cmd.env("REPLAY_WAIT_FOR_IO_SERIES", "1");
    }
    let mut child = cmd.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send((Instant::now(), line));
        }
    });
    let mut start = None;
    let mut _socket = None;
    if series > 0 {
        let stream = loop {
            if let Ok(s) = std::net::TcpStream::connect("127.0.0.1:9990") { break s; }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let mut reader = auth.authenticate(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let status: serde_json::Value = serde_json::from_str(&line).unwrap();
        let list: Vec<_> = SERIES[..series]
            .iter()
            .enumerate()
            .map(|(i, f)| {
                if aggregates {
                    serde_json::json!({"id": format!("s{i}"), "filter": f, "aggregate": {"fn": "avg", "field": AGG_FIELDS[i]}})
                } else {
                    serde_json::json!({"id": format!("s{i}"), "filter": f})
                }
            })
            .collect();
        let msg = serde_json::json!({"type":"set_io_series","baseEpoch":status["epoch"],"baseRevision":0,"requestId":"0000aaaa","series":list});
        reader.get_mut().write_all(format!("{msg}\n").as_bytes()).unwrap();
        _socket = Some(reader);
    }
    let end = loop {
        let (at, line) = rx.recv_timeout(std::time::Duration::from_secs(120)).expect("agent output");
        if line.contains(if series > 0 { "starting replay" } else { "mode=replay" }) { start = Some(at); }
        if line.contains("replay finished") { break at; }
    };
    let _ = child.kill();
    let _ = child.wait();
    (end - start.expect("start marker")).as_secs_f64()
}

#[test]
#[ignore]
fn io_series_end_to_end_replay_throughput() {
    let base = frames();
    let mut pcap = Vec::new();
    pcap.extend(0xa1b2c3d4u32.to_le_bytes());
    pcap.extend(2u16.to_le_bytes());
    pcap.extend(4u16.to_le_bytes());
    pcap.extend([0u8; 8]);
    pcap.extend(65535u32.to_le_bytes());
    pcap.extend(1u32.to_le_bytes());
    let count = 200_000u64;
    for i in 0..count {
        let data = &base[(i % base.len() as u64) as usize];
        let ts = 1_794_120_000_000_000u64 + i * 50;
        pcap.extend(((ts / 1_000_000) as u32).to_le_bytes());
        pcap.extend(((ts % 1_000_000) as u32).to_le_bytes());
        pcap.extend((data.len() as u32).to_le_bytes());
        pcap.extend((data.len() as u32).to_le_bytes());
        pcap.extend(data);
    }
    let path = std::env::temp_dir().join(format!("jam18-bench-{}.pcap", std::process::id()));
    std::fs::write(&path, &pcap).unwrap();
    println!("JAM-18 end-to-end fast replay, {count} frames (best of 3):");
    let mut results = Vec::new();
    for (series, aggregates) in [(0usize, false), (1, false), (8, false), (8, true)] {
        let best = (0..3).map(|_| replay_seconds(&path, series, aggregates)).fold(f64::INFINITY, f64::min);
        results.push((series, aggregates, best));
    }
    let _ = std::fs::remove_file(&path);
    let baseline = results[0].2;
    for (series, aggregates, secs) in &results {
        let label = if *aggregates { " + aggregates" } else { "" };
        println!("  {series} series{label}: {:7.0} ns/frame  ({:.2}x)", secs * 1e9 / count as f64, secs / baseline);
    }
    println!("  8-series / 0-series ratio: {:.2} (plan threshold: 2.00)", results[2].2 / baseline);
}
