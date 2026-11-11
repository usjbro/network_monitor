//! JAM-18 IO graph, end to end against the real agent binary in replay
//! mode: series counts are complete (not sampled by the 100/s packet-event
//! limiter), identical at `REPLAY_SPEED=realtime` and `fast`, include
//! transaction fields (`dns.time_us`), survive a replay shorter than the
//! grace period, and report a truncated file as `replay_error`.
#[path = "fixtures/agent_auth.rs"]
mod agent_auth;

use etherparse::PacketBuilder;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Every test here spawns an agent on the fixed control port.
static AGENT_LOCK: Mutex<()> = Mutex::new(());

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TempFile(PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const LOCAL: [u8; 4] = [192, 0, 2, 1];
const SERVER: [u8; 4] = [198, 51, 100, 53];
const T0_US: u64 = 1_794_120_000_000_000;

fn dns_payload(id: u16, response: bool) -> Vec<u8> {
    let mut bytes = Vec::from(id.to_be_bytes());
    bytes.extend((if response { 0x8180u16 } else { 0x0100u16 }).to_be_bytes());
    bytes.extend(1u16.to_be_bytes());
    bytes.extend(0u16.to_be_bytes());
    bytes.extend(0u32.to_be_bytes());
    bytes.extend([4, b't', b'e', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
    bytes.extend(1u16.to_be_bytes());
    bytes.extend(1u16.to_be_bytes());
    bytes
}

fn udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
        .ipv4(src, dst, 64)
        .udp(sport, dport)
        .write(&mut frame, payload)
        .unwrap();
    frame
}

/// Classic little-endian pcap, microsecond timestamps, Ethernet.
fn classic_pcap(frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xa1b2c3d4u32.to_le_bytes());
    out.extend(2u16.to_le_bytes());
    out.extend(4u16.to_le_bytes());
    out.extend(0i32.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(65535u32.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    for (ts_us, data) in frames {
        out.extend(((ts_us / 1_000_000) as u32).to_le_bytes());
        out.extend(((ts_us % 1_000_000) as u32).to_le_bytes());
        out.extend((data.len() as u32).to_le_bytes());
        out.extend((data.len() as u32).to_le_bytes());
        out.extend(data);
    }
    out
}

struct Fixture {
    frames: Vec<(u64, Vec<u8>)>,
    responses: u64,
}

/// `count` frames 1 ms apart (1 000 frames/s, ten times the packet-event
/// budget). Every 20th frame is a DNS query, answered two frames later.
fn busy_fixture(count: u64) -> Fixture {
    let mut frames = Vec::new();
    let mut responses = 0;
    for i in 0..count {
        let ts = T0_US + i * 1_000;
        let id = (i / 20) as u16;
        let frame = match i % 20 {
            0 => udp(LOCAL, SERVER, 53000, 53, &dns_payload(id, false)),
            2 => {
                responses += 1;
                udp(SERVER, LOCAL, 53, 53000, &dns_payload(id, true))
            }
            _ => udp(LOCAL, SERVER, 20000, 20001, b"filler"),
        };
        frames.push((ts, frame));
    }
    Fixture { frames, responses }
}

fn write_temp(label: &str, bytes: &[u8]) -> TempFile {
    let path = std::env::temp_dir().join(format!("jam18-{label}-{}.pcap", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    TempFile(path)
}

struct Run {
    statuses: Vec<Value>,
    buckets: Vec<Value>,
}

impl Run {
    /// Sum of packets per series id, and every bucket per id in order.
    fn totals(&self) -> BTreeMap<String, (u64, Vec<[u64; 3]>)> {
        let mut out: BTreeMap<String, (u64, Vec<[u64; 3]>)> = BTreeMap::new();
        for msg in &self.buckets {
            for s in msg["series"].as_array().unwrap() {
                let e = out.entry(s["id"].as_str().unwrap().to_string()).or_default();
                for b in s["buckets"].as_array().unwrap() {
                    let b = [b[0].as_u64().unwrap(), b[1].as_u64().unwrap(), b[2].as_u64().unwrap()];
                    e.0 += b[1];
                    e.1.push(b);
                }
            }
        }
        out
    }

    fn not_observed_reasons(&self) -> Vec<String> {
        self.buckets
            .iter()
            .flat_map(|m| m["notObserved"].as_array().unwrap().iter().map(|n| n["reason"].as_str().unwrap().to_string()))
            .collect()
    }
}

fn replay(path: &PathBuf, speed: &str, series: Value) -> Run {
    let _guard = AGENT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let auth = agent_auth::AuthFixture::new();
    let mut agent = Agent(
        Command::new(env!("CARGO_BIN_EXE_capture-agent"))
            .env("AGENT_TOKEN_FILE", auth.token_path())
            .env("REPLAY_FILE", path)
            .env("REPLAY_SPEED", speed)
            .env("REPLAY_LOCAL_ADDRS", "192.0.2.1")
            .env("REPLAY_WAIT_FOR_IO_SERIES", "1")
            .env_remove("CAPTURE_INTERFACE")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    // The replay ends with "replay finished" on stdout, or "replay failed"
    // on stderr for a file that cannot be read to the end.
    let (finished_tx, finished_rx) = mpsc::channel();
    let stdout = agent.0.stdout.take().unwrap();
    let stderr = agent.0.stderr.take().unwrap();
    let done_on_stderr = finished_tx.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("replay finished") {
                let _ = finished_tx.send(());
            }
        }
    });
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.contains("replay failed") {
                let _ = done_on_stderr.send(());
            }
        }
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

    let mut run = Run { statuses: Vec::new(), buckets: Vec::new() };
    let mut sent = false;
    let mut finished_at: Option<Instant> = None;
    let overall = Instant::now() + Duration::from_secs(60);
    let mut line = String::new();
    loop {
        assert!(Instant::now() < overall, "replay did not finish");
        if finished_at.is_none() && finished_rx.try_recv().is_ok() {
            finished_at = Some(Instant::now());
        }
        // Finalized buckets go out on the next emitter tick or two.
        if finished_at.is_some_and(|t| t.elapsed() > Duration::from_millis(2_500)) {
            break;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
            Err(e) => panic!("read failed: {e}"),
        }
        let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
        match v["type"].as_str() {
            Some("io_series_status") => {
                if !sent {
                    // The first line after authentication bootstraps the set.
                    assert_eq!(run.statuses.len(), 0);
                    assert_eq!(v["revision"], 0);
                    let request = json!({
                        "type": "set_io_series",
                        "baseEpoch": v["epoch"],
                        "baseRevision": 0,
                        "requestId": "c41f09aa",
                        "series": series,
                    });
                    let mut out = request.to_string();
                    out.push('\n');
                    reader.get_mut().write_all(out.as_bytes()).unwrap();
                    sent = true;
                }
                run.statuses.push(v);
            }
            Some("io_buckets") => {
                assert!(line.len() <= 64 * 1024, "line over the ceiling");
                run.buckets.push(v);
            }
            _ => {}
        }
    }
    assert!(sent, "no bootstrap io_series_status");
    run
}

fn standard_series() -> Value {
    json!([
        { "id": "all", "filter": "" },
        { "id": "dns", "filter": "dns" },
        { "id": "rt", "filter": "dns.time_us > 0" },
        { "id": "none", "filter": "frame.len > 100000" },
    ])
}

#[test]
fn counts_are_complete_above_the_packet_event_rate() {
    let fixture = busy_fixture(3_000);
    let file = write_temp("busy", &classic_pcap(&fixture.frames));
    let run = replay(&file.0, "fast", standard_series());

    let accepted = &run.statuses[1];
    assert_eq!(accepted["revision"], 1);
    assert_eq!(accepted["requestId"], "c41f09aa");
    assert!(accepted.get("rejected").is_none());

    let totals = run.totals();
    assert_eq!(totals["all"].0, 3_000, "every frame counted, not ~100/s");
    assert_eq!(totals["dns"].0, 300);
    assert_eq!(totals["rt"].0, fixture.responses, "transaction fields are series inputs");
    assert_eq!(totals.get("none").map(|t| t.0).unwrap_or(0), 0);

    // Bytes are on-wire lengths, buckets are 100 ms wide and in order, and
    // covered ranges abut from first to last message.
    let all = &totals["all"].1;
    assert_eq!(all.len(), 30);
    assert!(all.iter().all(|b| b[0] % 100 == 0 && b[1] == 100));
    for pair in run.buckets.windows(2) {
        assert_eq!(pair[0]["coveredToMs"], pair[1]["coveredFromMs"]);
    }
    let first = run.buckets.first().unwrap()["coveredFromMs"].as_u64().unwrap();
    let last = run.buckets.last().unwrap()["coveredToMs"].as_u64().unwrap();
    assert_eq!((first, last), (T0_US / 1_000, T0_US / 1_000 + 3_000));
    assert!(run.buckets.iter().all(|m| m["revision"] == 1 && m["bucketMs"] == 100));
}

#[test]
fn realtime_and_fast_replay_give_identical_buckets() {
    let fixture = busy_fixture(1_500);
    let file = write_temp("speeds", &classic_pcap(&fixture.frames));
    let fast = replay(&file.0, "fast", standard_series()).totals();
    let realtime = replay(&file.0, "realtime", standard_series()).totals();
    assert_eq!(fast, realtime);
    assert_eq!(fast["all"].0, 1_500);
}

#[test]
fn a_replay_shorter_than_the_grace_period_is_fully_counted() {
    let fixture = busy_fixture(200); // 200 ms of traffic, grace is 500 ms
    let file = write_temp("short", &classic_pcap(&fixture.frames));
    let totals = replay(&file.0, "fast", standard_series()).totals();
    assert_eq!(totals["all"].0, 200);
}

#[test]
fn a_truncated_file_reports_replay_error_after_what_it_counted() {
    let fixture = busy_fixture(500);
    let mut bytes = classic_pcap(&fixture.frames);
    bytes.truncate(bytes.len() - 20); // cut the last record short
    let file = write_temp("truncated", &bytes);
    let run = replay(&file.0, "fast", standard_series());
    assert_eq!(run.totals()["all"].0, 499);
    assert!(run.not_observed_reasons().contains(&"replay_error".to_string()), "{:?}", run.not_observed_reasons());
}

#[test]
fn aggregate_series_carry_exact_count_sum_min_max_from_the_real_agent() {
    // JAM-18 Task 5 (spec D10). frame.len == the on-wire length in this
    // fixture, so sum(frame.len) must equal the series' own byte total; and
    // each DNS response arrives exactly 2 ms after its query.
    let fixture = busy_fixture(3_000);
    let file = write_temp("agg", &classic_pcap(&fixture.frames));
    let run = replay(
        &file.0,
        "fast",
        json!([
            { "id": "len", "filter": "", "aggregate": { "fn": "sum", "field": "frame.len" } },
            { "id": "rtt", "filter": "dns.time_us > 0", "aggregate": { "fn": "avg", "field": "dns.time_us" } },
            { "id": "bad", "filter": "", "aggregate": { "fn": "max", "field": "dns.qry.name" } },
        ]),
    );
    let accepted = &run.statuses[1];
    assert_eq!(accepted["series"][0]["aggregate"], json!({ "fn": "sum", "field": "frame.len" }));
    assert_eq!(accepted["series"][2]["ok"], false, "a non-uint aggregate field is a compile error");

    let (mut len, mut rtt) = ((0u64, 0u64, 0u64), (0u64, 0u64, u64::MAX, 0u64));
    for msg in &run.buckets {
        for s in msg["series"].as_array().unwrap() {
            for b in s["buckets"].as_array().unwrap() {
                let b = b.as_array().unwrap();
                assert_eq!(b.len(), 7, "aggregate series send 7-tuples");
                let n = |i: usize| b[i].as_u64().unwrap();
                match s["id"].as_str().unwrap() {
                    "len" => {
                        assert_eq!(n(3), n(1), "every frame has frame.len");
                        assert_eq!(n(4), n(2), "sum(frame.len) == bytes");
                        len = (len.0 + n(1), len.1 + n(2), len.2 + n(4));
                    }
                    "rtt" => rtt = (rtt.0 + n(3), rtt.1 + n(4), rtt.2.min(n(5)), rtt.3.max(n(6))),
                    other => panic!("unexpected series {other}"),
                }
            }
        }
    }
    assert_eq!(len.0, 3_000);
    assert_eq!(len.1, len.2);
    assert_eq!(rtt, (fixture.responses, 2_000 * fixture.responses, 2_000, 2_000));
}
