//! KAN-131: the bounded rollups through the real binary, from a replay file to
//! the wire. Expected values are written out by hand below, not computed from
//! the code under test.
#[path = "fixtures/agent_auth.rs"]
mod agent_auth;
use serde_json::{json, Value};
use std::io::{BufRead, Read};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const LOCAL: [u8; 4] = [192, 0, 2, 1];
// Neither address order nor text order matches arrival order.
const A: [u8; 4] = [203, 0, 113, 5];
const B: [u8; 4] = [203, 0, 113, 4];
const C: [u8; 4] = [203, 0, 113, 9];
const D: [u8; 4] = [203, 0, 113, 2];
const E: [u8; 4] = [203, 0, 113, 1];

/// Ethernet + IPv4 + UDP headers.
const HEADERS: u64 = 14 + 20 + 8;

/// (remote, outbound, payload bytes), one packet every 10 ms.
///
/// Endpoints hold 2: C evicts B (t=0), D evicts A (t=20), E evicts D (t=40).
/// Left: C, and E in the slot before it. Conversations hold 3: D evicts B,
/// E evicts A. Left: C, D, E. C leads bytes and packets; E is the most recent
/// and, once every rate is zero, leads rate on the last-seen tie-break. So
/// N=1 sends C and E from both tables and leaves D unsent.
const PACKETS: [(Remote, bool, usize); 8] = [
    (B, true, 10),
    (A, true, 10),
    (A, true, 10),
    (C, true, 400),
    (D, true, 20),
    (C, false, 500),
    (C, true, 400),
    (E, true, 30),
];
type Remote = [u8; 4];

fn pcap() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xa1b2c3d4u32.to_le_bytes());
    out.extend(2u16.to_le_bytes());
    out.extend(4u16.to_le_bytes());
    out.extend([0; 8]);
    out.extend(65535u32.to_le_bytes());
    out.extend(1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    for (i, (remote, outbound, payload)) in PACKETS.iter().enumerate() {
        let (src, dst, ports) = if *outbound { (LOCAL, *remote, (40000, 4000)) } else { (*remote, LOCAL, (4000, 40000)) };
        let mut frame = Vec::new();
        etherparse::PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4(src, dst, 64)
            .udp(ports.0, ports.1)
            .write(&mut frame, &vec![0u8; *payload])
            .unwrap();
        assert_eq!(frame.len() as u64, HEADERS + *payload as u64);
        out.extend(100u32.to_le_bytes());
        out.extend((i as u32 * 10_000).to_le_bytes());
        out.extend((frame.len() as u32).to_le_bytes());
        out.extend((frame.len() as u32).to_le_bytes());
        out.extend(frame);
    }
    out
}

fn agent(token: &std::path::Path, replay: &std::path::Path, top_n: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_capture-agent"));
    command
        .env("AGENT_TOKEN_FILE", token)
        .env("REPLAY_FILE", replay)
        .env("REPLAY_SPEED", "fast")
        .env("REPLAY_LOCAL_ADDRS", "192.0.2.1")
        .env("MAX_ENDPOINTS", "2")
        .env("MAX_CONVERSATIONS", "3")
        .env("ROLLUP_TOP_N", top_n)
        .env_remove("CAPTURE_INTERFACE")
        .env_remove("REPLAY_WAIT_FOR_IO_SERIES")
        .stdout(Stdio::null());
    command
}

/// Sum of the four counters of every row, as (rx bytes, tx bytes, rx packets, tx packets).
fn row_sum(rows: &[Value]) -> [u64; 4] {
    ["rxBytesTotal", "txBytesTotal", "rxPacketsTotal", "txPacketsTotal"]
        .map(|field| rows.iter().map(|row| row[field].as_u64().unwrap()).sum())
}

fn traffic(value: &Value) -> [u64; 4] {
    ["rxBytes", "txBytes", "rxPackets", "txPackets"].map(|field| value[field].as_u64().unwrap())
}

fn minus(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    std::array::from_fn(|i| a[i] - b[i])
}

#[test]
#[ignore = "requires exclusive 127.0.0.1:9990; run with --ignored --test-threads=1"]
fn rollup_replay_through_the_real_binary() {
    // Refuse to connect to an operator's agent if the port is occupied.
    drop(TcpListener::bind("127.0.0.1:9990").expect("exclusive test port required"));
    let auth = agent_auth::AuthFixture::new();
    let path = auth.token_path().with_extension("pcap");
    std::fs::write(&path, pcap()).unwrap();

    let running = Agent(agent(&auth.token_path(), &path, "1").stderr(Stdio::null()).spawn().unwrap());
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

    // The last event of each kind. An event counts once the whole file is in
    // its totals, and the last is the third such one, so every rate has
    // drained to zero.
    let (mut endpoint, mut conversation) = (Value::Null, Value::Null);
    let (mut endpoints_seen, mut conversations_seen) = (0, 0);
    let mut legacy = Vec::new();
    let mut line = String::new();
    while Instant::now() < deadline && (endpoints_seen < 3 || conversations_seen < 3) {
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let event: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                line.clear();
                let kind = event["type"].as_str().unwrap_or_default().to_string();
                let done = {
                    let totals = &event["bounds"]["totals"];
                    totals["rxPackets"].as_u64().unwrap_or(0) + totals["txPackets"].as_u64().unwrap_or(0) == PACKETS.len() as u64
                };
                match kind.as_str() {
                    "endpoint_rollup" => {
                        endpoints_seen += usize::from(done);
                        endpoint = event;
                    }
                    "conversation_rollup" => {
                        conversations_seen += usize::from(done);
                        conversation = event;
                    }
                    "endpoint_update" | "conversation_update" => legacy.push(kind),
                    _ => {}
                }
            }
            // A partial line stays in `line` and is completed by the next read.
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(error) => panic!("wire read failed: {error}"),
        }
    }
    drop(running);
    assert!(endpoints_seen >= 3, "endpoint_rollup: {endpoints_seen} complete events; last {endpoint}");
    assert!(conversations_seen >= 3, "conversation_rollup: {conversations_seen} complete events; last {conversation}");
    assert_eq!(legacy, Vec::<String>::new());

    // Traffic per remote: (rx bytes, tx bytes, rx packets, tx packets).
    let c = [HEADERS + 500, 2 * (HEADERS + 400), 1, 2];
    let d = [0, HEADERS + 20, 0, 1];
    let e = [0, HEADERS + 30, 0, 1];
    let (a, b) = ([0, 2 * (HEADERS + 10), 0, 2], [0, HEADERS + 10, 0, 1]);
    let sum = |parts: &[[u64; 4]]| -> [u64; 4] { std::array::from_fn(|i| parts.iter().map(|p| p[i]).sum()) };

    let bounds = &endpoint["bounds"];
    assert_eq!(bounds["cap"], 2);
    assert_eq!(bounds["topN"], 1);
    assert_eq!(bounds["tracked"], 2);
    assert_eq!(bounds["evictions"], 3);
    assert_eq!(bounds["unkeyed"], 0);
    let since = bounds["sinceMs"].as_u64().unwrap();
    assert_eq!(bounds["horizonMs"], since + 40, "D was evicted last");
    assert_eq!(traffic(&bounds["totals"]), sum(&[a, b, c, d, e]));
    assert_eq!(traffic(&bounds["evicted"]), sum(&[a, b, d]));

    let rows = endpoint["endpoints"].as_array().unwrap();
    let hosts: Vec<_> = rows.iter().map(|r| (r["host"].clone(), r["historyComplete"].clone())).collect();
    // C was inserted at cap + 1, before any eviction was counted.
    assert_eq!(hosts, [(json!("203.0.113.9"), json!(true)), (json!("203.0.113.1"), json!(false))]);
    assert_eq!(row_sum(&rows[..1]), c);
    assert_eq!(row_sum(&rows[1..]), e);
    assert_eq!((&rows[0]["firstSeenMs"], &rows[0]["lastSeenMs"]), (&json!(since + 30), &json!(since + 60)));
    assert_eq!((&rows[1]["firstSeenMs"], &rows[1]["lastSeenMs"]), (&json!(since + 70), &json!(since + 70)));
    // Every tracked endpoint is sent here, so the rows alone balance.
    assert_eq!(minus(traffic(&bounds["totals"]), traffic(&bounds["evicted"])), row_sum(rows));

    let bounds = &conversation["bounds"];
    assert_eq!(bounds["cap"], 3);
    assert_eq!(bounds["topN"], 1);
    assert_eq!(bounds["tracked"], 3);
    assert_eq!(bounds["evictions"], 2);
    assert_eq!(bounds["unkeyed"], 0);
    assert_eq!(bounds["sinceMs"], since);
    assert_eq!(bounds["horizonMs"], since + 20, "A was evicted last");
    assert_eq!(traffic(&bounds["totals"]), sum(&[a, b, c, d, e]));
    assert_eq!(traffic(&bounds["evicted"]), sum(&[a, b]));

    let rows = conversation["conversations"].as_array().unwrap();
    let pairs: Vec<_> = rows
        .iter()
        .map(|r| (r["localAddr"].clone(), r["remoteAddr"].clone(), r["historyComplete"].clone()))
        .collect();
    assert_eq!(
        pairs,
        [
            (json!("192.0.2.1"), json!("203.0.113.9"), json!(true)),
            (json!("192.0.2.1"), json!("203.0.113.1"), json!(false)),
        ]
    );
    assert_eq!(row_sum(&rows[..1]), c);
    assert_eq!(row_sum(&rows[1..]), e);
    assert_eq!((&rows[0]["durationMs"], &rows[1]["durationMs"]), (&json!(30), &json!(0)));
    // D is tracked but unsent: what the rows leave out is exactly its traffic.
    assert_eq!(
        minus(minus(traffic(&bounds["totals"]), traffic(&bounds["evicted"])), row_sum(rows)),
        d
    );

    // Out of range: startup fails and the error names the variable.
    let mut refused = Agent(
        agent(&auth.token_path().with_extension("refused"), &path, "1001")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match refused.0.try_wait().unwrap() {
            Some(status) => break status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            None => panic!("ROLLUP_TOP_N=1001 did not stop the agent"),
        }
    };
    let mut stderr = String::new();
    refused.0.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    assert!(!status.success());
    assert!(stderr.contains("ROLLUP_TOP_N"), "{stderr}");
}
