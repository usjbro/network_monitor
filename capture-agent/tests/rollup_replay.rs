//! KAN-131: the bounded rollups through the real binary, from a replay file to
//! the wire. Expected values are written out by hand below, not computed from
//! the code under test.
#[path = "fixtures/agent_auth.rs"]
mod agent_auth;
#[path = "fixtures/replay_agent.rs"]
mod replay_agent;
use replay_agent::{classic_pcap, run_until_replayed, write_temp, Agent, AGENT_LOCK};
use serde_json::{json, Value};
use std::io::{BufRead, Error, ErrorKind, Read};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

/// A classic pcap of (time in ms, remote, outbound, payload bytes) UDP packets.
fn pcap(packets: impl Iterator<Item = (u32, Remote, bool, usize)>) -> Vec<u8> {
    let frames: Vec<_> = packets
        .map(|(ms, remote, outbound, payload)| {
            let (src, dst, ports) = if outbound { (LOCAL, remote, (40000, 4000)) } else { (remote, LOCAL, (4000, 40000)) };
            let mut frame = Vec::new();
            etherparse::PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
                .ipv4(src, dst, 64)
                .udp(ports.0, ports.1)
                .write(&mut frame, &vec![0u8; payload])
                .unwrap();
            assert_eq!(frame.len() as u64, HEADERS + payload as u64);
            (100_000_000 + u64::from(ms) * 1000, frame)
        })
        .collect();
    classic_pcap(&frames)
}

/// `limits`: MAX_ENDPOINTS, MAX_CONVERSATIONS, ROLLUP_TOP_N.
fn agent(token: &std::path::Path, replay: &std::path::Path, limits: [&str; 3]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_capture-agent"));
    // The operator's shell must not change the result.
    for name in [
        "CAPTURE_INTERFACE",
        "FOLLOW_STREAM",
        "FRONT_DOOR_PORT",
        "MAX_FLOWS",
        "MAX_OBSERVED_DNS_NAMES",
        "RELAY_PORT",
        "REPLAY_WAIT_FOR_IO_SERIES",
    ] {
        command.env_remove(name);
    }
    command
        .env("AGENT_TOKEN_FILE", token)
        .env("REPLAY_FILE", replay)
        .env("REPLAY_SPEED", "fast")
        .env("REPLAY_LOCAL_ADDRS", "192.0.2.1")
        .env("MAX_ENDPOINTS", limits[0])
        .env("MAX_CONVERSATIONS", limits[1])
        .env("ROLLUP_TOP_N", limits[2]);
    command
}

/// Far above any line these replays produce (N is 1, and payloads are small).
const MAX_AGENT_LINE_BYTES: usize = 64 * 1024;

/// Completes `line` and parses it. The limit is on the whole line however many
/// reads it takes: after a read timeout, call again with the same `line`.
/// Bytes, not a `String`, so a timeout inside a character loses nothing.
fn read_agent_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> std::io::Result<Value> {
    let room = (MAX_AGENT_LINE_BYTES + 1).saturating_sub(line.len());
    reader.take(room as u64).read_until(b'\n', line)?;
    if line.len() > MAX_AGENT_LINE_BYTES || !line.ends_with(b"\n") {
        return Err(Error::new(ErrorKind::InvalidData, "oversized or incomplete agent line"));
    }
    let value = serde_json::from_slice(line).map_err(|_| Error::new(ErrorKind::InvalidData, "invalid agent JSON"))?;
    line.clear();
    Ok(value)
}

/// Yields each chunk, then times out once, like a socket with a read timeout.
struct Stuttering(std::collections::VecDeque<Vec<u8>>, bool, usize);
impl Read for Stuttering {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if std::mem::take(&mut self.1) {
            return Err(ErrorKind::WouldBlock.into());
        }
        let Some(chunk) = self.0.front_mut() else { return Ok(0) };
        let n = chunk.len().min(out.len());
        out[..n].copy_from_slice(&chunk[..n]);
        chunk.drain(..n);
        self.2 += n;
        if chunk.is_empty() {
            self.0.pop_front();
            self.1 = true;
        }
        Ok(n)
    }
}

fn stuttering(chunks: &[&[u8]]) -> std::io::BufReader<Stuttering> {
    std::io::BufReader::with_capacity(1, Stuttering(chunks.iter().map(|c| c.to_vec()).collect(), false, 0))
}

#[test]
fn agent_line_reader_enforces_the_limit_before_parsing() {
    let mut oversized = std::io::Cursor::new(vec![b' '; MAX_AGENT_LINE_BYTES * 2]);
    assert!(read_agent_line(&mut oversized, &mut Vec::new()).is_err());
    assert_eq!(oversized.position(), (MAX_AGENT_LINE_BYTES + 1) as u64);

    // Valid JSON, one byte over.
    let mut over = vec![b' '; MAX_AGENT_LINE_BYTES + 1];
    over[0] = b'0';
    over[MAX_AGENT_LINE_BYTES] = b'\n';
    assert!(read_agent_line(&mut &over[..], &mut Vec::new()).is_err());
    // Exactly the limit.
    over.remove(1);
    assert_eq!(read_agent_line(&mut &over[..], &mut Vec::new()).unwrap(), 0);

    for bad in [&b"0"[..], b"", b"{nope}\n"] {
        assert_eq!(read_agent_line(&mut &bad[..], &mut Vec::new()).unwrap_err().kind(), ErrorKind::InvalidData);
    }
}

#[test]
fn agent_line_reader_keeps_a_partial_line_across_a_timeout() {
    // The first split is inside a two-byte character.
    let mut reader = stuttering(&[b"{\"a\":\"\xc3", b"\xa9\"}", b"\n1\n"]);
    let mut line = Vec::new();
    for _ in 0..2 {
        assert_eq!(read_agent_line(&mut reader, &mut line).unwrap_err().kind(), ErrorKind::WouldBlock);
    }
    assert_eq!(read_agent_line(&mut reader, &mut line).unwrap(), json!({"a": "\u{e9}"}));
    assert_eq!(read_agent_line(&mut reader, &mut line).unwrap(), 1);

    // The limit is on the accumulated line, not on each read.
    let half = vec![b' '; MAX_AGENT_LINE_BYTES / 2 + 1];
    let mut reader = stuttering(&[&half, &half, &half]);
    let mut line = Vec::new();
    assert_eq!(read_agent_line(&mut reader, &mut line).unwrap_err().kind(), ErrorKind::WouldBlock);
    assert_eq!(read_agent_line(&mut reader, &mut line).unwrap_err().kind(), ErrorKind::InvalidData);
    assert_eq!(reader.get_ref().2, MAX_AGENT_LINE_BYTES + 1);
}

/// What a client saw up to the third event of each kind whose totals hold all
/// `packets`: by then every rate has drained to zero.
#[derive(Default)]
struct Seen {
    endpoint: Value,
    conversation: Value,
    endpoints_complete: usize,
    conversations_complete: usize,
    legacy: Vec<String>,
    /// The types of the three lines that ended with the last
    /// `conversation_rollup`.
    tick_end: Vec<String>,
    flows_observed: u64,
}

fn watch(auth: &agent_auth::AuthFixture, packets: u64) -> Seen {
    let deadline = Instant::now() + Duration::from_secs(15);
    // The agent listens before it publishes its token.
    agent_auth::read_token(&auth.token_path());
    let stream = TcpStream::connect("127.0.0.1:9990").expect("agent listening");
    let mut reader = auth.authenticate(stream);
    reader.get_mut().set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let mut seen = Seen::default();
    let mut recent = std::collections::VecDeque::from([String::new(), String::new(), String::new()]);
    let mut line = Vec::new();
    while Instant::now() < deadline && (seen.endpoints_complete < 3 || seen.conversations_complete < 3) {
        match read_agent_line(&mut reader, &mut line) {
            Ok(event) => {
                let kind = event["type"].as_str().unwrap_or_default().to_string();
                recent.pop_front();
                recent.push_back(kind.clone());
                let totals = &event["bounds"]["totals"];
                let complete =
                    totals["rxPackets"].as_u64().unwrap_or(0) + totals["txPackets"].as_u64().unwrap_or(0) == packets;
                match kind.as_str() {
                    "endpoint_rollup" => {
                        seen.endpoints_complete += usize::from(complete);
                        seen.endpoint = event;
                    }
                    "conversation_rollup" => {
                        seen.conversations_complete += usize::from(complete);
                        seen.conversation = event;
                        seen.tick_end = recent.iter().cloned().collect();
                    }
                    "endpoint_update" | "conversation_update" => seen.legacy.push(kind),
                    "capture_stats" => {
                        seen.flows_observed = event["stats"]["totalConnectionsObserved"].as_u64().unwrap_or(0);
                    }
                    _ => {}
                }
            }
            // A partial line stays in `line` and is completed by the next read.
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => panic!("wire read failed: {error}"),
        }
    }
    assert!(seen.endpoints_complete >= 3, "endpoint_rollup: {} complete events; last {}", seen.endpoints_complete, seen.endpoint);
    assert!(
        seen.conversations_complete >= 3,
        "conversation_rollup: {} complete events; last {}",
        seen.conversations_complete,
        seen.conversation
    );
    seen
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
    let _serial = AGENT_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    // Refuse to connect to an operator's agent if the port is occupied.
    drop(TcpListener::bind("127.0.0.1:9990").expect("exclusive test port required"));
    let auth = agent_auth::AuthFixture::new();
    let packets = PACKETS.iter().enumerate().map(|(i, &(remote, outbound, payload))| (i as u32 * 10, remote, outbound, payload));
    let file = write_temp("kan131", "rollup", &pcap(packets));

    let running = run_until_replayed(&mut agent(&auth.token_path(), &file.0, ["2", "3", "1"]), Duration::from_secs(15));
    let Seen { endpoint, conversation, legacy, .. } = watch(&auth, PACKETS.len() as u64);
    drop(running);
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
        agent(&auth.token_path().with_extension("refused"), &file.0, ["2", "3", "1001"])
            .stdout(Stdio::null())
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

/// More live flows than the agent's 1,024-event queue holds, and the host and
/// conversation lists still arrive.
///
/// A tick sends one event per live flow in one burst, and a queue that
/// overflows drops its oldest events. The lists are the last two events of the
/// tick, so a client that overflowed resumes with both still queued, and it
/// keeps them unless another 1,022 events are sent before it reads that far.
/// The next burst is a second away and the replay is over, so nothing else is.
/// Sent before the per-flow events, they are the first to be dropped.
#[test]
#[ignore = "requires exclusive 127.0.0.1:9990; run with --ignored --test-threads=1"]
fn rollups_survive_a_tick_larger_than_the_client_queue() {
    const FLOWS: u32 = 4_000;
    let _serial = AGENT_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    drop(TcpListener::bind("127.0.0.1:9990").expect("exclusive test port required"));
    let auth = agent_auth::AuthFixture::new();
    let packets = (0..FLOWS).map(|i| (i / 10, [198, 18, (i >> 8) as u8, i as u8], true, 20));
    let file = write_temp("kan131", "rollup", &pcap(packets));

    let running = run_until_replayed(&mut agent(&auth.token_path(), &file.0, ["5000", "5000", "1"]), Duration::from_secs(15));
    let seen = watch(&auth, u64::from(FLOWS));
    drop(running);
    assert_eq!(seen.flows_observed, u64::from(FLOWS));
    assert_eq!(seen.endpoint["bounds"]["tracked"], FLOWS);
    assert_eq!(seen.conversation["bounds"]["tracked"], FLOWS);
    assert_eq!(seen.tick_end, ["agent_status", "endpoint_rollup", "conversation_rollup"]);
}
