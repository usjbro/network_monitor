//! KAN-110 Task 3c-2, end to end against the real agent binary in replay
//! mode with `FOLLOW_STREAM=1`: a replayed conversation comes back through
//! `get_stream` with its credential masked, a response delivered as IPv4
//! fragments, a missing segment recorded as a gap, a TLS flow's bytes
//! withheld, and a reused tuple starting a new generation, identically at
//! `REPLAY_SPEED=fast` and `realtime`. Without `FOLLOW_STREAM=1` the same
//! request says disabled and carries nothing.
#[path = "fixtures/agent_auth.rs"]
mod agent_auth;

use base64::Engine;
use etherparse::PacketBuilder;
use serde_json::{json, Value};
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

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct TempFile(PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const LOCAL: [u8; 4] = [192, 0, 2, 1];
const SERVER: [u8; 4] = [198, 51, 100, 80];
const T0_US: u64 = 1_794_120_000_000_000;
const SECRET: &str = "s3cr3t-replay-token";
const HTTP_ID: &str = "Tcp-192.0.2.1:51000-198.51.100.80:80";
const TLS_ID: &str = "Tcp-192.0.2.1:51001-198.51.100.80:443";
const REUSED_ID: &str = "Tcp-192.0.2.1:51002-198.51.100.80:80";
const RELAY_PORT: u16 = 3000;

struct Seg<'a> {
    outbound: bool,
    port: u16,
    server_port: u16,
    seq: u32,
    ack: Option<u32>,
    syn: bool,
    fin: bool,
    payload: &'a [u8],
}

fn frame(s: &Seg<'_>) -> Vec<u8> {
    let (src, dst, sport, dport) =
        if s.outbound { (LOCAL, SERVER, s.port, s.server_port) } else { (SERVER, LOCAL, s.server_port, s.port) };
    let mut builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
        .ipv4(src, dst, 64)
        .tcp(sport, dport, s.seq, 65535);
    if s.syn {
        builder = builder.syn();
    }
    if s.fin {
        builder = builder.fin();
    }
    if let Some(ack) = s.ack {
        builder = builder.ack(ack);
    }
    let mut out = Vec::new();
    builder.write(&mut out, s.payload).unwrap();
    out
}

/// Splits an Ethernet/IPv4 frame into two IPv4 fragments, the first
/// carrying `first` bytes (a multiple of 8) of the IP payload.
fn fragments(whole: &[u8], first: usize) -> [Vec<u8>; 2] {
    assert_eq!(first % 8, 0);
    let (eth, ip) = whole.split_at(14);
    let (header, payload) = ip.split_at(20);
    let piece = |bytes: &[u8], offset: usize, more: bool| {
        let mut h = header.to_vec();
        h[2..4].copy_from_slice(&((20 + bytes.len()) as u16).to_be_bytes());
        let flags_offset = ((offset / 8) as u16) | if more { 0x2000 } else { 0 };
        h[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        h[10..12].copy_from_slice(&[0, 0]);
        let sum = h.chunks(2).map(|w| u32::from(u16::from_be_bytes([w[0], w[1]]))).sum::<u32>();
        let folded = (sum & 0xffff) + (sum >> 16);
        h[10..12].copy_from_slice(&(!((folded & 0xffff) + (folded >> 16)) as u16).to_be_bytes());
        [eth, &h, bytes].concat()
    };
    [piece(&payload[..first], 0, true), piece(&payload[first..], first, false)]
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

fn request_text() -> String {
    format!("GET / HTTP/1.1\r\nAuthorization: Bearer {SECRET}\r\nHost: a\r\n\r\n")
}

const RESPONSE_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 60\r\n\r\n0123456789abcdefghij\n";
const LOST: &[u8] = b"LOSTLOSTLO";
/// The rest of the line the gap interrupted is uncertain, so masked (D7);
/// the next line is not.
const AFTER_GAP: &[u8] = b"tail\nafter-the-gap\n";
const AFTER_GAP_SHOWN: &[u8] = b"****\nafter-the-gap\n";

/// Handshake both ways from `t`; returns the next sequence numbers.
fn handshake(frames: &mut Vec<(u64, Vec<u8>)>, t: u64, port: u16, server_port: u16) -> (u32, u32) {
    let (c, s) = (1_000u32, 50_000u32);
    let seg = |outbound, seq, ack, syn| Seg { outbound, port, server_port, seq, ack, syn, fin: false, payload: b"" };
    frames.push((t, frame(&seg(true, c, None, true))));
    frames.push((t + 1_000, frame(&seg(false, s, Some(c + 1), true))));
    frames.push((t + 2_000, frame(&seg(true, c + 1, Some(s + 1), false))));
    (c + 1, s + 1)
}

fn capture() -> Vec<(u64, Vec<u8>)> {
    let mut f = Vec::new();
    let data = |outbound, port, server_port, seq, ack, payload| Seg {
        outbound,
        port,
        server_port,
        seq,
        ack: Some(ack),
        syn: false,
        fin: false,
        payload,
    };

    // A conversation on 51002 that closes, then the same tuple 130 s later
    // (past FlowTable's 120 s close-wait threshold): a new generation.
    let (c, s) = handshake(&mut f, T0_US, 51002, 80);
    f.push((T0_US + 10_000, frame(&data(true, 51002, 80, c, s, b"GET /old HTTP/1.1\r\n\r\n"))));
    let fin = |outbound, seq, ack| Seg { outbound, port: 51002, server_port: 80, seq, ack: Some(ack), syn: false, fin: true, payload: b"" };
    f.push((T0_US + 20_000, frame(&fin(true, c + 21, s))));
    f.push((T0_US + 30_000, frame(&fin(false, s, c + 22))));
    let t1 = T0_US + 130_000_000;
    let (c, s) = handshake(&mut f, t1, 51002, 80);
    f.push((t1 + 10_000, frame(&data(true, 51002, 80, c, s, b"GET /new HTTP/1.1\r\n\r\n"))));

    // HTTP on 51000: a credential, a fragmented response, then a lost
    // segment and the one after it.
    let t2 = t1 + 1_000_000;
    let (c, s) = handshake(&mut f, t2, 51000, 80);
    let req = request_text();
    f.push((t2 + 10_000, frame(&data(true, 51000, 80, c, s, req.as_bytes()))));
    let c_next = c + req.len() as u32;
    let [first, second] = fragments(&frame(&data(false, 51000, 80, s, c_next, RESPONSE_HEAD)), 32);
    f.push((t2 + 20_000, first));
    f.push((t2 + 21_000, second));
    let lost_at = s + RESPONSE_HEAD.len() as u32;
    // `LOST` is never captured.
    f.push((t2 + 30_000, frame(&data(false, 51000, 80, lost_at + LOST.len() as u32, c_next, AFTER_GAP))));

    // TLS on 51001: a handshake record, never emitted as bytes.
    let (c, s) = handshake(&mut f, t2 + 40_000, 51001, 443);
    let hello = [&[0x16, 0x03, 0x01, 0x00, 0x2c][..], &[0x01; 0x2c][..]].concat();
    f.push((t2 + 50_000, frame(&data(true, 51001, 443, c, s, &hello))));

    // Five seconds later: capture time passes the 2 s hole and
    // classification deadlines before the replay ends.
    f.push((t2 + 5_000_000, frame(&data(true, 51001, 443, c + hello.len() as u32, s, b""))));
    f
}

fn write_temp(label: &str, bytes: &[u8]) -> TempFile {
    // Unique per call: tests run in parallel and each deletes its own file.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("kan110-{label}-{}-{n}.pcap", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    TempFile(path)
}

fn get_stream(n: usize, id: &str, generation: Option<&str>) -> String {
    let mut m = json!({
        "type": "get_stream",
        "requestId": format!("{n:032x}"),
        "connectionId": id,
        "c2s": { "offset": 0 },
        "s2c": { "offset": 0 },
        "relayPort": RELAY_PORT,
    });
    if let Some(g) = generation {
        m["generation"] = json!(g);
    }
    let mut line = m.to_string();
    line.push('\n');
    line
}

/// Replays the capture to the end, then asks for each flow once capture
/// time has settled (the emitter ticks the store once a second).
fn replay_and_ask(speed: &str, follow: bool) -> Vec<Value> {
    let file = write_temp(&format!("{speed}-{follow}"), &classic_pcap(&capture()));
    let _guard = AGENT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let auth = agent_auth::AuthFixture::new();
    // The no-disk invariant for retained content: the agent runs in an empty
    // working directory, which must still be empty after every reply.
    let workdir = TempDir(file.0.with_extension("cwd"));
    std::fs::create_dir_all(&workdir.0).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_capture-agent"));
    command
        .current_dir(&workdir.0)
        .env("AGENT_TOKEN_FILE", auth.token_path())
        .env("REPLAY_FILE", &file.0)
        .env("REPLAY_SPEED", speed)
        .env("REPLAY_LOCAL_ADDRS", "192.0.2.1")
        .env_remove("CAPTURE_INTERFACE")
        .env_remove("REPLAY_WAIT_FOR_IO_SERIES")
        .env_remove("RELAY_PORT")
        .env_remove("FRONT_DOOR_PORT")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if follow {
        command.env("FOLLOW_STREAM", "1");
    } else {
        command.env_remove("FOLLOW_STREAM");
    }
    let mut agent = Agent(command.spawn().unwrap());
    let (finished_tx, finished_rx) = mpsc::channel();
    let stdout = agent.0.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("replay finished") {
                let _ = finished_tx.send(());
            }
        }
    });
    finished_rx.recv_timeout(Duration::from_secs(60)).expect("replay finished");

    let stream = TcpStream::connect("127.0.0.1:9990").expect("agent listening");
    let mut reader = auth.authenticate(stream);
    reader.get_mut().set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut n = 0;
    let mut ask = |reader: &mut BufReader<TcpStream>, id: &str, generation: Option<&str>| -> Value {
        n += 1;
        let request = get_stream(n, id, generation);
        reader.get_mut().write_all(request.as_bytes()).unwrap();
        let want = format!("{n:032x}");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(Instant::now() < deadline, "no stream_data reply");
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0, "agent closed the connection");
            let value: Value = serde_json::from_str(&line).unwrap();
            if value["type"] == "stream_data" {
                assert!(line.len() <= 192 * 1024, "reply over the line ceiling");
                assert!(!line.contains(SECRET), "the secret left the agent");
                if value["requestId"] == want.as_str() {
                    return value;
                }
            } else {
                assert!(!line.contains(SECRET), "the secret reached the broadcast stream");
            }
        }
    };
    // The emitter ticks the store once a second; wait for the hole and the
    // classification deadlines it settles.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let reply = ask(&mut reader, HTTP_ID, None);
        let settled = reply["enabled"] == false || !reply["directions"]["serverToClient"]["gaps"].as_array().unwrap().is_empty();
        if settled {
            break;
        }
        assert!(Instant::now() < deadline, "the store never settled: {reply}");
        std::thread::sleep(Duration::from_millis(200));
    }
    let http = ask(&mut reader, HTTP_ID, None);
    let tls = ask(&mut reader, TLS_ID, None);
    let reused = ask(&mut reader, REUSED_ID, None);
    // The first conversation's generation: this run's epoch, counter 1
    // (any well-formed epoch when Follow Stream is off and none is given).
    let epoch = reused["generation"].as_str().and_then(|g| g.split(':').next()).unwrap_or("0000000000000000").to_owned();
    let stale = ask(&mut reader, REUSED_ID, Some(&format!("{epoch}:1")));
    let written: Vec<_> = std::fs::read_dir(&workdir.0).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert!(written.is_empty(), "the agent wrote files: {written:?}");
    vec![http, tls, reused, stale]
}

fn bytes(reply: &Value, dir: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(reply["directions"][dir]["dataBase64"].as_str().unwrap())
        .unwrap()
}

/// Epoch varies per run; everything else must match across speeds.
fn without_epoch(mut replies: Vec<Value>) -> Vec<Value> {
    for r in &mut replies {
        if let Some(g) = r["generation"].as_str().map(str::to_owned) {
            r["generation"] = json!(g.split(':').nth(1).unwrap());
        }
        r["requestId"] = json!("");
    }
    replies
}

#[test]
fn a_replayed_conversation_comes_back_masked_with_its_gaps_and_generations() {
    let replies = replay_and_ask("fast", true);
    let [http, tls, reused, stale] = &replies[..] else { unreachable!() };

    assert_eq!((http["found"].as_bool(), http["clientIsLocal"].as_bool()), (Some(true), Some(true)));
    // The whole header value is masked, scheme included.
    let value = format!("Bearer {SECRET}");
    let masked = request_text().replace(&value, &"*".repeat(value.len()));
    assert_eq!(String::from_utf8(bytes(http, "clientToServer")).unwrap(), masked, "masked request");
    let response = bytes(http, "serverToClient");
    assert_eq!(response, [RESPONSE_HEAD, AFTER_GAP_SHOWN].concat(), "fragmented response and the bytes after the gap");
    assert_eq!(
        http["directions"]["serverToClient"]["gaps"],
        json!([{ "at": RESPONSE_HEAD.len(), "missing": LOST.len(), "reason": "missing" }])
    );
    assert_eq!(
        http["directions"]["serverToClient"]["redactedRanges"],
        json!([{ "start": RESPONSE_HEAD.len(), "len": 4, "reason": "uncertain" }])
    );

    assert_eq!(tls["directions"]["clientToServer"]["classification"], "tls");
    assert_eq!(tls["directions"]["clientToServer"]["dataBase64"], "", "TLS bytes were emitted");

    assert_eq!(bytes(reused, "clientToServer"), b"GET /new HTTP/1.1\r\n\r\n", "the old conversation leaked into the new one");
    let generation = reused["generation"].as_str().unwrap();
    assert!(!generation.ends_with(":1"), "a reused tuple kept its first generation: {generation}");
    assert_eq!((stale["stale"].as_bool(), stale["generation"].as_str()), (Some(true), Some(generation)));
    assert_eq!(stale["directions"]["clientToServer"]["dataBase64"], "");
}

#[test]
fn realtime_and_fast_replay_give_the_same_streams() {
    assert_eq!(without_epoch(replay_and_ask("realtime", true)), without_epoch(replay_and_ask("fast", true)));
}

#[test]
fn without_follow_stream_the_agent_says_disabled_and_sends_nothing() {
    for reply in replay_and_ask("fast", false) {
        assert_eq!((reply["enabled"].as_bool(), reply["found"].as_bool()), (Some(false), Some(false)));
        assert_eq!(reply["directions"]["clientToServer"]["dataBase64"], "");
        assert_eq!(reply["directions"]["serverToClient"]["dataBase64"], "");
    }
}
