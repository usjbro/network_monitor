//! KAN-129 Task 3, end to end against the real agent binary in replay
//! mode: a replayed TCP flow's sample ring comes back through
//! `get_tcp_samples` as the plan describes — a monotonic staircase, a
//! marked retransmission and zero window, scaled windows only when both
//! sides negotiated scaling, RTT equal to the fixture's ACK delay, the same
//! reply at `REPLAY_SPEED=realtime` and `fast`, and `capture_stats` cost
//! fields that match the rings held.
#[path = "fixtures/agent_auth.rs"]
mod agent_auth;

use capture_agent::tcp_samples::{flag, mark, RING_RESERVED_BYTES};
use etherparse::{PacketBuilder, TcpOptionElement};
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

struct TempFile(PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const LOCAL: [u8; 4] = [192, 0, 2, 1];
const SERVER: [u8; 4] = [198, 51, 100, 80];
const CLIENT_PORT: u16 = 51000;
const SERVER_PORT: u16 = 80;
const CONNECTION_ID: &str = "Tcp-192.0.2.1:51000-198.51.100.80:80";
const T0_US: u64 = 1_794_120_000_000_000;
const CLIENT_ISN: u32 = 4_000_000_000; // wraps during the transfer
const SERVER_ISN: u32 = 77;
const SEGMENT: usize = 1000;
const ACK_DELAY_US: u64 = 2_000;

struct Segment {
    outbound: bool,
    seq: u32,
    ack: Option<u32>,
    syn: bool,
    window: u16,
    wscale: Option<u8>,
    len: usize,
}

fn frame(s: &Segment) -> Vec<u8> {
    let (src, dst, sport, dport) = if s.outbound {
        (LOCAL, SERVER, CLIENT_PORT, SERVER_PORT)
    } else {
        (SERVER, LOCAL, SERVER_PORT, CLIENT_PORT)
    };
    let mut builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
        .ipv4(src, dst, 64)
        .tcp(sport, dport, s.seq, s.window);
    if s.syn {
        builder = builder.syn();
    }
    if let Some(ack) = s.ack {
        builder = builder.ack(ack);
    }
    if let Some(shift) = s.wscale {
        builder = builder.options(&[TcpOptionElement::WindowScale(shift)]).unwrap();
    }
    let mut out = Vec::new();
    builder.write(&mut out, &vec![b'd'; s.len]).unwrap();
    out
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

/// A handshake, `segments` outbound data segments 1 ms apart each ACKed
/// `ACK_DELAY_US` later, one retransmission of segment 5, then a
/// zero-window ACK. `client_wscale`/`server_wscale` are the SYN and SYN-ACK
/// window-scale options.
fn bulk_transfer(segments: u32, client_wscale: Option<u8>, server_wscale: Option<u8>) -> Vec<(u64, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut t = T0_US;
    let mut push = |t: u64, s: Segment| frames.push((t, frame(&s)));
    let data_start = CLIENT_ISN.wrapping_add(1);
    let server_next = SERVER_ISN.wrapping_add(1);
    let syn = |outbound, seq, ack, wscale| Segment { outbound, seq, ack, syn: true, window: 65535, wscale, len: 0 };
    push(t, syn(true, CLIENT_ISN, None, client_wscale));
    t += 10_000;
    push(t, syn(false, SERVER_ISN, Some(data_start), server_wscale));
    t += 10_000;
    push(t, Segment { outbound: true, seq: data_start, ack: Some(server_next), syn: false, window: 512, wscale: None, len: 0 });
    let data = |i: u32| Segment {
        outbound: true,
        seq: data_start.wrapping_add(i * SEGMENT as u32),
        ack: Some(server_next),
        syn: false,
        window: 512,
        wscale: None,
        len: SEGMENT,
    };
    let ack = |i: u32, window: u16| Segment {
        outbound: false,
        seq: server_next,
        ack: Some(data_start.wrapping_add((i + 1) * SEGMENT as u32)),
        syn: false,
        window,
        wscale: None,
        len: 0,
    };
    for i in 0..segments {
        t += 1_000;
        push(t, data(i));
        push(t + ACK_DELAY_US, ack(i, 100));
        t += ACK_DELAY_US;
    }
    t += 1_000;
    push(t, data(5)); // retransmission
    t += 1_000;
    push(t, ack(segments - 1, 0)); // zero window
    frames
}

fn write_temp(label: &str, bytes: &[u8]) -> TempFile {
    let path = std::env::temp_dir().join(format!("kan129-{label}-{}.pcap", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    TempFile(path)
}

struct Answer {
    /// Every page, in order, until `more` was false.
    pages: Vec<Value>,
    capture_stats: Value,
}

fn request_id(n: usize) -> String {
    format!("{n:032x}")
}

/// Replays `frames` to the end, then pages through `connection_id`'s ring
/// and reads one `capture_stats` sent after the replay finished.
fn replay_and_ask(label: &str, frames: &[(u64, Vec<u8>)], speed: &str, connection_id: &str) -> Answer {
    let file = write_temp(label, &classic_pcap(frames));
    let _guard = AGENT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let auth = agent_auth::AuthFixture::new();
    let mut agent = Agent(
        Command::new(env!("CARGO_BIN_EXE_capture-agent"))
            .env("AGENT_TOKEN_FILE", auth.token_path())
            .env("REPLAY_FILE", &file.0)
            .env("REPLAY_SPEED", speed)
            .env("REPLAY_LOCAL_ADDRS", "192.0.2.1")
            .env_remove("CAPTURE_INTERFACE")
            .env_remove("REPLAY_WAIT_FOR_IO_SERIES")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let (finished_tx, finished_rx) = mpsc::channel();
    let stdout = agent.0.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("replay finished") {
                let _ = finished_tx.send(());
            }
        }
    });
    finished_rx.recv_timeout(Duration::from_secs(30)).expect("replay finished");

    let stream = TcpStream::connect("127.0.0.1:9990").expect("agent listening");
    let mut reader = auth.authenticate(stream);
    reader.get_mut().set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let read = |reader: &mut BufReader<TcpStream>, want: &dyn Fn(&Value) -> bool| -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(Instant::now() < deadline, "no matching line");
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0, "agent closed the connection");
            let value: Value = serde_json::from_str(&line).unwrap();
            if value["type"] == "tcp_samples" {
                assert!(line.len() <= 256 * 1024, "reply over the line ceiling");
            }
            if want(&value) {
                return value;
            }
        }
    };

    let mut pages = Vec::new();
    let mut from_index = 0;
    loop {
        let id = request_id(pages.len());
        let mut message =
            json!({ "type": "get_tcp_samples", "requestId": id, "connectionId": connection_id, "fromIndex": from_index })
                .to_string();
        message.push('\n');
        reader.get_mut().write_all(message.as_bytes()).unwrap();
        let page = read(&mut reader, &|v| v["type"] == "tcp_samples" && v["requestId"] == id.as_str());
        let more = page["more"] == true;
        from_index = page["nextIndex"].as_u64().unwrap_or(0);
        pages.push(page);
        if !more {
            break;
        }
        assert!(pages.len() < 10, "paging did not end");
    }
    let capture_stats = read(&mut reader, &|v| v["type"] == "capture_stats")["stats"].clone();
    Answer { pages, capture_stats }
}

/// One decoded sample, with an absolute timestamp and relative sequence.
#[derive(Debug, Clone, PartialEq)]
struct Sample {
    t_us: u64,
    seq: u64,
    ack: u64,
    win: u64,
    len: u64,
    flags: u64,
    mark: u64,
    rtt_us: u64,
}

fn samples(page: &Value) -> Vec<Sample> {
    let s = &page["samples"];
    let col = |name: &str| -> Vec<i64> { s[name].as_array().unwrap().iter().map(|v| v.as_i64().unwrap()).collect() };
    let (t, seq, ack, win, len, flags, marks, rtt) =
        (col("tUs"), col("seq"), col("ack"), col("win"), col("len"), col("flags"), col("mark"), col("rttUs"));
    let mut at = 0i64;
    (0..t.len())
        .map(|i| {
            at = if i == 0 { t[0] } else { at + t[i] };
            Sample {
                t_us: at as u64,
                seq: seq[i] as u64,
                ack: ack[i] as u64,
                win: win[i] as u64,
                len: len[i] as u64,
                flags: flags[i] as u64,
                mark: marks[i] as u64,
                rtt_us: rtt[i] as u64,
            }
        })
        .collect()
}

fn all_samples(answer: &Answer) -> Vec<Sample> {
    answer.pages.iter().flat_map(samples).collect()
}

const SEGMENTS: u32 = 40;

#[test]
fn a_bulk_transfer_replays_as_a_marked_staircase_with_per_ack_rtt() {
    let answer = replay_and_ask("bulk", &bulk_transfer(SEGMENTS, Some(7), Some(8)), "fast", CONNECTION_ID);
    assert_eq!(answer.pages.len(), 1);
    let page = &answer.pages[0];
    assert_eq!((page["found"].as_bool(), page["stale"].as_bool()), (Some(true), Some(false)));
    assert_eq!(page["handshakeSeen"], true);
    assert_eq!(page["relativeTo"], "isn");
    assert_eq!(page["seqBase"], json!({ "outbound": CLIENT_ISN, "inbound": SERVER_ISN }));
    assert_eq!(page["windowScale"], json!({ "local": 7, "remote": 8 }));
    let samples = all_samples(&answer);
    // Handshake (3) + data and its ACKs (2 each) + retransmission + zero window.
    assert_eq!(samples.len() as u32, 3 + 2 * SEGMENTS + 2);
    assert_eq!(samples[0].t_us, T0_US);
    assert!(samples.windows(2).all(|w| w[0].t_us <= w[1].t_us), "frame timestamps in order");

    let outbound = |s: &&Sample| s.mark & u64::from(mark::OUTBOUND) != 0;
    let retransmit = |s: &&Sample| s.mark & u64::from(mark::RETRANSMIT) != 0;
    // Staircase: first-sent data segments climb by one segment each,
    // relative to the ISN, across the sequence-number wrap.
    let first_sent: Vec<u64> = samples.iter().filter(outbound).filter(|s| s.len > 0 && !retransmit(s)).map(|s| s.seq).collect();
    assert_eq!(first_sent, (0..u64::from(SEGMENTS)).map(|i| 1 + i * SEGMENT as u64).collect::<Vec<_>>());
    // The one retransmission is marked and is segment 5 again.
    let retransmits: Vec<&Sample> = samples.iter().filter(retransmit).collect();
    assert_eq!(retransmits.len(), 1);
    assert_eq!(retransmits[0].seq, 1 + 5 * SEGMENT as u64);

    // Scaled on both sides: the server's raw 100 arrives as 100 << 8.
    let acks: Vec<&Sample> = samples.iter().filter(|s| !outbound(s) && s.flags & u64::from(flag::SYN) == 0).collect();
    assert!(acks[..acks.len() - 1].iter().all(|s| s.win == 100 << 8 && s.mark & u64::from(mark::WIN_SCALED) != 0));
    let zero = acks.last().unwrap();
    assert_eq!(zero.win, 0);
    assert_ne!(zero.mark & u64::from(mark::ZERO_WINDOW), 0, "the zero window is marked");
    assert_eq!(acks.iter().filter(|s| s.mark & u64::from(mark::ZERO_WINDOW) != 0).count(), 1);
    // ACKs are relative to the client's ISN.
    assert_eq!(acks[0].ack, 1 + SEGMENT as u64);

    // RTT per ACK equals the fixture's ACK delay; Karn's rule leaves the
    // ACK after the retransmission without one.
    let rtts: Vec<u64> = samples.iter().filter(|s| s.mark & u64::from(mark::RTT) != 0).map(|s| s.rtt_us).collect();
    assert_eq!(rtts.len() as u32, SEGMENTS);
    assert!(rtts.iter().all(|&r| r == ACK_DELAY_US), "{rtts:?}");

    // Cost fields: one ring, counted by reserved capacity.
    let stats = &answer.capture_stats;
    assert_eq!(stats["tcpSampleRings"], 1);
    assert_eq!(stats["tcpSampleRingBytes"].as_u64(), Some(RING_RESERVED_BYTES as u64));
    assert_eq!(stats["tcpSampleRingsRecycled"], 0);
}

#[test]
fn scaling_offered_by_one_side_only_leaves_windows_raw() {
    let answer = replay_and_ask("oneside", &bulk_transfer(4, Some(7), None), "fast", CONNECTION_ID);
    let page = &answer.pages[0];
    assert_eq!(page["windowScale"], Value::Null);
    let samples = all_samples(&answer);
    assert!(samples.iter().all(|s| s.mark & u64::from(mark::WIN_SCALED) == 0));
    assert!(samples.iter().filter(|s| s.mark & u64::from(mark::OUTBOUND) == 0 && s.flags & u64::from(flag::SYN) == 0).any(|s| s.win == 100));
}

#[test]
fn unknown_and_non_tcp_ids_are_found_false() {
    for id in ["Tcp-192.0.2.1:51001-198.51.100.80:80", "Udp-192.0.2.1:51000-198.51.100.80:80", "not-an-id"] {
        let answer = replay_and_ask("absent", &bulk_transfer(2, None, None), "fast", id);
        let page = &answer.pages[0];
        assert_eq!(page["found"], false, "{id}");
        assert_eq!(page["connectionId"], id);
        assert!(page.get("samples").is_none());
    }
}

#[test]
fn realtime_and_fast_replays_give_identical_replies() {
    let frames = bulk_transfer(SEGMENTS, Some(7), Some(8));
    let strip = |answer: Answer| -> Vec<Value> {
        answer
            .pages
            .into_iter()
            .map(|mut page| {
                // The generation's epoch is random per process.
                page.as_object_mut().unwrap().remove("generation");
                page
            })
            .collect()
    };
    let fast = strip(replay_and_ask("speed-fast", &frames, "fast", CONNECTION_ID));
    let realtime = strip(replay_and_ask("speed-realtime", &frames, "realtime", CONNECTION_ID));
    assert_eq!(fast, realtime);
    assert!(!samples(&fast[0]).is_empty());
}

#[test]
fn a_ring_past_one_page_is_read_in_two() {
    // 3 + 2 × 2 100 + 2 = 4 205 samples: the ring keeps 4 096, overwriting
    // 109, and a reader starting at 0 needs two pages.
    let answer = replay_and_ask("pages", &bulk_transfer(2_100, Some(7), Some(8)), "fast", CONNECTION_ID);
    let lens: Vec<usize> = answer.pages.iter().map(|p| samples(p).len()).collect();
    assert_eq!(lens, vec![3072, 4096 - 3072]);
    let (one, two) = (&answer.pages[0], &answer.pages[1]);
    assert_eq!((one["firstIndex"].as_u64(), one["droppedOlder"].as_u64(), one["more"].as_bool()), (Some(109), Some(109), Some(true)));
    assert_eq!((two["nextIndex"].as_u64(), two["droppedOlder"].as_u64(), two["more"].as_bool()), (Some(4205), Some(0), Some(false)));
    assert_eq!(one["nextIndex"].as_u64(), Some(109 + 3072));
}
