//! KAN-131 Task 4: the rollup rank fixture shared with the browser
//! (`testdata/rollup-rank.jsonl`), and the size of the largest rollup line.
//!
//! The reference model here is a full sort of the generated rows. It never
//! touches `RollupTable`. Rows are built by the library conversion the
//! emitter calls, `EndpointJson::from_snapshot` and
//! `ConversationJson::from_snapshot`.

use capture_agent::flow::{ConversationSnapshot, EndpointSnapshot};
use capture_agent::rollup::{Bounds, Traffic};
use capture_agent::wire::{encode_event, AgentEvent, ConversationJson, EndpointJson};
use serde_json::{json, Value};
use std::cmp::Ordering;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/rollup-rank.jsonl");

/// What one generated row ranks by. Everything else follows from the id.
#[derive(Clone)]
struct Gen {
    id: u64,
    key: String,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_speed: f64,
    tx_speed: f64,
    last_seen_ms: u64,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64: fixed seed, so the fixture is reproducible.
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const SPEEDS: [f64; 5] = [0.0, 100.0, 250.5, 350.5, 1024.0];

/// Few distinct values everywhere, so ties are the common case. Ids run in
/// insertion order; `last_seen_ms` climbs and then steps backward, as a
/// replay with a timestamp reset does.
fn generate(rows: u64, seed: u64, conversation: bool) -> Vec<Gen> {
    let mut rng = Rng(seed);
    (1..=rows)
        .map(|id| {
            let i = id - 1;
            let remote = format!("10.{}.{}.{}", i / 65_536, (i / 256) % 256, i % 256);
            let key = if conversation {
                format!("192.168.1.{}|{remote}", 10 + i % 3)
            } else {
                remote
            };
            let last_seen_ms = if id <= rows / 2 {
                1_000 + 10 * rng.pick(6)
            } else {
                500 + 10 * rng.pick(6)
            };
            Gen {
                id,
                key,
                rx_bytes: 1_000 * rng.pick(4),
                tx_bytes: 1_000 * rng.pick(4),
                rx_packets: rng.pick(3),
                tx_packets: rng.pick(3),
                rx_speed: SPEEDS[rng.pick(5) as usize],
                tx_speed: SPEEDS[rng.pick(5) as usize],
                last_seen_ms,
            }
        })
        .collect()
}

/// Rank by one value, descending; then `last_seen_ms` descending; then id
/// ascending.
fn top_n(rows: &[Gen], n: usize, rank: impl Fn(&Gen, &Gen) -> Ordering) -> Vec<Gen> {
    let mut sorted = rows.to_vec();
    sorted.sort_by(|a, b| {
        rank(b, a)
            .then(b.last_seen_ms.cmp(&a.last_seen_ms))
            .then(a.id.cmp(&b.id))
    });
    sorted.truncate(n);
    sorted
}

struct Model {
    expected: [Vec<Gen>; 4],
}

fn rank_all(rows: &[Gen], n: usize) -> Model {
    let bytes = |a: &Gen, b: &Gen| (a.rx_bytes as u128 + a.tx_bytes as u128).cmp(&(b.rx_bytes as u128 + b.tx_bytes as u128));
    let packets = |a: &Gen, b: &Gen| (a.rx_packets as u128 + a.tx_packets as u128).cmp(&(b.rx_packets as u128 + b.tx_packets as u128));
    let rate = |a: &Gen, b: &Gen| (a.rx_speed + a.tx_speed).total_cmp(&(b.rx_speed + b.tx_speed));
    let recent = |a: &Gen, b: &Gen| a.last_seen_ms.cmp(&b.last_seen_ms);
    Model {
        expected: [
            top_n(rows, n, bytes),
            top_n(rows, n, packets),
            top_n(rows, n, rate),
            top_n(rows, n, recent),
        ],
    }
}

fn bounds(tracked: usize) -> Bounds {
    Bounds {
        cap: 50_000,
        top_n: 200,
        tracked,
        evictions: 0,
        unkeyed: 0,
        since_ms: Some(0),
        horizon_ms: None,
        totals: Traffic { rx_bytes: 1, tx_bytes: 1, rx_packets: 1, tx_packets: 1 },
        evicted: Traffic::default(),
    }
}

fn endpoint_snapshot(g: &Gen) -> EndpointSnapshot {
    EndpointSnapshot {
        host: g.key.clone(),
        rx_bytes_total: g.rx_bytes,
        tx_bytes_total: g.tx_bytes,
        rx_packets_total: g.rx_packets,
        tx_packets_total: g.tx_packets,
        rx_speed: g.rx_speed,
        tx_speed: g.tx_speed,
        flow_count: 1,
        first_seen_ms: 0,
        last_seen_ms: g.last_seen_ms,
        ja3_label: None,
        history_complete: true,
        observed_name: None,
    }
}

fn conversation_snapshot(g: &Gen) -> ConversationSnapshot {
    let (local, remote) = g.key.split_once('|').unwrap();
    ConversationSnapshot {
        local_addr: local.to_string(),
        remote_addr: remote.to_string(),
        rx_bytes_total: g.rx_bytes,
        tx_bytes_total: g.tx_bytes,
        rx_packets_total: g.rx_packets,
        tx_packets_total: g.tx_packets,
        rx_speed: g.rx_speed,
        tx_speed: g.tx_speed,
        flow_count: 1,
        first_seen_ms: 0,
        last_seen_ms: g.last_seen_ms,
        duration_ms: g.last_seen_ms,
        ja3_label: None,
        history_complete: true,
    }
}

/// The union of the four top-N lists, in id order, as one encoded event.
fn event_for(rows: &[Gen], model: &Model, conversation: bool) -> Value {
    let mut union: Vec<&Gen> = model.expected.iter().flatten().collect();
    union.sort_by_key(|g| g.id);
    union.dedup_by_key(|g| g.id);
    let bounds = bounds(rows.len()).into();
    let event = if conversation {
        AgentEvent::ConversationRollup {
            conversations: union
                .iter()
                .map(|g| ConversationJson::from_snapshot(conversation_snapshot(g), "unknown".into(), 0))
                .collect(),
            bounds,
        }
    } else {
        AgentEvent::EndpointRollup {
            endpoints: union
                .iter()
                .map(|g| EndpointJson::from_snapshot(endpoint_snapshot(g), "unknown".into(), 0))
                .collect(),
            bounds,
        }
    };
    serde_json::from_str(encode_event(&event).trim_end()).unwrap()
}

fn keys(list: &[Gen]) -> Vec<&str> {
    list.iter().map(|g| g.key.as_str()).collect()
}

fn generated_fixture() -> String {
    let mut out = String::new();
    for (conversation, seed) in [(false, 0x9e37_79b9_7f4a_7c15u64), (true, 0xd1b5_4a32_d192_ed03u64)] {
        for (n, rows) in [(3usize, 40u64), (200, 600)] {
            let generated = generate(rows, seed ^ n as u64, conversation);
            let model = rank_all(&generated, n);
            let line = json!({
                "event": event_for(&generated, &model, conversation),
                "topN": n,
                "expected": {
                    "bytes": keys(&model.expected[0]),
                    "packets": keys(&model.expected[1]),
                    "rate": keys(&model.expected[2]),
                    "recent": keys(&model.expected[3]),
                },
            });
            out.push_str(&serde_json::to_string(&line).unwrap());
            out.push('\n');
        }
    }
    out
}

/// The browser's view: rank the rows on the wire, ties by array position.
fn rank_from_wire(rows: &[Value], n: usize, key: impl Fn(&Value) -> String, value: impl Fn(&Value) -> f64) -> Vec<String> {
    let mut indexed: Vec<(usize, &Value)> = rows.iter().enumerate().collect();
    indexed.sort_by(|(ia, a), (ib, b)| {
        value(b)
            .total_cmp(&value(a))
            .then(b["lastSeenMs"].as_u64().cmp(&a["lastSeenMs"].as_u64()))
            .then(ia.cmp(ib))
    });
    indexed.into_iter().take(n).map(|(_, row)| key(row)).collect()
}

#[test]
fn rank_fixture_matches() {
    let generated = generated_fixture();
    if std::env::var_os("UPDATE_ROLLUP_FIXTURE").is_some() {
        std::fs::write(FIXTURE, &generated).unwrap();
    }
    let on_disk = std::fs::read_to_string(FIXTURE).expect("testdata/rollup-rank.jsonl is missing; run with UPDATE_ROLLUP_FIXTURE=1");
    assert_eq!(on_disk, generated, "fixture is stale; regenerate with UPDATE_ROLLUP_FIXTURE=1");

    let lines: Vec<Value> = on_disk.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 4);
    for line in &lines {
        let event = &line["event"];
        let conversation = event["type"] == "conversation_rollup";
        let rows = event[if conversation { "conversations" } else { "endpoints" }].as_array().unwrap();
        let n = line["topN"].as_u64().unwrap() as usize;
        let key = |row: &Value| {
            if conversation {
                format!("{}|{}", row["localAddr"].as_str().unwrap(), row["remoteAddr"].as_str().unwrap())
            } else {
                row["host"].as_str().unwrap().to_string()
            }
        };
        let num = |row: &Value, f: &str| row[f].as_u64().unwrap() as f64;
        let ranked = [
            ("bytes", rank_from_wire(rows, n, key, |r| num(r, "rxBytesTotal") + num(r, "txBytesTotal"))),
            ("packets", rank_from_wire(rows, n, key, |r| num(r, "rxPacketsTotal") + num(r, "txPacketsTotal"))),
            ("rate", rank_from_wire(rows, n, key, |r| r["rxSpeed"].as_f64().unwrap() + r["txSpeed"].as_f64().unwrap())),
            ("recent", rank_from_wire(rows, n, key, |r| r["lastSeenMs"].as_u64().unwrap() as f64)),
        ];
        for (name, got) in ranked {
            let want: Vec<String> = line["expected"][name].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
            assert_eq!(got, want, "{name} at N={n}");
        }
        // Ties were really exercised: some value is shared by many rows.
        let distinct_bytes: std::collections::HashSet<u64> = rows
            .iter()
            .map(|r| r["rxBytesTotal"].as_u64().unwrap() + r["txBytesTotal"].as_u64().unwrap())
            .collect();
        assert!(distinct_bytes.len() <= 7 && rows.len() > distinct_bytes.len(), "fixture must be tie-heavy");
    }
}

/// One MiB-scale bound check. The longest rollup line the agent can write:
/// N=1,000 so up to 4,000 rows, IPv6 addresses (the longest textual form is
/// the 45-byte IPv4-mapped one), 253-byte observed names, a 64-byte JA3
/// label (the label table is empty today, so this is a stand-in), u64-max
/// counters and 24-byte f64 speeds. Process names stay short: they are not
/// bounded by this work.
#[test]
fn worst_case_line_length() {
    const LIMIT: usize = 4 * 1024 * 1024;
    const MAPPED_V6: &str = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255";
    let label: &'static str = Box::leak("L".repeat(64).into_boxed_str());
    let name = "a".repeat(253);
    let rows = 4_000u64;
    let bounds = Bounds {
        cap: 500_000,
        top_n: 1_000,
        tracked: 500_000,
        evictions: u64::MAX,
        unkeyed: u64::MAX,
        since_ms: Some(u64::MAX),
        horizon_ms: Some(u64::MAX),
        totals: Traffic { rx_bytes: u64::MAX, tx_bytes: u64::MAX, rx_packets: u64::MAX, tx_packets: u64::MAX },
        evicted: Traffic { rx_bytes: u64::MAX, tx_bytes: u64::MAX, rx_packets: u64::MAX, tx_packets: u64::MAX },
    };
    let endpoints: Vec<EndpointJson> = (0..rows)
        .map(|_| {
            EndpointJson::from_snapshot(
                EndpointSnapshot {
                    host: MAPPED_V6.to_string(),
                    rx_bytes_total: u64::MAX,
                    tx_bytes_total: u64::MAX,
                    rx_packets_total: u64::MAX,
                    tx_packets_total: u64::MAX,
                    rx_speed: f64::MAX,
                    tx_speed: f64::MAX,
                    flow_count: u64::MAX,
                    first_seen_ms: u64::MAX,
                    last_seen_ms: u64::MAX,
                    ja3_label: Some(label),
                    history_complete: false,
                    observed_name: Some(name.clone()),
                },
                "unknown".to_string(),
                u32::MAX,
            )
        })
        .collect();
    let conversations: Vec<ConversationJson> = (0..rows)
        .map(|_| {
            ConversationJson::from_snapshot(
                ConversationSnapshot {
                    local_addr: MAPPED_V6.to_string(),
                    remote_addr: MAPPED_V6.to_string(),
                    rx_bytes_total: u64::MAX,
                    tx_bytes_total: u64::MAX,
                    rx_packets_total: u64::MAX,
                    tx_packets_total: u64::MAX,
                    rx_speed: f64::MAX,
                    tx_speed: f64::MAX,
                    flow_count: u64::MAX,
                    first_seen_ms: u64::MAX,
                    last_seen_ms: u64::MAX,
                    duration_ms: u64::MAX,
                    ja3_label: Some(label),
                    history_complete: false,
                },
                "unknown".to_string(),
                u32::MAX,
            )
        })
        .collect();
    let endpoint_line = encode_event(&AgentEvent::EndpointRollup { endpoints, bounds: bounds.clone().into() });
    let conversation_line = encode_event(&AgentEvent::ConversationRollup { conversations, bounds: bounds.into() });
    // `encode_event` includes the trailing newline the wire sends.
    println!("worst-case endpoint_rollup line: {} bytes", endpoint_line.len());
    println!("worst-case conversation_rollup line: {} bytes", conversation_line.len());
    assert!(endpoint_line.len() < LIMIT, "endpoint_rollup is {} bytes", endpoint_line.len());
    assert!(conversation_line.len() < LIMIT, "conversation_rollup is {} bytes", conversation_line.len());
}
