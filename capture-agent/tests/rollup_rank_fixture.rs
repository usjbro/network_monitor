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
    /// Inserted before the first eviction.
    history_complete: bool,
    /// Evicted from the table: counted in `bounds.evicted`, never sent.
    evicted: bool,
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

/// `tight` builds a table where the cut at N falls inside a tie for every
/// ranking: each of bytes, packets and rate has one champion row, most other
/// rows share the next level, and `last_seen_ms` has only a few values. A
/// ranking's top N is then its champion plus the first rows of the shared
/// level, and the rows that the other rankings add share that level too.
///
/// The table holds `rows` keys at its cap. Ids 1..=rows were inserted before
/// any eviction (history complete); every fourth of them was later evicted
/// and replaced by ids rows+1..=rows+rows/4, which are not complete. So
/// `evictions` is rows/4. `last_seen_ms` climbs and then steps backward, as a
/// replay with a timestamp reset does.
fn generate(rows: u64, seed: u64, conversation: bool, tight: bool) -> Vec<Gen> {
    let mut rng = Rng(seed);
    let speeds: &[f64] = &[0.0, 100.0, 250.5, 350.5, 1024.0];
    let later = rows / 4;
    (1..=rows + later)
        .map(|id| {
            let i = id - 1;
            let remote = format!("10.{}.{}.{}", i / 65_536, (i / 256) % 256, i % 256);
            let key = if conversation {
                format!("192.168.1.{}|{remote}", 10 + i % 3)
            } else {
                remote
            };
            let mut row = Gen {
                id,
                key,
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_speed: 0.0,
                tx_speed: 0.0,
                last_seen_ms: 0,
                history_complete: id <= rows,
                evicted: id <= rows && id % 4 == 0,
            };
            if tight {
                let shared = |rng: &mut Rng| rng.pick(5) < 3;
                // Champions are late ids, so they are never among the first
                // rows of a shared level. Two rows are newest; the second
                // half steps back in time.
                row.rx_bytes = if id == rows + 3 { 2_000 } else if shared(&mut rng) { 1_000 } else { 0 };
                row.rx_packets = if id == rows + 5 { 2 } else if shared(&mut rng) { 1 } else { 0 };
                row.rx_speed = if id == rows + 7 { 200.0 } else if shared(&mut rng) { 100.0 } else { 0.0 };
                row.last_seen_ms = if id == rows / 2 + 2 || id == rows / 2 + 3 {
                    1_010
                } else if id <= rows / 2 {
                    1_000
                } else {
                    990 + 10 * rng.pick(2)
                };
            } else {
                row.rx_bytes = 1_000 * rng.pick(4);
                row.tx_bytes = 1_000 * rng.pick(4);
                row.rx_packets = rng.pick(3);
                row.tx_packets = rng.pick(3);
                row.rx_speed = speeds[rng.pick(5) as usize];
                row.tx_speed = speeds[rng.pick(5) as usize];
                row.last_seen_ms = if id <= rows / 2 {
                    1_000 + 10 * rng.pick(3)
                } else {
                    500 + 10 * rng.pick(3)
                };
            }
            row
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

/// Bounds consistent with the generated rows: `totals - evicted` is the sum
/// over the tracked rows, `tracked` is their count, and `horizonMs` is the
/// latest `last_seen_ms` among the evicted.
fn bounds(all: &[Gen], n: usize) -> Bounds {
    fn sum<'a>(rows: impl Iterator<Item = &'a Gen>) -> Traffic {
        rows.fold(Traffic::default(), |t, g| Traffic {
            rx_bytes: t.rx_bytes + g.rx_bytes,
            tx_bytes: t.tx_bytes + g.tx_bytes,
            rx_packets: t.rx_packets + g.rx_packets,
            tx_packets: t.tx_packets + g.tx_packets,
        })
    }
    let tracked: Vec<&Gen> = all.iter().filter(|g| !g.evicted).collect();
    let evicted = sum(all.iter().filter(|g| g.evicted));
    let held = sum(tracked.iter().copied());
    Bounds {
        cap: tracked.len(),
        top_n: n,
        tracked: tracked.len(),
        evictions: all.iter().filter(|g| g.evicted).count() as u64,
        unkeyed: 0,
        since_ms: Some(0),
        horizon_ms: all.iter().filter(|g| g.evicted).map(|g| g.last_seen_ms).max(),
        totals: Traffic {
            rx_bytes: held.rx_bytes + evicted.rx_bytes,
            tx_bytes: held.tx_bytes + evicted.tx_bytes,
            rx_packets: held.rx_packets + evicted.rx_packets,
            tx_packets: held.tx_packets + evicted.tx_packets,
        },
        evicted,
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
        history_complete: g.history_complete,
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
        history_complete: g.history_complete,
    }
}

/// The union of the four top-N lists, in id order, as one encoded event.
fn event_for(all: &[Gen], n: usize, model: &Model, conversation: bool) -> Value {
    let mut union: Vec<&Gen> = model.expected.iter().flatten().collect();
    union.sort_by_key(|g| g.id);
    union.dedup_by_key(|g| g.id);
    let bounds = bounds(all, n).into();
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
    // Chosen by scanning seeds until the N=3 lines tie at the cut in every
    // ranking and on `lastSeenMs` for bytes, packets and rate, and the
    // lastSeenMs and id tie-breaks change which rows are in the top 3. The
    // test below asserts the ties; the break-it checks cover the rest, so a generator change cannot lose it silently.
    let seed = 0xdaa6_6d2c_7ddf_743fu64;
    for conversation in [false, true] {
        for (n, rows) in [(3usize, 40u64), (200, 600)] {
            let all = generate(rows, if n == 3 { seed ^ 3 } else { seed ^ 200 }, conversation, n == 3);
            let tracked: Vec<Gen> = all.iter().filter(|g| !g.evicted).cloned().collect();
            let model = rank_all(&tracked, n);
            let line = json!({
                "event": event_for(&all, n, &model, conversation),
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

/// The browser's view: rank the rows on the wire by value, then
/// `lastSeenMs`, then array position. Returns row indices, best first.
fn rank_from_wire(rows: &[Value], value: impl Fn(&Value) -> f64) -> Vec<usize> {
    let mut indexed: Vec<usize> = (0..rows.len()).collect();
    indexed.sort_by(|&ia, &ib| {
        let (a, b) = (&rows[ia], &rows[ib]);
        value(b)
            .total_cmp(&value(a))
            .then(b["lastSeenMs"].as_u64().cmp(&a["lastSeenMs"].as_u64()))
            .then(ia.cmp(&ib))
    });
    indexed
}

#[test]
fn rank_fixture_matches() {
    let generated = generated_fixture();
    if std::env::var("UPDATE_ROLLUP_FIXTURE").as_deref() == Ok("1") {
        std::fs::write(FIXTURE, &generated).unwrap();
    }
    let on_disk = std::fs::read_to_string(FIXTURE).expect("testdata/rollup-rank.jsonl is missing; run with UPDATE_ROLLUP_FIXTURE=1");
    assert_eq!(on_disk, generated, "fixture is stale; regenerate with UPDATE_ROLLUP_FIXTURE=1");

    let lines: Vec<Value> = on_disk.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 4);
    let mut failures: Vec<String> = Vec::new();
    // Per event kind and ranking: some line ties on lastSeenMs at the cut.
    let mut last_seen_ties: std::collections::HashSet<(bool, &str)> = std::collections::HashSet::new();
    for (index, line) in lines.iter().enumerate() {
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
        type Rank<'a> = (&'static str, Box<dyn Fn(&Value) -> f64 + 'a>);
        let rankings: [Rank; 4] = [
            ("bytes", Box::new(|r| num(r, "rxBytesTotal") + num(r, "txBytesTotal"))),
            ("packets", Box::new(|r| num(r, "rxPacketsTotal") + num(r, "txPacketsTotal"))),
            ("rate", Box::new(|r| r["rxSpeed"].as_f64().unwrap() + r["txSpeed"].as_f64().unwrap())),
            ("recent", Box::new(|r| num(r, "lastSeenMs"))),
        ];
        assert!(rows.len() > n && rows.len() <= 4 * n, "line {index}: {} rows at N={n}", rows.len());
        for (name, value) in &rankings {
            let order = rank_from_wire(rows, value);
            let got: Vec<String> = order.iter().take(n).map(|&i| key(&rows[i])).collect();
            let want: Vec<String> = line["expected"][*name].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
            if got != want {
                failures.push(format!("line {index} ({}, N={n}): {name} ranking differs from expected", event["type"]));
            }
            // The cut falls inside a tie, so the tie-break decides who is in.
            let (last, next) = (&rows[order[n - 1]], &rows[order[n]]);
            if value(last) != value(next) {
                failures.push(format!("line {index} ({}, N={n}): {name} does not tie across the cut", event["type"]));
            } else if last["lastSeenMs"] == next["lastSeenMs"] {
                last_seen_ties.insert((conversation, name));
            }
        }
    }
    for conversation in [false, true] {
        for name in ["bytes", "packets", "rate"] {
            if !last_seen_ties.contains(&(conversation, name)) {
                failures.push(format!("no line ties {name} on lastSeenMs too (conversation={conversation})"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // Rows that are not history-complete are present, with evictions to match.
    let incomplete = lines.iter().filter(|l| {
        let e = &l["event"];
        e[if e["type"] == "conversation_rollup" { "conversations" } else { "endpoints" }]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["historyComplete"] == false)
    });
    assert_eq!(incomplete.count(), 4, "every line carries a historyComplete:false row");
    assert!(lines.iter().all(|l| l["event"]["bounds"]["evictions"].as_u64().unwrap() > 0));
}

/// Size of a very large rollup line: N=1,000 so 4,000 rows, IPv6 addresses
/// (45 bytes at most, the IPv4-mapped form), 253-byte observed names, a
/// 64-byte JA3 label (the label table is empty today, so this is a
/// stand-in), u64-max counters and f64::MAX speeds. The process name is 9
/// backslashes, which JSON escapes to 18 bytes. The 9-byte length comes from
/// `lsof`'s default COMMAND truncation (our parser takes that field as is),
/// not from any limit in this code, so a different lister could send more.
#[test]
fn worst_case_line_length() {
    const LIMIT: usize = 4 * 1024 * 1024;
    const MAPPED_V6: &str = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255";
    let label: &'static str = Box::leak("L".repeat(64).into_boxed_str());
    const PROCESS: &str = "\\\\\\\\\\\\\\\\\\";
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
                PROCESS.to_string(),
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
                PROCESS.to_string(),
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
