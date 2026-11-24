//! KAN-131: how long the flow lock is held for both rollup snapshots. Ignored
//! by default; run with
//! `cargo test --release --locked --test rollup_cost -- --ignored --nocapture`.
//! `ROLLUP_COST_SHAPE`, `ROLLUP_COST_K` and `ROLLUP_COST_N` together select a
//! single case and one run, so that a driver can interleave this binary with
//! one built from an older commit. `digest` identifies the packet and DNS
//! sequence.
//!
//! Shapes:
//! - `original`: the four rankings have disjoint leaders, so each table sends
//!   its worst case of 4N rows.
//! - `scan_zero`: every key gets one equal packet in slot order with strictly
//!   ascending timestamps. Each tick repeats that, then drains the rates with
//!   an untimed snapshot, so the timed one finds new traffic but zero rates.
//! - `scan_equal`: the same feed without the drain, so all rates are equal and
//!   not zero. Strict millisecond timestamps make each tick K ms long.
//! - `evicting`: K new keys every tick, so a full table replaces itself. The
//!   unbounded baseline keeps every key instead, so the two do unlike work.
//!
//! In the scan shapes all four rankings agree: the N most recent keys.
//!
//! No counting allocator here: it would slow code that allocates more. The
//! memory measurement is in `rollup_memory.rs`.
use std::collections::HashSet;
use std::hint::black_box;
use std::net::Ipv6Addr;
use std::sync::Mutex;
use std::time::Instant;

use capture_agent::dns_names::DEFAULT_MAX_OBSERVED_DNS_NAMES;
use capture_agent::flow::{ConversationSnapshot, EndpointSnapshot, FlowTable};
use capture_agent::l7::{DnsAnswer, L7Info};
use capture_agent::parse::{ParsedPacket, TransportProtocol};

// API-BEGIN: the only part that differs in the copy built against the old API.
use capture_agent::flow::RollupConfig;
use capture_agent::rollup::Bounds;

type Raw = (
    (Vec<EndpointSnapshot>, Bounds),
    (Vec<ConversationSnapshot>, Bounds),
);

fn new_table(k: usize, n: usize) -> FlowTable {
    FlowTable::new(vec![LOCAL.to_string()]).with_rollup_config(RollupConfig {
        max_endpoints: k,
        max_conversations: k,
        top_n: n,
    })
}

/// The bounded tables hold exactly K keys and send exactly the expected rows.
fn check(raw: Raw, e: &Expect) -> (Vec<EndpointSnapshot>, Vec<ConversationSnapshot>) {
    let ((endpoints, endpoint_bounds), (conversations, conversation_bounds)) = raw;
    for b in [&endpoint_bounds, &conversation_bounds] {
        assert_eq!((b.tracked, b.unkeyed), (e.k, 0));
        assert_eq!(b.evictions, (e.keys_seen - e.k) as u64);
    }
    match &e.sent {
        Some(sent) => {
            assert_eq!(endpoints.len(), sent.len());
            assert_eq!(conversations.len(), sent.len());
            assert!(endpoints.iter().all(|r| sent.contains(r.host.as_str())));
            assert!(conversations.iter().all(|r| sent.contains(r.remote_addr.as_str())));
            assert!(endpoints.iter().all(|r| r.observed_name.is_some()));
        }
        None => {
            assert!((e.n..=4 * e.n).contains(&endpoints.len()));
            assert_eq!(conversations.len(), endpoints.len());
        }
    }
    (endpoints, conversations)
}
// API-END

/// What one tick must produce: `keys_seen` distinct keys so far, and the exact
/// rows a bounded table sends, when the shape fixes them.
struct Expect<'a> {
    k: usize,
    n: usize,
    keys_seen: usize,
    sent: Option<HashSet<&'a str>>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Shape {
    Original,
    ScanZero,
    ScanEqual,
    Evicting,
}

impl Shape {
    fn name(self) -> &'static str {
        match self {
            Shape::Original => "original",
            Shape::ScanZero => "scan_zero",
            Shape::ScanEqual => "scan_equal",
            Shape::Evicting => "evicting",
        }
    }
    fn parse(name: &str) -> Shape {
        [Shape::Original, Shape::ScanZero, Shape::ScanEqual, Shape::Evicting]
            .into_iter()
            .find(|s| s.name() == name)
            .unwrap_or_else(|| panic!("unknown ROLLUP_COST_SHAPE {name}"))
    }
}

const LOCAL: &str = "2001:db8:1:2:a1b2:c3d4:e5f6:1234";
const TICKS: usize = 5;
const RUNS: usize = 5;
const BACKGROUND_PER_TICK: usize = 20_000;
/// Longer than the 60 s idle limit of a UDP flow.
const PAST_IDLE_MS: u64 = 61_000;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    /// Log-uniform in 60..1500.
    fn size(&mut self) -> u16 {
        let u = (self.next() >> 11) as f64 / (1u64 << 53) as f64;
        (60.0 * (1500.0f64 / 60.0).powf(u)) as u16
    }
}

/// Distinct for distinct `i`: the low 32 bits hold `i`.
fn remote(i: usize) -> String {
    let hi = 0x2600_0000_0000_0000 | (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 8;
    let lo = 0xabcd_ef01_0000_0000 | i as u64;
    Ipv6Addr::from((u128::from(hi) << 64) | u128::from(lo)).to_string()
}

fn packet(remote: &str, outbound: bool, total_len: u16) -> ParsedPacket {
    let (src, dst, sport, dport) = if outbound {
        (LOCAL, remote, 51_000, 443)
    } else {
        (remote, LOCAL, 443, 51_000)
    };
    ParsedPacket {
        src_mac: "aa:aa:aa:aa:aa:aa".into(),
        dst_mac: "bb:bb:bb:bb:bb:bb".into(),
        src_ip: src.into(),
        dst_ip: dst.into(),
        protocol: TransportProtocol::Udp,
        src_port: Some(sport),
        dst_port: Some(dport),
        tcp_flags: None,
        seq: None,
        ttl: 64,
        total_len,
        payload: vec![],
        header_bytes: vec![],
        ip_header_len: 40,
        transport_header_len: 8,
        ip_version: 6,
        ip_checksum: None,
        vlan_tag: None,
        ip_declared_payload_len: 0,
        ip_fragment: None,
    }
}

struct Feed {
    table: Mutex<FlowTable>,
    addrs: Vec<String>,
    rng: Rng,
    digest: u64,
    packets: u64,
}

impl Feed {
    fn mix(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.digest = (self.digest ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
        }
    }
    fn send(&mut self, i: usize, len: u16, now_ms: u64) {
        let outbound = self.rng.next() & 1 == 0;
        let p = packet(&self.addrs[i], outbound, len);
        self.mix(p.src_ip.as_bytes());
        self.mix(p.dst_ip.as_bytes());
        self.mix(&len.to_le_bytes());
        self.mix(&now_ms.to_le_bytes());
        self.packets += 1;
        let seen = self.table.get_mut().unwrap().observe(&p, &L7Info::None, now_ms);
        assert_eq!(seen.map(|r| r.is_outbound), Some(outbound));
        // Keeps the loading phase from holding one live flow per key.
        if self.packets.is_multiple_of(20_000) {
            self.drop_flows(now_ms);
        }
    }
    fn drop_flows(&mut self, now_ms: u64) {
        self.table.get_mut().unwrap().evict_stale(now_ms + PAST_IDLE_MS);
    }
    fn learn_name(&mut self, i: usize, now_ms: u64) {
        let name = format!("host-{i:08}.edge.cdn.example.net");
        self.mix(name.as_bytes());
        let answer = DnsAnswer {
            name: name.clone(),
            rtype: 28,
            ttl: 86_400,
            data: self.addrs[i].clone(),
            data_truncated: false,
        };
        self.table.get_mut().unwrap().learn_dns_response(&name, &[answer], now_ms);
    }
}

struct Sample {
    ms: f64,
    endpoints: usize,
    conversations: usize,
    named: usize,
}

/// Both snapshots in one lock hold, as in the emitter, with the rows kept past
/// it. Checked against `expect` outside the timed region.
fn timed(
    f: &Feed,
    shape: Shape,
    now: u64,
    expect: &Expect,
) -> Sample {
    let mut guard = f.table.lock().unwrap();
    let start = Instant::now();
    let endpoints = black_box(guard.endpoint_snapshot(black_box(now)));
    let conversations = black_box(guard.conversation_snapshot(black_box(now)));
    let elapsed = start.elapsed();
    drop(guard);
    let (endpoints, conversations) = check((endpoints, conversations), expect);
    let rates: Vec<f64> = endpoints
        .iter()
        .map(|r| r.rx_speed + r.tx_speed)
        .chain(conversations.iter().map(|r| r.rx_speed + r.tx_speed))
        .collect();
    match shape {
        Shape::ScanZero => assert!(rates.iter().all(|r| *r == 0.0)),
        Shape::ScanEqual => assert!(rates[0] > 0.0 && rates.iter().all(|r| *r == rates[0])),
        Shape::Original | Shape::Evicting => {
            assert!(rates[..endpoints.len()].iter().any(|r| *r > 0.0));
            assert!(rates[endpoints.len()..].iter().any(|r| *r > 0.0));
        }
    }
    Sample {
        ms: elapsed.as_secs_f64() * 1e3,
        endpoints: endpoints.len(),
        conversations: conversations.len(),
        named: endpoints.iter().filter(|r| r.observed_name.is_some()).count(),
    }
}

fn untimed(f: &Feed, now: u64) {
    let mut guard = f.table.lock().unwrap();
    black_box(guard.endpoint_snapshot(now));
    black_box(guard.conversation_snapshot(now));
}

/// One run: a new table, K keys loaded and their counters drained, one untimed
/// tick, then TICKS timed ones, each after its own traffic. Every tick's rows
/// are checked, the untimed one's included.
fn run(shape: Shape, k: usize, n: usize) -> (Vec<Sample>, u64, u64) {
    let keys = if shape == Shape::Evicting { k * (TICKS + 2) } else { k };
    let mut f = Feed {
        table: Mutex::new(new_table(k, n)),
        addrs: (0..keys).map(remote).collect(),
        rng: Rng(0x1234_5678_9abc_def1),
        digest: 0xcbf2_9ce4_8422_2325,
        packets: 0,
    };
    let mut samples = match shape {
        Shape::Original => run_original(&mut f, k, n),
        Shape::ScanZero | Shape::ScanEqual => run_scan(&mut f, shape, k, n),
        Shape::Evicting => run_evicting(&mut f, k, n),
    };
    samples.remove(0);
    (samples, f.digest, f.packets)
}

fn run_original(f: &mut Feed, k: usize, n: usize) -> Vec<Sample> {
    let sets = 2 + 2 * (TICKS + 1);
    assert!(k > sets * n + 1_000, "not enough keys for disjoint leaders");
    // A shuffle, so a group's members are scattered over the table's slots.
    let mut order: Vec<usize> = (0..k).collect();
    for i in (1..k).rev() {
        order.swap(i, f.rng.below(i + 1));
    }
    // Byte leaders and packet leaders persist; rate and recent leaders are a
    // new group on every tick.
    let group = |g: usize| &order[g * n..(g + 1) * n];
    let background = &order[sets * n..];

    for i in 0..k {
        let len = f.rng.size();
        f.send(i, len, 1 + i as u64 / 10);
    }
    let mut now = 1 + k as u64 / 10;
    for &i in group(0) {
        for _ in 0..40 {
            f.send(i, 65_000, now);
        }
    }
    for &i in group(1) {
        for _ in 0..300 {
            f.send(i, 60, now);
        }
    }
    // Leaders first, then others up to the production capacity.
    for &i in order.iter().take(DEFAULT_MAX_OBSERVED_DNS_NAMES.min(k)) {
        f.learn_name(i, now);
    }
    f.drop_flows(now);
    // Drains the loading traffic: otherwise the byte leaders would also lead
    // the first tick's rate.
    untimed(f, now);

    let mut samples = Vec::new();
    for tick in 0..=TICKS {
        for j in 0..BACKGROUND_PER_TICK {
            let i = background[f.rng.below(background.len())];
            let len = f.rng.size();
            f.send(i, len, now + 1 + (j * 800 / BACKGROUND_PER_TICK) as u64);
        }
        let (rate, recent) = (group(2 + 2 * tick), group(3 + 2 * tick));
        for &i in group(0) {
            f.send(i, 1_000, now + 810);
        }
        for &i in group(1) {
            for _ in 0..3 {
                f.send(i, 60, now + 820);
            }
        }
        for &i in rate {
            f.send(i, 60_000, now + 830);
        }
        for (j, &i) in recent.iter().enumerate() {
            f.send(i, 60, now + 900 + (j * 99 / n) as u64);
        }
        now += 1_000;
        f.drop_flows(now);

        let expect = Expect {
            k,
            n,
            keys_seen: k,
            sent: Some(
                [group(0), group(1), rate, recent]
                    .iter()
                    .flat_map(|g| g.iter().map(|&i| f.addrs[i].as_str()))
                    .collect(),
            ),
        };
        assert_eq!(expect.sent.as_ref().map(HashSet::len), Some(4 * n));
        samples.push(timed(f, Shape::Original, now, &expect));
    }
    samples
}

fn run_scan(f: &mut Feed, shape: Shape, k: usize, n: usize) -> Vec<Sample> {
    let mut now = 0;
    // Insertion order is slot order, so feeding 0..K feeds in slot order.
    let scan = |f: &mut Feed, now: u64| {
        for i in 0..k {
            f.send(i, 100, now + 1 + i as u64);
        }
        now + 1 + k as u64
    };
    now = scan(f, now);
    // The newest keys first, so every row sent has a name.
    for i in (0..k).rev().take(DEFAULT_MAX_OBSERVED_DNS_NAMES) {
        f.learn_name(i, now);
    }
    f.drop_flows(now);
    untimed(f, now);

    let mut samples = Vec::new();
    for _ in 0..=TICKS {
        now = scan(f, now);
        f.drop_flows(now);
        if shape == Shape::ScanZero {
            untimed(f, now);
            now += 1_000;
        }
        let expect = Expect {
            k,
            n,
            keys_seen: k,
            sent: Some(f.addrs[k - n..].iter().map(String::as_str).collect()),
        };
        assert_eq!(expect.sent.as_ref().map(HashSet::len), Some(n));
        samples.push(timed(f, shape, now, &expect));
    }
    samples
}

fn run_evicting(f: &mut Feed, k: usize, n: usize) -> Vec<Sample> {
    let mut now = 0;
    let mut seen = 0;
    let mut fill = |f: &mut Feed, now: u64| {
        for j in 0..k {
            let len = f.rng.size();
            f.send(seen + j, len, now + 1 + (j * 900 / k) as u64);
        }
        for j in (0..k).rev().take(DEFAULT_MAX_OBSERVED_DNS_NAMES) {
            f.learn_name(seen + j, now + 950);
        }
        seen += k;
        f.drop_flows(now + 1_000);
        (now + 1_000, seen)
    };
    (now, _) = fill(f, now);
    untimed(f, now);

    let mut samples = Vec::new();
    for _ in 0..=TICKS {
        let keys_seen;
        (now, keys_seen) = fill(f, now);
        let expect = Expect { k, n, keys_seen, sent: None };
        samples.push(timed(f, Shape::Evicting, now, &expect));
    }
    samples
}

fn median(values: impl Iterator<Item = f64>) -> f64 {
    let mut v: Vec<f64> = values.collect();
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn join<T: std::fmt::Display>(values: impl Iterator<Item = T>) -> String {
    values.map(|v| v.to_string()).collect::<Vec<_>>().join(" ")
}

fn report(shape: Shape, k: usize, n: usize, runs: usize) {
    let label = format!("shape={} K={k} N={n}", shape.name());
    let mut medians = Vec::new();
    for _ in 0..runs {
        let (samples, digest, packets) = run(shape, k, n);
        assert_eq!(samples.len(), TICKS);
        let m = median(samples.iter().map(|s| s.ms));
        println!(
            "{label} run_median_ms={m:.3} ticks_ms=[{}] endpoint_rows=[{}] \
             conversation_rows=[{}] named=[{}] packets={packets} digest={digest:016x}",
            join(samples.iter().map(|s| format!("{:.3}", s.ms))),
            join(samples.iter().map(|s| s.endpoints)),
            join(samples.iter().map(|s| s.conversations)),
            join(samples.iter().map(|s| s.named)),
        );
        medians.push(m);
    }
    if runs > 1 {
        println!("{label} median_of_{runs}_runs_ms={:.3}", median(medians.into_iter()));
    }
}

#[test]
#[ignore = "measurement, not a check; prints the lock-hold time of both snapshots"]
fn rollup_cost() {
    let var = |name: &str| std::env::var(name).ok();
    let one = (var("ROLLUP_COST_SHAPE"), var("ROLLUP_COST_K"), var("ROLLUP_COST_N"));
    if let (Some(shape), Some(k), Some(n)) = one {
        report(Shape::parse(&shape), k.parse().unwrap(), n.parse().unwrap(), 1);
        return;
    }
    for k in [10_000, 50_000, 100_000, 500_000] {
        report(Shape::Original, k, 200, RUNS);
    }
    report(Shape::Original, 50_000, 1_000, RUNS);
    for shape in [Shape::ScanZero, Shape::ScanEqual] {
        for n in [200, 1_000] {
            report(shape, 50_000, n, RUNS);
        }
    }
    report(Shape::Evicting, 50_000, 200, RUNS);
}
