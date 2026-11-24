//! KAN-131: a bounded, exact-LRU table of per-key traffic rollups. It holds at
//! most `cap` keys. Every recorded packet moves its key to the front of the
//! recency list; inserting a new key at the cap evicts the tail and folds its
//! traffic into `evicted`, so `totals - evicted` always equals the sum over the
//! tracked keys. Recency is arrival order, never `last_seen_ms`, so equal or
//! backward replay timestamps cannot make eviction ambiguous.
//!
//! Entries live in a slab (`Vec`) with `u32` links; an evicted slot is reused
//! for the new key, so the slab never exceeds `cap` and a cap reserves nothing
//! up front. The index keeps std's randomly keyed hasher because remote
//! addresses are attacker-chosen. A key that returns after eviction starts from
//! zero: nothing is restored or estimated.
use std::cmp::Reverse;
use std::collections::HashMap;
use std::hash::Hash;

pub const DEFAULT_MAX_ENDPOINTS: usize = 50_000;
pub const DEFAULT_MAX_CONVERSATIONS: usize = 50_000;
pub const MAX_ROLLUP_CAP: usize = 500_000;
pub const DEFAULT_ROLLUP_TOP_N: usize = 200;
pub const MAX_ROLLUP_TOP_N: usize = 1_000;

const NIL: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Traffic {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl Traffic {
    fn add(&mut self, other: &Traffic) {
        self.rx_bytes = self.rx_bytes.saturating_add(other.rx_bytes);
        self.tx_bytes = self.tx_bytes.saturating_add(other.tx_bytes);
        self.rx_packets = self.rx_packets.saturating_add(other.rx_packets);
        self.tx_packets = self.tx_packets.saturating_add(other.tx_packets);
    }

    fn bytes(&self) -> u64 {
        self.rx_bytes.saturating_add(self.tx_bytes)
    }

    fn packets(&self) -> u64 {
        self.rx_packets.saturating_add(self.tx_packets)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounds {
    pub cap: usize,
    pub top_n: usize,
    pub tracked: usize,
    pub evictions: u64,
    pub unkeyed: u64,
    pub since_ms: Option<u64>,
    pub horizon_ms: Option<u64>,
    pub totals: Traffic,
    pub evicted: Traffic,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RollupRow<K> {
    pub id: u64,
    pub key: K,
    pub total: Traffic,
    pub rx_speed: f64,
    pub tx_speed: f64,
    pub flow_count: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub ja3_label: Option<&'static str>,
    pub history_complete: bool,
}

struct Entry<K> {
    key: K,
    id: u64,
    prev: u32,
    next: u32,
    total: Traffic,
    rx_bytes_this_tick: u64,
    tx_bytes_this_tick: u64,
    flow_count: u64,
    first_seen_ms: u64,
    last_seen_ms: u64,
    ja3_label: Option<&'static str>,
    history_complete: bool,
}

pub struct RollupTable<K> {
    cap: usize,
    top_n: usize,
    entries: Vec<Entry<K>>,
    index: HashMap<K, u32>,
    /// Most recently used slot.
    head: u32,
    /// Least recently used slot.
    tail: u32,
    next_id: u64,
    evictions: u64,
    unkeyed: u64,
    since_ms: Option<u64>,
    horizon_ms: Option<u64>,
    totals: Traffic,
    evicted: Traffic,
}

impl<K: Copy + Eq + Hash> RollupTable<K> {
    pub fn new(cap: usize, top_n: usize) -> Self {
        let cap = cap.clamp(1, MAX_ROLLUP_CAP);
        Self {
            cap,
            top_n: top_n.max(1),
            entries: Vec::new(),
            index: HashMap::new(),
            head: NIL,
            tail: NIL,
            next_id: 1,
            evictions: 0,
            unkeyed: 0,
            since_ms: None,
            horizon_ms: None,
            totals: Traffic::default(),
            evicted: Traffic::default(),
        }
    }

    /// Returns the entry's id. Counts a flow when it differs from `last_counted`.
    pub fn record(
        &mut self,
        key: K,
        is_outbound: bool,
        bytes: u64,
        now_ms: u64,
        last_counted: u64,
    ) -> u64 {
        self.since_ms.get_or_insert(now_ms);
        let slot = match self.index.get(&key) {
            Some(&slot) => {
                self.unlink(slot);
                self.push_front(slot);
                slot
            }
            None => self.insert(key, now_ms),
        };
        let delta = if is_outbound {
            Traffic {
                tx_bytes: bytes,
                tx_packets: 1,
                ..Traffic::default()
            }
        } else {
            Traffic {
                rx_bytes: bytes,
                rx_packets: 1,
                ..Traffic::default()
            }
        };
        self.totals.add(&delta);
        let e = &mut self.entries[slot as usize];
        e.total.add(&delta);
        if is_outbound {
            e.tx_bytes_this_tick = e.tx_bytes_this_tick.saturating_add(bytes);
        } else {
            e.rx_bytes_this_tick = e.rx_bytes_this_tick.saturating_add(bytes);
        }
        e.last_seen_ms = now_ms;
        if e.id != last_counted {
            e.flow_count = e.flow_count.saturating_add(1);
        }
        e.id
    }

    /// A packet whose address did not parse: counted, in no row, in no total.
    pub fn record_unkeyed(&mut self, now_ms: u64) {
        self.since_ms.get_or_insert(now_ms);
        self.unkeyed = self.unkeyed.saturating_add(1);
    }

    pub fn set_ja3_label(&mut self, key: &K, label: &'static str) {
        if let Some(&slot) = self.index.get(key) {
            self.entries[slot as usize].ja3_label = Some(label);
        }
    }

    /// The union of the four top-N lists in id order; drains the tick counters
    /// of every entry. One pass over the table: O(K + N log N) in any order.
    pub fn snapshot(&mut self, elapsed_s: f64) -> Vec<RollupRow<K>> {
        let n = self.top_n.min(self.entries.len());
        if n == 0 {
            return Vec::new();
        }
        let buffer = n.saturating_mul(2).min(self.entries.len());
        let mut by_bytes = TopN::new(n, buffer);
        let mut by_packets = TopN::new(n, buffer);
        let mut by_rate = TopN::new(n, buffer);
        let mut by_recency = TopN::new(n, buffer);
        for (slot, e) in self.entries.iter_mut().enumerate() {
            let candidate = |value| Candidate {
                rank: (value, e.last_seen_ms, Reverse(e.id)),
                slot: slot as u32,
                rx_bytes_this_tick: e.rx_bytes_this_tick,
                tx_bytes_this_tick: e.tx_bytes_this_tick,
            };
            let (rx_speed, tx_speed) = candidate(0).speeds(elapsed_s);
            by_bytes.offer(candidate(e.total.bytes()));
            by_packets.offer(candidate(e.total.packets()));
            by_rate.offer(candidate(total_order_bits(rx_speed + tx_speed)));
            by_recency.offer(candidate(e.last_seen_ms));
            e.rx_bytes_this_tick = 0;
            e.tx_bytes_this_tick = 0;
        }
        let mut chosen = Vec::with_capacity(4 * n);
        for top in [by_bytes, by_packets, by_rate, by_recency] {
            chosen.extend(top.finish());
        }
        chosen.sort_unstable_by_key(Candidate::id);
        chosen.dedup_by_key(|c| c.id());
        chosen
            .into_iter()
            .map(|c| {
                let e = &self.entries[c.slot as usize];
                let (rx_speed, tx_speed) = c.speeds(elapsed_s);
                RollupRow {
                    id: e.id,
                    key: e.key,
                    total: e.total,
                    rx_speed,
                    tx_speed,
                    flow_count: e.flow_count,
                    first_seen_ms: e.first_seen_ms,
                    last_seen_ms: e.last_seen_ms,
                    ja3_label: e.ja3_label,
                    history_complete: e.history_complete,
                }
            })
            .collect()
    }

    pub fn bounds(&self) -> Bounds {
        Bounds {
            cap: self.cap,
            top_n: self.top_n,
            tracked: self.index.len(),
            evictions: self.evictions,
            unkeyed: self.unkeyed,
            since_ms: self.since_ms,
            horizon_ms: self.horizon_ms,
            totals: self.totals,
            evicted: self.evicted,
        }
    }

    /// Clears entries and counters; keeps cap, top_n and the next id.
    pub fn clear(&mut self) {
        self.entries = Vec::new();
        self.index = HashMap::new();
        self.head = NIL;
        self.tail = NIL;
        self.evictions = 0;
        self.unkeyed = 0;
        self.since_ms = None;
        self.horizon_ms = None;
        self.totals = Traffic::default();
        self.evicted = Traffic::default();
    }

    /// Inserts a new key at the front, evicting the tail first when full.
    fn insert(&mut self, key: K, now_ms: u64) -> u32 {
        // P3: decided before this insertion's own eviction.
        let history_complete = self.evictions == 0;
        let id = self.next_id;
        self.next_id += 1;
        let fresh = Entry {
            key,
            id,
            prev: NIL,
            next: NIL,
            total: Traffic::default(),
            rx_bytes_this_tick: 0,
            tx_bytes_this_tick: 0,
            flow_count: 0,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            ja3_label: None,
            history_complete,
        };
        let slot = if self.entries.len() >= self.cap {
            let slot = self.tail;
            self.unlink(slot);
            let old = &self.entries[slot as usize];
            self.evicted.add(&old.total);
            self.evictions = self.evictions.saturating_add(1);
            self.horizon_ms = Some(
                self.horizon_ms
                    .map_or(old.last_seen_ms, |h| h.max(old.last_seen_ms)),
            );
            self.index.remove(&old.key);
            self.entries[slot as usize] = fresh;
            slot
        } else {
            self.entries.push(fresh);
            (self.entries.len() - 1) as u32
        };
        self.index.insert(key, slot);
        self.push_front(slot);
        slot
    }

    fn unlink(&mut self, slot: u32) {
        let (prev, next) = {
            let e = &self.entries[slot as usize];
            (e.prev, e.next)
        };
        if prev == NIL {
            self.head = next;
        } else {
            self.entries[prev as usize].next = next;
        }
        if next == NIL {
            self.tail = prev;
        } else {
            self.entries[next as usize].prev = prev;
        }
    }

    fn push_front(&mut self, slot: u32) {
        let old_head = self.head;
        {
            let e = &mut self.entries[slot as usize];
            e.prev = NIL;
            e.next = old_head;
        }
        if old_head == NIL {
            self.tail = slot;
        } else {
            self.entries[old_head as usize].prev = slot;
        }
        self.head = slot;
    }
}

/// Where an entry stands in one ranking; greater is better. Value desc, then
/// last_seen_ms desc, then id asc. Ids are unique, so no two ranks are equal.
type Rank = (u64, u64, Reverse<u64>);

/// Maps a rate to an integer that orders exactly as `f64::total_cmp` (P1), so
/// every ranking compares the same type.
fn total_order_bits(rate: f64) -> u64 {
    let bits = rate.to_bits();
    if bits >> 63 == 1 {
        !bits
    } else {
        bits | 1 << 63
    }
}

/// An entry that may be in a ranking's top N. It carries the tick counters
/// because the pass that offers it also drains them from the entry.
struct Candidate {
    rank: Rank,
    slot: u32,
    rx_bytes_this_tick: u64,
    tx_bytes_this_tick: u64,
}

impl Candidate {
    fn id(&self) -> u64 {
        self.rank.2 .0
    }

    fn speeds(&self, elapsed_s: f64) -> (f64, f64) {
        (
            self.rx_bytes_this_tick as f64 / elapsed_s,
            self.tx_bytes_this_tick as f64 / elapsed_s,
        )
    }
}

/// Keeps the best `n` of the candidates offered. Holds up to 2n; when full, an
/// O(n) selection drops the worse half and the worst one kept becomes the
/// threshold. At least n offers separate two selections, so an offer is
/// amortized O(1) whatever the order, and one under the threshold costs a
/// comparison.
struct TopN {
    n: usize,
    threshold: Rank,
    kept: Vec<Candidate>,
}

impl TopN {
    fn new(n: usize, buffer: usize) -> Self {
        Self {
            n,
            // Below every real rank: ids never reach u64::MAX.
            threshold: (0, 0, Reverse(u64::MAX)),
            kept: Vec::with_capacity(buffer),
        }
    }

    #[inline]
    fn offer(&mut self, candidate: Candidate) {
        if candidate.rank <= self.threshold {
            return;
        }
        self.kept.push(candidate);
        if self.kept.len() / 2 >= self.n {
            self.shrink();
        }
    }

    fn shrink(&mut self) {
        if self.kept.len() > self.n {
            let last = self.n - 1;
            self.kept
                .select_nth_unstable_by(last, |a, b| b.rank.cmp(&a.rank));
            self.kept.truncate(self.n);
            self.threshold = self.kept[last].rank;
        }
    }

    fn finish(mut self) -> Vec<Candidate> {
        self.shrink();
        self.kept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap as Map};

    type Ranking = Box<dyn Fn(&RollupRow<u32>, &RollupRow<u32>) -> std::cmp::Ordering>;

    fn keys(t: &RollupTable<u32>) -> BTreeSet<u32> {
        t.index.keys().copied().collect()
    }

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn assert_balanced(t: &RollupTable<u32>) {
        let b = t.bounds();
        let mut sum = Traffic::default();
        for e in &t.entries {
            sum.add(&e.total);
        }
        let mut expect = b.totals;
        expect.rx_bytes -= b.evicted.rx_bytes;
        expect.tx_bytes -= b.evicted.tx_bytes;
        expect.rx_packets -= b.evicted.rx_packets;
        expect.tx_packets -= b.evicted.tx_packets;
        assert_eq!(sum, expect);
    }

    #[test]
    fn cap_plus_one_evicts_exactly_the_least_recent() {
        let mut t = RollupTable::new(3, 3);
        for k in [1, 2, 3, 1, 4] {
            t.record(k, false, 10, 1, 0);
        }
        assert_eq!(keys(&t), BTreeSet::from([1, 3, 4]));
        assert_eq!(t.bounds().evictions, 1);
    }

    #[test]
    fn recency_ignores_equal_and_backward_timestamps() {
        let mut t = RollupTable::new(3, 3);
        for k in [1, 2, 3, 1, 4] {
            t.record(k, false, 10, 5, 0);
        }
        assert_eq!(keys(&t), BTreeSet::from([1, 3, 4]));
        let mut t = RollupTable::new(3, 3);
        for (k, ms) in [(1, 9), (2, 8), (3, 7), (1, 6), (4, 5)] {
            t.record(k, false, 10, ms, 0);
        }
        assert_eq!(keys(&t), BTreeSet::from([1, 3, 4]));
    }

    #[test]
    fn totals_minus_evicted_equals_the_sum_over_tracked() {
        let mut t = RollupTable::new(64, 64);
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        for i in 1..=20_000u32 {
            let r = xorshift(&mut s);
            t.record(
                (r % 500) as u32,
                r & 0x1_0000 != 0,
                (r >> 20) % 1500,
                i as u64,
                0,
            );
            if i % 1000 == 0 {
                assert_balanced(&t);
            }
        }
        assert!(t.bounds().evictions > 0);
    }

    #[test]
    fn cap_one_top_one_balances() {
        let mut t = RollupTable::new(1, 1);
        for k in 0..100u32 {
            t.record(k, k % 2 == 0, 7, k as u64, 0);
        }
        let b = t.bounds();
        assert_eq!((b.tracked, b.evictions), (1, 99));
        assert_balanced(&t);
    }

    #[test]
    fn slots_are_reused() {
        let mut t = RollupTable::new(100, 10);
        for k in 0..1000u32 {
            t.record(k, false, 1, k as u64, 0);
            assert!(t.entries.len() <= 100);
        }
        let mut t = RollupTable::new(1000, 10);
        for k in 0..10_000u32 {
            t.record(k, false, 1, k as u64, 0);
            assert!(
                t.index.capacity() <= 4 * 1000,
                "index capacity {}",
                t.index.capacity()
            );
        }
        assert_eq!(t.entries.len(), 1000);
    }

    #[test]
    fn history_complete_follows_p3() {
        let mut t = RollupTable::new(2, 10);
        for k in 1..=4u32 {
            t.record(k, false, 1, 1, 0);
        }
        let complete: Map<u32, bool> = t
            .snapshot(1.0)
            .into_iter()
            .map(|r| (r.key, r.history_complete))
            .collect();
        assert_eq!(complete, Map::from([(3, true), (4, false)]));
        // Keys 1, 2 were evicted; at cap 2 the first three were 1, 2, 3.
        let mut t = RollupTable::new(2, 10);
        for k in 1..=3u32 {
            t.record(k, false, 1, 1, 0);
        }
        let rows = t.snapshot(1.0);
        assert!(rows.iter().all(|r| r.history_complete));
    }

    #[test]
    fn a_returning_key_starts_from_zero() {
        let mut t = RollupTable::new(1, 10);
        let first = t.record(1, false, 100, 10, 0);
        t.record(2, false, 5, 20, 0);
        let back = t.record(1, false, 7, 30, 0);
        assert_ne!(first, back);
        let rows = t.snapshot(1.0);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(
            r.total,
            Traffic {
                rx_bytes: 7,
                rx_packets: 1,
                ..Traffic::default()
            }
        );
        assert_eq!((r.first_seen_ms, r.id), (30, back));
        assert!(!r.history_complete);
    }

    #[test]
    fn evicted_and_returned_within_one_tick() {
        let mut t = RollupTable::new(1, 10);
        t.record(1, false, 100, 1, 0);
        t.record(2, false, 5, 2, 0);
        t.record(1, false, 40, 3, 0);
        t.record(1, true, 30, 3, 0);
        let rows = t.snapshot(2.0);
        assert_eq!((rows[0].rx_speed, rows[0].tx_speed), (20.0, 15.0));
        t.record(1, true, 50, 4, 0);
        let rows = t.snapshot(1.0);
        assert_eq!((rows[0].rx_speed, rows[0].tx_speed), (0.0, 50.0));
        assert_eq!((rows[0].total.rx_bytes, rows[0].total.tx_bytes), (40, 80));
    }

    #[test]
    fn flow_counts_once_per_entry_id() {
        let mut t = RollupTable::new(4, 4);
        let id = t.record(1, false, 1, 1, 0);
        t.record(1, false, 1, 2, id);
        assert_eq!(t.snapshot(1.0)[0].flow_count, 1);
        t.record(1, false, 1, 3, 0);
        assert_eq!(t.snapshot(1.0)[0].flow_count, 2);
    }

    #[test]
    fn horizon_is_the_latest_evicted_last_seen() {
        let mut t = RollupTable::new(1, 1);
        assert_eq!(t.bounds().horizon_ms, None);
        t.record(1, false, 1, 50, 0);
        assert_eq!(t.bounds().horizon_ms, None);
        t.record(2, false, 1, 10, 0);
        assert_eq!(t.bounds().horizon_ms, Some(50));
        t.record(3, false, 1, 20, 0);
        assert_eq!(t.bounds().horizon_ms, Some(50));
    }

    #[test]
    fn since_is_the_first_recorded_or_unkeyed_packet() {
        let mut t: RollupTable<u32> = RollupTable::new(4, 4);
        assert_eq!(t.bounds().since_ms, None);
        t.record_unkeyed(7);
        t.record(1, false, 1, 3, 0);
        assert_eq!(t.bounds().since_ms, Some(7));
        assert_eq!(t.bounds().unkeyed, 1);
        let mut t: RollupTable<u32> = RollupTable::new(4, 4);
        t.record(1, false, 1, 3, 0);
        t.record_unkeyed(1);
        assert_eq!(t.bounds().since_ms, Some(3));
    }

    #[test]
    fn each_ranking_matches_a_full_sort_with_ties() {
        const SIZES: [u64; 5] = [10, 20, 30, 40, 50];
        for n in [1usize, 10, 200] {
            // The same input drives the table under test and a reference
            // table that keeps everything, so the reference snapshot is a
            // full sort's input.
            let feed = |t: &mut RollupTable<u32>| {
                let mut s = 0x1234_5678_9ABC_DEF1u64;
                for k in 0..2000u32 {
                    let r = xorshift(&mut s);
                    t.record(
                        k,
                        r & 1 == 0,
                        SIZES[(r >> 8) as usize % 5],
                        (r >> 16) % 3,
                        0,
                    );
                }
                // Drain, so the rates below come from the second phase only.
                t.snapshot(1.0);
                // Decorrelate packets, recency, bytes and rate: old keys with
                // many small mixed-direction packets, the newest keys with one
                // small packet, and mid-age keys with one large packet.
                for k in 0..2000u32 {
                    let r = xorshift(&mut s);
                    match k % 4 {
                        0 => {
                            for i in 0..3 + (r >> 4) % 3 {
                                t.record(k, (r >> i) & 1 == 0, SIZES[0], 1 + (r >> 16) % 2, 0);
                            }
                        }
                        1 => {
                            t.record(k, r & 1 == 0, SIZES[0], 3 + (r >> 16) % 3, 0);
                        }
                        2 => {
                            t.record(k, r & 1 == 0, SIZES[(r >> 8) as usize % 5] * 100, 2, 0);
                        }
                        _ => {}
                    }
                }
            };
            let mut t = RollupTable::new(10_000, n);
            feed(&mut t);
            let rows_after = t.snapshot(2.0);
            let mut reference = RollupTable::new(10_000, 10_000);
            feed(&mut reference);
            let all = reference.snapshot(2.0);
            let rankings: Vec<Ranking> = vec![
                Box::new(|a, b| {
                    (b.total.rx_bytes + b.total.tx_bytes)
                        .cmp(&(a.total.rx_bytes + a.total.tx_bytes))
                }),
                Box::new(|a, b| {
                    (b.total.rx_packets + b.total.tx_packets)
                        .cmp(&(a.total.rx_packets + a.total.tx_packets))
                }),
                Box::new(|a, b| (b.rx_speed + b.tx_speed).total_cmp(&(a.rx_speed + a.tx_speed))),
                Box::new(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms)),
            ];
            for rank in &rankings {
                let order = |rows: &[RollupRow<u32>]| {
                    let mut v: Vec<(usize, &RollupRow<u32>)> = rows.iter().enumerate().collect();
                    v.sort_by(|(pa, a), (pb, b)| {
                        rank(a, b)
                            .then(b.last_seen_ms.cmp(&a.last_seen_ms))
                            .then(pa.cmp(pb))
                    });
                    v.into_iter().map(|(_, r)| r.key).collect::<Vec<u32>>()
                };
                let want: Vec<u32> = order(&all).into_iter().take(n).collect();
                let got: Vec<u32> = order(&rows_after).into_iter().take(n).collect();
                assert_eq!(got, want, "n={n}");
            }
        }
    }

    #[test]
    fn identical_input_gives_identical_rows() {
        let run = || {
            let mut t = RollupTable::new(50, 5);
            let mut s = 42u64;
            for i in 0..2000u64 {
                let r = xorshift(&mut s);
                t.record((r % 200) as u32, r & 1 == 0, (r >> 8) % 900, i, 0);
            }
            t.snapshot(1.0)
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn counters_saturate() {
        let mut t = RollupTable::new(2, 2);
        t.record(1, false, u64::MAX, 1, 0);
        t.record(1, false, u64::MAX, 2, 0);
        t.record(1, true, u64::MAX, 3, 0);
        let rows = t.snapshot(1.0);
        assert_eq!(rows[0].total.rx_bytes, u64::MAX);
        assert_eq!(t.bounds().totals.rx_bytes, u64::MAX);
    }

    #[test]
    fn clear_resets_everything_but_the_id() {
        let mut t = RollupTable::new(2, 3);
        t.record(1, false, 1, 5, 0);
        t.record(2, false, 1, 5, 0);
        let last = t.record(3, false, 1, 5, 0);
        t.record_unkeyed(5);
        t.clear();
        let b = t.bounds();
        assert_eq!(
            (b.cap, b.top_n, b.tracked, b.evictions, b.unkeyed),
            (2, 3, 0, 0, 0)
        );
        assert_eq!(
            (b.since_ms, b.horizon_ms, b.totals, b.evicted),
            (None, None, Traffic::default(), Traffic::default())
        );
        assert!(t.snapshot(1.0).is_empty());
        assert!(t.record(9, false, 1, 6, 0) > last);
    }

    #[test]
    fn rate_bits_order_exactly_as_total_cmp() {
        let values = [
            f64::NAN,
            -f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MAX,
            f64::MIN,
            1.5,
            -1.5,
            f64::MIN_POSITIVE,
            5e-324,
            -5e-324,
            0.0,
            -0.0,
        ];
        for a in values {
            for b in values {
                let got = total_order_bits(a).cmp(&total_order_bits(b));
                assert_eq!(got, a.total_cmp(&b), "{a} {b}");
            }
        }
    }

    #[test]
    fn slot_order_never_changes_the_selection() {
        // One ranking follows the slot order (so an ascending one beats the
        // threshold at every entry) while the other three are scattered.
        for n in [1usize, 2, 7, 50] {
            let k_max = 20 * n;
            for len in [n - 1, n, n + 1, 2 * n - 1, 2 * n, 2 * n + 1, k_max] {
                for ranking in 0..4 {
                    for (order, ms_seed) in ["ascending", "descending", "equal", "equal ms too"]
                        .into_iter()
                        .flat_map(|o| [(o, 1u64), (o, 99)])
                    {
                        let mut t = RollupTable::new(k_max, n);
                        for k in 0..len {
                            t.record(k as u32, false, 0, 0, 0);
                        }
                        // Ids must not follow the slots, or a tie-break by slot
                        // would pass.
                        let mut ids: Vec<u64> = (1..=len as u64).collect();
                        let mut s = 0x9E37_79B9_7F4A_7C15u64 ^ ms_seed;
                        for i in (1..len).rev() {
                            ids.swap(i, (xorshift(&mut s) % (i as u64 + 1)) as usize);
                        }
                        for (i, e) in t.entries.iter_mut().enumerate() {
                            let i = i as u64;
                            let mut v = [0u64; 4];
                            for x in &mut v {
                                *x = xorshift(&mut s) % (len as u64);
                            }
                            if order == "equal ms too" {
                                v[3] = 5;
                            }
                            v[ranking] = match order {
                                "ascending" => i,
                                "descending" => len as u64 - i,
                                _ => 5,
                            };
                            e.id = ids[i as usize];
                            e.total.rx_bytes = v[0];
                            e.total.rx_packets = v[1];
                            e.rx_bytes_this_tick = v[2];
                            e.tx_bytes_this_tick = 1;
                            e.last_seen_ms = v[3];
                        }
                        let all: Vec<RollupRow<u32>> = t
                            .entries
                            .iter()
                            .map(|e| RollupRow {
                                id: e.id,
                                key: e.key,
                                total: e.total,
                                rx_speed: e.rx_bytes_this_tick as f64 / 3.0,
                                tx_speed: e.tx_bytes_this_tick as f64 / 3.0,
                                flow_count: e.flow_count,
                                first_seen_ms: e.first_seen_ms,
                                last_seen_ms: e.last_seen_ms,
                                ja3_label: e.ja3_label,
                                history_complete: e.history_complete,
                            })
                            .collect();
                        let rankings: [Ranking; 4] = [
                            Box::new(|a, b| b.total.rx_bytes.cmp(&a.total.rx_bytes)),
                            Box::new(|a, b| b.total.rx_packets.cmp(&a.total.rx_packets)),
                            Box::new(|a, b| {
                                (b.rx_speed + b.tx_speed).total_cmp(&(a.rx_speed + a.tx_speed))
                            }),
                            Box::new(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms)),
                        ];
                        let mut want = Map::new();
                        for rank in &rankings {
                            let mut sorted = all.clone();
                            sorted.sort_by(|a, b| {
                                rank(a, b)
                                    .then(b.last_seen_ms.cmp(&a.last_seen_ms))
                                    .then(a.id.cmp(&b.id))
                            });
                            for row in sorted.into_iter().take(n) {
                                want.insert(row.id, row);
                            }
                        }
                        let mut want: Vec<_> = want.into_values().collect();
                        want.sort_by_key(|r| r.id);
                        let got = t.snapshot(3.0);
                        assert_eq!(got, want, "n={n} len={len} ranking={ranking} {order}");
                        assert!(t
                            .entries
                            .iter()
                            .all(|e| (e.rx_bytes_this_tick, e.tx_bytes_this_tick) == (0, 0)));
                    }
                }
            }
        }
    }
}
