//! JAM-21: names observed in DNS responses, kept so an endpoint can show the
//! name the local host asked for. Purely passive: it only remembers what
//! answered responses said, so the name is whatever the queried server said:
//! any process able to send a query, or any zone owner, can choose it (no
//! on-path attacker is needed). It is separate from reverse-lookup hostnames and is
//! labelled accordingly on the wire.
//!
//! One name per address, the most recently learned. Entries expire on the
//! caller's clock (`now_ms`), which is the replay-aware flow clock in the
//! agent, never packet timestamps or wall time. The table is bounded:
//! expired entries go first, then the entry expiring soonest.
use std::collections::{BTreeSet, HashMap};

use crate::l7::DnsAnswer;

pub const DEFAULT_MAX_OBSERVED_DNS_NAMES: usize = 16_384;
/// Shortest and longest time an entry lives, whatever TTL the response
/// carried. A zero TTL would otherwise lose the name before the connection
/// it explains is even drawn, and a huge one would pin a slot for years.
pub const MIN_NAME_RETENTION_MS: u64 = 3_600_000;
pub const MAX_NAME_RETENTION_MS: u64 = 86_400_000;

/// Longest name kept, in bytes: the DNS presentation-form limit.
const MAX_NAME_BYTES: usize = 253;
const RTYPE_A: u16 = 1;
const RTYPE_CNAME: u16 = 5;
const RTYPE_AAAA: u16 = 28;

struct Entry {
    name: String,
    expires_ms: u64,
    seq: u64,
}

pub struct ObservedDnsNames {
    capacity: usize,
    entries: HashMap<String, Entry>,
    /// Entries by (expiry, sequence, address), so purging and eviction take
    /// the front instead of scanning. The sequence keeps equal expiries
    /// distinct and makes eviction order deterministic.
    by_expiry: BTreeSet<(u64, u64, String)>,
    next_seq: u64,
    evictions: u64,
}

impl ObservedDnsNames {
    pub fn new(capacity: usize) -> Self {
        ObservedDnsNames {
            capacity,
            entries: HashMap::new(),
            by_expiry: BTreeSet::new(),
            next_seq: 0,
            evictions: 0,
        }
    }

    /// Learns `query_name` for every address the response gives it. An
    /// address counts only when an A/AAAA record's owner is the question or
    /// is reachable from it through the response's CNAMEs: a response can
    /// carry unrelated records, and those must not name anything.
    pub fn learn_response(&mut self, query_name: &str, answers: &[DnsAnswer], now_ms: u64) {
        if !is_learnable_name(query_name) {
            return;
        }
        self.purge_expired(now_ms);
        let name = query_name.to_ascii_lowercase();
        // Each pass can only add names, so `answers.len()` passes reach
        // every CNAME chain whatever order the records arrive in, and a
        // loop adds nothing new.
        let mut reachable = vec![name.clone()];
        for _ in 0..answers.len() {
            let before = reachable.len();
            for answer in answers.iter().filter(|a| a.rtype == RTYPE_CNAME) {
                let target = answer.data.to_ascii_lowercase();
                if reachable.iter().any(|n| answer.name.eq_ignore_ascii_case(n))
                    && !reachable.contains(&target)
                {
                    reachable.push(target);
                }
            }
            if reachable.len() == before {
                break;
            }
        }
        for answer in answers {
            if !matches!(answer.rtype, RTYPE_A | RTYPE_AAAA) || answer.data.is_empty() {
                continue;
            }
            if !reachable.iter().any(|n| answer.name.eq_ignore_ascii_case(n)) {
                continue;
            }
            let retention = (u64::from(answer.ttl) * 1000)
                .clamp(MIN_NAME_RETENTION_MS, MAX_NAME_RETENTION_MS);
            self.insert(&answer.data, name.clone(), now_ms.saturating_add(retention), now_ms);
        }
    }

    fn insert(&mut self, addr: &str, name: String, expires_ms: u64, now_ms: u64) {
        if let Some(old) = self.entries.remove(addr) {
            self.by_expiry.remove(&(old.expires_ms, old.seq, addr.to_string()));
        } else if self.entries.len() >= self.capacity {
            self.purge_expired(now_ms);
            if self.entries.len() >= self.capacity {
                if let Some((_, _, victim)) = self.by_expiry.pop_first() {
                    self.entries.remove(&victim);
                    self.evictions += 1;
                }
            }
        }
        if self.capacity == 0 {
            return;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.by_expiry.insert((expires_ms, seq, addr.to_string()));
        self.entries.insert(addr.to_string(), Entry { name, expires_ms, seq });
    }

    /// Removes every entry at or past its expiry. Not an eviction: the
    /// entry reached the end of its life.
    fn purge_expired(&mut self, now_ms: u64) {
        while let Some((expires_ms, _, _)) = self.by_expiry.first() {
            if *expires_ms > now_ms {
                break;
            }
            if let Some((_, _, addr)) = self.by_expiry.pop_first() {
                self.entries.remove(&addr);
            }
        }
    }

    /// The name last learned for `addr`, unless it is at or past expiry.
    pub fn lookup(&self, addr: &str, now_ms: u64) -> Option<&str> {
        self.entries
            .get(addr)
            .filter(|entry| entry.expires_ms > now_ms)
            .map(|entry| entry.name.as_str())
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_expiry.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn evictions(&self) -> u64 {
        self.evictions
    }
}

/// A name from the wire is shown in the UI, so only plain hostname bytes are
/// accepted; anything else (escapes, non-ASCII, spaces) is not learned.
fn is_learnable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ans(name: &str, rtype: u16, ttl: u32, data: &str) -> DnsAnswer {
        DnsAnswer { name: name.into(), rtype, ttl, data: data.into(), data_truncated: false }
    }
    fn a(name: &str, ip: &str) -> DnsAnswer {
        ans(name, 1, 300, ip)
    }
    fn cname(name: &str, target: &str) -> DnsAnswer {
        ans(name, 5, 300, target)
    }

    #[test]
    fn a_record_maps_address_to_question() {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response("example.com", &[a("example.com", "1.2.3.4")], 0);
        assert_eq!(t.lookup("1.2.3.4", 0), Some("example.com"));
    }

    #[test]
    fn aaaa_key_matches_the_flow_table_address_form() {
        // The flow table keys on the packet's address string, which is
        // `Ipv6Addr::to_string`; the answer's data is produced the same way
        // from the wire bytes, so a compressible address must agree.
        let addr: std::net::Ipv6Addr = "2001:db8:0:0:0:0:0:1".parse().unwrap();
        let flow_form = addr.to_string();
        assert_eq!(flow_form, "2001:db8::1");
        let mut t = ObservedDnsNames::new(8);
        t.learn_response("v6.example", &[ans("v6.example", 28, 300, &flow_form)], 0);
        assert_eq!(t.lookup(&flow_form, 0), Some("v6.example"));
    }

    #[test]
    fn cname_chain_maps_to_the_question() {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response(
            "www.a.com",
            &[cname("www.a.com", "cdn.b.net"), a("cdn.b.net", "1.2.3.4")],
            0,
        );
        assert_eq!(t.lookup("1.2.3.4", 0), Some("www.a.com"));
    }

    #[test]
    fn cname_order_in_the_answer_section_does_not_matter() {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response(
            "www.a.com",
            &[a("edge.c.org", "1.2.3.4"), cname("cdn.b.net", "edge.c.org"), cname("www.a.com", "cdn.b.net")],
            0,
        );
        assert_eq!(t.lookup("1.2.3.4", 0), Some("www.a.com"));
    }

    #[test]
    fn cname_loop_terminates() {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response("a.com", &[cname("a.com", "b.com"), cname("b.com", "a.com")], 0);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn unrelated_a_record_is_ignored() {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response("a.com", &[a("evil.net", "6.6.6.6")], 0);
        assert_eq!(t.lookup("6.6.6.6", 0), None);
    }

    #[test]
    fn owner_comparison_is_case_insensitive() {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response("WwW.A.cOm", &[a("www.A.COM", "1.2.3.4")], 0);
        assert_eq!(t.lookup("1.2.3.4", 0), Some("www.a.com"));
    }

    #[test]
    fn name_with_disallowed_bytes_is_not_learned() {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response("a<b.com", &[a("a<b.com", "1.2.3.4")], 0);
        t.learn_response("b\u{fc}cher.de", &[a("b\u{fc}cher.de", "1.2.3.5")], 0);
        t.learn_response("", &[a("", "1.2.3.6")], 0);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn allowed_punctuation_is_learned() {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response("_dmarc.a-b.com", &[a("_dmarc.a-b.com", "1.2.3.4")], 0);
        assert_eq!(t.lookup("1.2.3.4", 0), Some("_dmarc.a-b.com"));
    }

    fn name_of(len: usize) -> String {
        let mut name = String::new();
        while name.len() + 64 < len {
            name.push_str(&"a".repeat(63));
            name.push('.');
        }
        name.push_str(&"b".repeat(len - name.len()));
        assert_eq!(name.len(), len);
        name
    }

    #[test]
    fn name_of_253_bytes_is_learned() {
        let name = name_of(253);
        let mut t = ObservedDnsNames::new(8);
        t.learn_response(&name, &[a(&name, "1.2.3.4")], 0);
        assert_eq!(t.lookup("1.2.3.4", 0), Some(name.as_str()));
    }

    #[test]
    fn name_of_254_bytes_is_not_learned() {
        let name = name_of(254);
        let mut t = ObservedDnsNames::new(8);
        t.learn_response(&name, &[a(&name, "1.2.3.4")], 0);
        assert_eq!(t.lookup("1.2.3.4", 0), None);
    }

    #[test]
    fn most_recent_name_wins_for_a_shared_address() {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response("one.com", &[a("one.com", "1.2.3.4")], 0);
        t.learn_response("two.com", &[a("two.com", "1.2.3.4")], 1);
        assert_eq!(t.lookup("1.2.3.4", 1), Some("two.com"));
        assert_eq!(t.len(), 1);
    }

    fn learn_with_ttl(ttl: u32) -> ObservedDnsNames {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response("a.com", &[ans("a.com", 1, ttl, "1.2.3.4")], 0);
        t
    }

    #[test]
    fn ttl_below_floor_uses_the_floor() {
        let t = learn_with_ttl(0);
        assert!(t.lookup("1.2.3.4", MIN_NAME_RETENTION_MS - 1).is_some());
        assert!(t.lookup("1.2.3.4", MIN_NAME_RETENTION_MS).is_none());
    }

    #[test]
    fn ttl_above_ceiling_uses_the_ceiling() {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response("a.com", &[ans("a.com", 1, u32::MAX, "1.2.3.4")], u64::MAX - 1);
        assert!(t.lookup("1.2.3.4", u64::MAX - 1).is_some());
        let t = learn_with_ttl(u32::MAX);
        assert!(t.lookup("1.2.3.4", MAX_NAME_RETENTION_MS - 1).is_some());
        assert!(t.lookup("1.2.3.4", MAX_NAME_RETENTION_MS).is_none());
    }

    #[test]
    fn ttl_in_range_is_used() {
        let t = learn_with_ttl(7_200);
        assert!(t.lookup("1.2.3.4", 7_200_000 - 1).is_some());
        assert!(t.lookup("1.2.3.4", 7_200_000).is_none());
    }

    #[test]
    fn re_resolving_extends_expiry() {
        let mut t = learn_with_ttl(0);
        t.learn_response("a.com", &[ans("a.com", 1, 0, "1.2.3.4")], MIN_NAME_RETENTION_MS - 10);
        assert!(t.lookup("1.2.3.4", MIN_NAME_RETENTION_MS + 10).is_some());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn capacity_holds_at_the_limit() {
        let mut t = ObservedDnsNames::new(2);
        t.learn_response("a.com", &[a("a.com", "1.1.1.1")], 0);
        t.learn_response("b.com", &[a("b.com", "2.2.2.2")], 0);
        assert!(t.lookup("1.1.1.1", 0).is_some() && t.lookup("2.2.2.2", 0).is_some());
        assert_eq!(t.evictions(), 0);
    }

    #[test]
    fn over_capacity_drops_expired_first() {
        let mut t = ObservedDnsNames::new(2);
        t.learn_response("a.com", &[ans("a.com", 1, 0, "1.1.1.1")], 0);
        t.learn_response("b.com", &[ans("b.com", 1, 86_400, "2.2.2.2")], 0);
        let later = MIN_NAME_RETENTION_MS + 1;
        t.learn_response("c.com", &[a("c.com", "3.3.3.3")], later);
        assert!(t.lookup("1.1.1.1", later).is_none());
        assert!(t.lookup("2.2.2.2", later).is_some());
        assert!(t.lookup("3.3.3.3", later).is_some());
        assert_eq!(t.evictions(), 0);
    }

    #[test]
    fn over_capacity_evicts_the_soonest_to_expire() {
        let mut t = ObservedDnsNames::new(2);
        t.learn_response("a.com", &[ans("a.com", 1, 7_200, "1.1.1.1")], 0);
        t.learn_response("b.com", &[ans("b.com", 1, 86_400, "2.2.2.2")], 0);
        t.learn_response("c.com", &[ans("c.com", 1, 7_200, "3.3.3.3")], 0);
        assert!(t.lookup("1.1.1.1", 0).is_none());
        assert!(t.lookup("2.2.2.2", 0).is_some());
        assert!(t.lookup("3.3.3.3", 0).is_some());
        assert_eq!(t.evictions(), 1);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn clear_empties_the_table() {
        let mut t = ObservedDnsNames::new(8);
        t.learn_response("a.com", &[a("a.com", "1.1.1.1")], 0);
        t.clear();
        assert_eq!(t.len(), 0);
        assert!(t.lookup("1.1.1.1", 0).is_none());
    }

    #[test]
    fn zero_capacity_stores_nothing_and_counts_no_evictions() {
        let mut t = ObservedDnsNames::new(0);
        t.learn_response("a.com", &[a("a.com", "1.2.3.4"), a("a.com", "1.2.3.5")], 0);
        assert_eq!(t.len(), 0);
        assert_eq!(t.lookup("1.2.3.4", 0), None);
        assert_eq!(t.evictions(), 0);
    }

    fn retained_until(ttl: u32) -> u64 {
        // Smallest `now` at which the entry is gone.
        let mut t = ObservedDnsNames::new(4);
        t.learn_response("a.com", &[ans("a.com", 1, ttl, "1.2.3.4")], 0);
        let mut lo = 0u64;
        let mut hi = MAX_NAME_RETENTION_MS + 1;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if t.lookup("1.2.3.4", mid).is_none() { hi = mid } else { lo = mid + 1 }
        }
        lo
    }

    #[test]
    fn retention_clamp_at_the_ttl_boundaries() {
        assert_eq!(retained_until(3_600), 3_600_000);
        assert_eq!(retained_until(3_601), 3_601_000);
        assert_eq!(retained_until(86_400), 86_400_000);
        assert_eq!(retained_until(86_401), 86_400_000);
    }
}
