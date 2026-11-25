//! JAM-21: what one observed-name entry costs at its worst, so the default
//! capacity (`DEFAULT_MAX_OBSERVED_DNS_NAMES`) is chosen from a measurement
//! and not a guess. Ignored by default; run with
//! `cargo test --release --test dns_names_entry_cost -- --ignored --nocapture`.
//!
//! Own integration-test binary because it installs a counting global
//! allocator, which must not replace the allocator for the unit tests.
#[path = "fixtures/counting_allocator.rs"]
mod counting_allocator;
use counting_allocator::LIVE_BYTES;
use std::sync::atomic::Ordering;

use capture_agent::dns_names::ObservedDnsNames;
use capture_agent::l7::DnsAnswer;

/// A 253-byte name and a 39-byte address: the longest of each.
fn worst_case_entry(i: usize) -> (String, DnsAnswer) {
    let mut name = format!("h{i:08}.");
    while name.len() + 64 < 253 {
        name.push_str(&"a".repeat(63));
        name.push('.');
    }
    name.push_str(&"b".repeat(253 - name.len()));
    assert_eq!(name.len(), 253);
    let data = format!(
        "fedc:ba98:7654:3210:fedc:ba98:{:04x}:{:04x}",
        0x1000 + i % 0xE000,
        0x1000 + i / 0xE000
    );
    assert_eq!(data.len(), 39);
    let answer = DnsAnswer { name: name.clone(), rtype: 28, ttl: 3600, data, data_truncated: false };
    (name, answer)
}

#[test]
#[ignore = "measurement, not a check; prints bytes per entry"]
fn dns_names_entry_cost() {
    for capacity in [4_096usize, 16_384, 1_048_576] {
        // Built before measuring so only the table's own allocations count.
        let entries: Vec<(String, DnsAnswer)> = (0..capacity).map(worst_case_entry).collect();
        let before = LIVE_BYTES.load(Ordering::Relaxed);
        let mut table = ObservedDnsNames::new(capacity);
        for (i, (name, answer)) in entries.iter().enumerate() {
            table.learn_response(name, std::slice::from_ref(answer), i as u64);
        }
        let used = LIVE_BYTES.load(Ordering::Relaxed) - before;
        assert_eq!(table.len(), capacity);
        println!(
            "capacity {capacity}: {used} bytes total, {} bytes/entry ({:.1} MiB)",
            used / capacity,
            used as f64 / (1024.0 * 1024.0)
        );
    }
}
