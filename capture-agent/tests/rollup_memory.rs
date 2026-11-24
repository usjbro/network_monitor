//! KAN-131: live heap bytes of one `RollupTable` at first fill and after
//! churn of 10 x cap distinct keys. Ignored by default; run with
//! `cargo test --release --locked --test rollup_memory -- --ignored --nocapture`.
//!
//! Own integration-test binary because it installs a counting global
//! allocator, which must not slow `rollup_cost.rs`.
use std::alloc::{GlobalAlloc, Layout, System};
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

use capture_agent::rollup::RollupTable;

struct Counting;
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE_BYTES.fetch_add(new_size, Ordering::Relaxed);
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn measure<K: Copy + Eq + Hash>(label: &str, k: usize, key: impl Fn(usize) -> K) {
    let before = LIVE_BYTES.load(Ordering::Relaxed);
    let used = || LIVE_BYTES.load(Ordering::Relaxed) - before;
    let mut table = RollupTable::new(k, 200);
    for i in 0..k {
        table.record(key(i), false, 100, i as u64, 0);
    }
    let filled = used();
    let mut most = filled;
    for i in k..11 * k {
        table.record(key(i), false, 100, i as u64, 0);
        most = most.max(used());
    }
    let churned = used();
    let b = table.bounds();
    assert_eq!((b.tracked, b.evictions), (k, 10 * k as u64));
    println!(
        "{label} K={k} first_fill={filled} after_churn={churned} max_between_inserts={most} \
         ({:.1} / {:.1} MiB, {} / {} bytes per key)",
        filled as f64 / 1048576.0,
        churned as f64 / 1048576.0,
        filled / k,
        churned / k
    );
}

#[test]
#[ignore = "measurement, not a check; prints bytes per table"]
fn rollup_memory() {
    let remote = |i: usize| IpAddr::V6(Ipv6Addr::from((0x2600u128 << 112) | i as u128));
    let local = remote(usize::MAX >> 1);
    for k in [10_000, 50_000, 100_000, 500_000] {
        measure("endpoints", k, remote);
        measure("conversations", k, |i| (local, remote(i)));
    }
}
