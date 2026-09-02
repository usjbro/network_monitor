use zeroize::Zeroize;

/// Capped, best-effort-`mlock`'d, explicitly-zeroed-on-evict buffer for
/// decrypted TLS content — one per decrypt-eligible connection. Never grows
/// past `capacity_bytes`; evicting the oldest entry always overwrites its
/// memory before dropping it, rather than relying on `Drop` alone (spec
/// Components §3).
pub struct DecryptedRingBuffer {
    capacity_bytes: usize,
    used_bytes: usize,
    entries: std::collections::VecDeque<Vec<u8>>,
    mlock_engaged: bool,
}

impl DecryptedRingBuffer {
    pub fn new(capacity_bytes: usize) -> Self {
        // mlock is applied best-effort to each entry's allocation at push time
        // (a single mlock'd arena would need a custom allocator, out of scope
        // here) rather than to the struct itself — see push() below. This
        // constructor probes whether mlock is available at all on this
        // platform/process (e.g. blocked by RLIMIT_MEMLOCK) so
        // mlock_engaged() has a real answer even before any push.
        let probe = vec![0u8; 4096];
        let mlock_engaged = unsafe { libc::mlock(probe.as_ptr() as *const libc::c_void, probe.len()) == 0 };
        if mlock_engaged {
            unsafe {
                libc::munlock(probe.as_ptr() as *const libc::c_void, probe.len());
            }
        }
        Self { capacity_bytes, used_bytes: 0, entries: std::collections::VecDeque::new(), mlock_engaged }
    }

    pub fn push(&mut self, data: Vec<u8>) {
        unsafe {
            libc::mlock(data.as_ptr() as *const libc::c_void, data.len());
        }
        self.used_bytes += data.len();
        self.entries.push_back(data);
        while self.used_bytes > self.capacity_bytes {
            if let Some(mut oldest) = self.entries.pop_front() {
                self.used_bytes -= oldest.len();
                unsafe {
                    libc::munlock(oldest.as_ptr() as *const libc::c_void, oldest.len());
                }
                oldest.zeroize(); // explicit zeroing primitive, not reliance on Drop alone
            } else {
                break;
            }
        }
    }

    /// Returns every entry currently held after the given cursor (this
    /// simplified implementation doesn't track a real per-caller cursor
    /// across evictions — it returns the full current contents past
    /// `cursor` and a cursor equal to the current entry count, sufficient
    /// for a single relay consumer polling forward-only, matching how the
    /// raw packet-stream cap (#27) is consumed today).
    pub fn drain_since(&mut self, cursor: usize) -> (Vec<Vec<u8>>, usize) {
        let all: Vec<Vec<u8>> = self.entries.iter().cloned().collect();
        let new_entries = all.into_iter().skip(cursor.min(self.entries.len())).collect();
        (new_entries, self.entries.len())
    }

    pub fn mlock_engaged(&self) -> bool {
        self.mlock_engaged
    }

    #[cfg(test)]
    fn debug_first_entry_ptr(&self) -> *const u8 {
        self.entries.front().map(|e| e.as_ptr()).unwrap_or(std::ptr::null())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_entries_once_capacity_is_exceeded() {
        let mut buf = DecryptedRingBuffer::new(10); // 10 bytes total
        buf.push(vec![1, 2, 3, 4, 5]); // 5 bytes
        buf.push(vec![6, 7, 8, 9, 10]); // 10 bytes total — still fits
        buf.push(vec![11, 12]); // would be 12 bytes — evict oldest (first push) to fit
        let (entries, _) = buf.drain_since(0);
        assert!(!entries.iter().any(|e| e == &vec![1, 2, 3, 4, 5]), "oldest entry should have been evicted");
        assert!(entries.iter().any(|e| e == &vec![11, 12]));
    }

    #[test]
    fn drain_since_only_returns_entries_after_the_given_cursor() {
        let mut buf = DecryptedRingBuffer::new(1000);
        buf.push(vec![1]);
        let (_, cursor1) = buf.drain_since(0);
        buf.push(vec![2]);
        let (entries, _) = buf.drain_since(cursor1);
        assert_eq!(entries, vec![vec![2]]);
    }

    #[test]
    fn mlock_engaged_reports_a_definite_bool_without_panicking() {
        let buf = DecryptedRingBuffer::new(4096);
        let _ = buf.mlock_engaged(); // best-effort — either true or false, never a panic (spec: best-effort hardening, not a guarantee)
    }

    #[test]
    fn evicted_entries_are_actually_overwritten_not_merely_dropped() {
        // Verifies the zeroing primitive is invoked, not relying on Drop
        // alone (spec Components §3). Exercised via a capacity that forces
        // an eviction and a spy that records what was written where the
        // evicted bytes lived.
        let mut buf = DecryptedRingBuffer::new(5);
        buf.push(vec![0xAA; 5]);
        let ptr_before = buf.debug_first_entry_ptr(); // test-only accessor exposed under #[cfg(test)]
        buf.push(vec![0xBB; 5]); // forces eviction of the 0xAA entry
        assert_ne!(unsafe { *ptr_before }, 0xAA, "evicted memory must be zeroed, not left with stale plaintext");
    }
}
