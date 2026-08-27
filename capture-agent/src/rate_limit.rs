/// Caps how many discrete `AgentEvent::Packet` events go out per fixed time
/// window, independent of how many packets are actually captured. Flow/layer
/// aggregates (`FlowTable::observe`) still see every packet — this only
/// gates the per-packet event sent to the browser, which the UI truncates to
/// its last 100 entries anyway (`app/page.tsx`'s `prev.slice(0, 100)`).
///
/// Takes an explicit `now_ms` (mirroring `flow.rs`) instead of calling
/// `Instant::now()` internally, so it stays deterministic and unit-testable
/// without sleeping.
pub struct PacketEventLimiter {
    max_per_window: u32,
    window_ms: u64,
    window_start_ms: Option<u64>,
    count_in_window: u32,
}

impl PacketEventLimiter {
    pub fn new(max_per_window: u32, window_ms: u64) -> Self {
        Self {
            max_per_window,
            window_ms,
            window_start_ms: None,
            count_in_window: 0,
        }
    }

    /// Call once per candidate emission with the same `now_ms` clock main.rs
    /// already derives from `start.elapsed()`. Returns true if this packet's
    /// event should be sent, false if the window's budget is exhausted.
    pub fn allow(&mut self, now_ms: u64) -> bool {
        let reset = match self.window_start_ms {
            None => true,
            Some(s) => now_ms.saturating_sub(s) >= self.window_ms,
        };
        if reset {
            self.window_start_ms = Some(now_ms);
            self.count_in_window = 0;
        }
        if self.count_in_window >= self.max_per_window {
            false
        } else {
            self.count_in_window += 1;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_exactly_n_then_denies_the_n_plus_1th() {
        let mut limiter = PacketEventLimiter::new(3, 1000);
        assert!(limiter.allow(0));
        assert!(limiter.allow(10));
        assert!(limiter.allow(20));
        assert!(!limiter.allow(30), "4th call within the same window should be denied");
    }

    #[test]
    fn window_boundary_resets_and_allows_again() {
        let mut limiter = PacketEventLimiter::new(2, 1000);
        assert!(limiter.allow(0));
        assert!(limiter.allow(0));
        assert!(!limiter.allow(500), "budget exhausted mid-window");

        // Exactly at window_start + window_ms: a new window begins.
        assert!(limiter.allow(1000), "call at window_start + window_ms should reset the window");
        assert!(limiter.allow(1000));
        assert!(!limiter.allow(1000), "budget for the new window should now be exhausted");
    }

    #[test]
    fn zero_budget_denies_immediately() {
        let mut limiter = PacketEventLimiter::new(0, 1000);
        assert!(!limiter.allow(0));
        assert!(!limiter.allow(0));
    }

    #[test]
    fn window_partway_through_does_not_reset() {
        let mut limiter = PacketEventLimiter::new(1, 1000);
        assert!(limiter.allow(0));
        assert!(!limiter.allow(999), "still within the same 1000ms window");
    }
}
