/// Caps how many discrete `AgentEvent::Packet` events go out per unit time,
/// independent of how many packets are actually captured. Flow/layer
/// aggregates (`FlowTable::observe`) still see every packet — this only
/// gates the per-packet event sent to the browser, which the UI truncates to
/// its last 100 entries anyway (`app/page.tsx`'s `prev.slice(0, 100)`).
///
/// Admits at most one event every `window_ms / max_per_window` milliseconds,
/// spacing allowed events evenly across the window instead of admitting the
/// first `max_per_window` packets of each window and then blocking the rest.
/// The latter (head-of-window truncation) makes the sampled stream
/// unrepresentative — e.g. on a 10k pps link, "the last 100 packets of every
/// second" would really mean "the first ~10ms of every second, and nothing
/// from the remaining 990ms". A minimum-interval throttle also avoids the
/// fixed-window artifact where up to `2 * max_per_window` events could land
/// in a rolling window straddling a window boundary.
///
/// Takes an explicit `now_ms` (mirroring `flow.rs`) instead of calling
/// `Instant::now()` internally, so it stays deterministic and unit-testable
/// without sleeping.
pub struct PacketEventLimiter {
    /// `None` means the budget is zero: never allow.
    min_interval_ms: Option<u64>,
    last_allowed_ms: Option<u64>,
}

impl PacketEventLimiter {
    pub fn new(max_per_window: u32, window_ms: u64) -> Self {
        let min_interval_ms = if max_per_window == 0 {
            None
        } else {
            Some(window_ms / max_per_window as u64)
        };
        Self {
            min_interval_ms,
            last_allowed_ms: None,
        }
    }

    /// Call once per candidate emission with the same `now_ms` clock main.rs
    /// already derives from `start.elapsed()`. Returns true if this packet's
    /// event should be sent, false if it arrived before the next allowed
    /// slot.
    pub fn allow(&mut self, now_ms: u64) -> bool {
        let Some(min_interval_ms) = self.min_interval_ms else {
            return false;
        };
        let due = match self.last_allowed_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= min_interval_ms,
        };
        if due {
            self.last_allowed_ms = Some(now_ms);
        }
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_is_allowed_and_an_immediate_second_call_is_denied() {
        let mut limiter = PacketEventLimiter::new(3, 1000);
        assert!(limiter.allow(0));
        assert!(!limiter.allow(10), "10ms since last allow is well under the ~333ms interval");
    }

    #[test]
    fn zero_budget_denies_immediately() {
        let mut limiter = PacketEventLimiter::new(0, 1000);
        assert!(!limiter.allow(0));
        assert!(!limiter.allow(1000));
    }

    #[test]
    fn spaces_events_evenly_by_the_computed_interval() {
        // budget of 2 per 1000ms => admit at most one every 500ms.
        let mut limiter = PacketEventLimiter::new(2, 1000);
        assert!(limiter.allow(0), "first call is always allowed");
        assert!(!limiter.allow(400), "400ms since last allow is < the 500ms interval");
        assert!(limiter.allow(500), "500ms since last allow meets the interval");
        assert!(!limiter.allow(999), "499ms since last allow is < the 500ms interval");
        assert!(limiter.allow(1000), "500ms since last allow meets the interval");
    }

    #[test]
    fn spreads_a_burst_across_the_full_window_instead_of_only_the_start() {
        // budget of 100 per 1000ms => interval of 10ms. Feed one candidate
        // packet per millisecond for a full second (1000 calls) and confirm
        // the allowed events land throughout the window, not only in the
        // first ~10ms — the defect the fixed-window counter had.
        let mut limiter = PacketEventLimiter::new(100, 1000);
        let mut allowed_at = Vec::new();
        for now_ms in 0..1000u64 {
            if limiter.allow(now_ms) {
                allowed_at.push(now_ms);
            }
        }

        // Budget matches: exactly max_per_window admits per window.
        assert_eq!(allowed_at.len(), 100);
        // Not head-of-window truncation: the last allowed event is near the
        // end of the window, not clustered at the start.
        assert!(
            *allowed_at.last().unwrap() >= 900,
            "expected allowed events spread across the full window, last was at {:?}",
            allowed_at.last()
        );
        // Every allowed event is spaced by (approximately) the interval —
        // no two allowed events are closer together than the interval.
        for pair in allowed_at.windows(2) {
            assert!(pair[1] - pair[0] >= 10, "events {:?} closer than the 10ms interval", pair);
        }
    }
}
