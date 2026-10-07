# Current Task

JAM-203: derive replay finding timestamps and transaction expiry from capture time, not wall clock.

Worktree: `.worktrees/replay-capture-time-timestamps`; branch: `jamesmbrownjr/jam-203-p2-replay-derive-finding-timestamps-and-transaction-expiry-from`.

Scope: use capture timestamps for replay packet events and packet-triggered findings, and pass the already-correct capture-time transaction expiry timestamp into unanswered-finding emission. Code inspection confirms replay transaction matching and per-frame expiry already use capture timestamps; replay also skips the wall-clock timeout sweep. Preserve live packet stamping and its wall-clock idle timeout. Audit and classify remaining non-test `SystemTime::now()` / `Instant::now()` calls, and document timestamp meanings in `docs/wire-protocol.md`. `ReplayClock` outlier handling remains with JAM-190. Add regressions proving fast and realtime replay have identical packet/finding timestamps and transaction outcomes, and findings use the triggering frame's capture time.
