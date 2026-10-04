# Current Task

## Objective

None active. JAM-16 (stream reassembly, #239) merged to `main` as `886d4b4` on 2026-10-04, after JAM-172 was fixed in #257. Epic JAM-130 stays open for two owner actions: JAM-187 and JAM-188.

## Queue (approved by James in chat, 2026-10-04)

1. JAM-182 `[P1]`: during replay, drive reassembly timers from the frames' capture timestamps, not wall-clock time. Gate `jam-182__replay-reassembly-clock` is awaiting approval.
2. JAM-183 `[P2]`: reset stream reassembly after a successful runtime interface switch. Gate `jam-183__reassembly-interface-reset` is awaiting approval.

## Other open follow-ups (not queued)

- Under JAM-16: JAM-167, JAM-168, JAM-170, JAM-173 (reassembly correctness and memory accounting).
- JAM-174: the replay snap-length truncation detector never fires.
- JAM-184: per-launch token on the agent control socket (a wire change).
- JAM-185: `osi-mon` prints made-up metrics.
- JAM-186: the `~` path example in `docs/usage.md` doesn't work.
- JAM-187 and JAM-188 (JAM-130): owner checks in Settings → Code security, then a note in `CONTRIBUTING.md`.

See `HANDOFF.md` for details.
