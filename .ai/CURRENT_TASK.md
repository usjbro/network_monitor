# Current Task

## Objective

JAM-185: `osi-mon` (written by `/api/install`) printed hardcoded per-layer "Gbps" figures, `Math.random()` throughput and a constant uptime. It now reads `/api/stream` and prints only what the agent reports. Branch `jamesmbrownjr/jam-185-osi-mon-no-made-up-metrics`.

JAM-15 merged as `e04403e` (PR #262). The 2026-10-04 Linear triage set the order: JAM-185, JAM-184, then the JAM-16 follow-ups (JAM-170, JAM-167, JAM-189, JAM-168, JAM-173), JAM-193, then the JAM-17 spec.

## Other open follow-ups

- Under JAM-16: JAM-167, JAM-168, JAM-170, JAM-173 (reassembly correctness and memory accounting).
- JAM-174: the replay snap-length truncation detector never fires.
- JAM-184: per-launch token on the agent control socket (a wire change).
- JAM-186: the `~` path example in `docs/usage.md` doesn't work.
- JAM-127 children still Todo: JAM-17, JAM-18, JAM-19, JAM-20, JAM-162, JAM-165.

See `HANDOFF.md` for details.
