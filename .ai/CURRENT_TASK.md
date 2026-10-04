# Current Task

## Objective

JAM-15 (epic JAM-127): DNS and HTTP/1.x request/response matching, service response time, `unanswered-request` findings and a per-protocol latency summary. Taken over from Codex at James's direct instruction on 2026-10-04. Codex's 2026-09-28 claim was never pushed. Branch `jamesmbrownjr/jam-15-dns-http-service-time`. Spec: `docs/superpowers/specs/2026-10-04-service-response-time-design.md`.

The previous queue (JAM-182, JAM-183) and JAM-187/JAM-188 have merged (#260, #261, #259).

## Other open follow-ups (not queued)

- Under JAM-16: JAM-167, JAM-168, JAM-170, JAM-173 (reassembly correctness and memory accounting).
- JAM-174: the replay snap-length truncation detector never fires.
- JAM-184: per-launch token on the agent control socket (a wire change).
- JAM-185: `osi-mon` prints made-up metrics.
- JAM-186: the `~` path example in `docs/usage.md` doesn't work.
- JAM-127 children still Todo: JAM-17, JAM-18, JAM-19, JAM-20, JAM-162, JAM-165.

See `HANDOFF.md` for details.
