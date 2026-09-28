# Current Task

## Objective

JAM-16: Stream reassembly — IP fragments (RFC 791 keying) and TCP segments (existing per-flow identity) — the next Todo child of epic JAM-127 in task order. Dependency (#68 / runtime snap-length control) was already shipped. Flagged in the issue as the epic's highest-risk item: attacker-controlled bytes, memory-exhaustion risk, required documented overlap policy, required new cargo-fuzz target.

## Verified Baseline

- Branch `jamesmbrownjr/jam-16-stream-reassembly-ip-fragments-and-tcp-segments`, worktree `.worktrees/stream-reassembly-ip-fragments-and-tcp-segments`, rebased onto `main` at `539f055` (includes JAM-14, JAM-164, JAM-27, and the gate-reclaim-timeout-removal PRs).
- Design spec written first, given the judgment calls involved (overlap policy, cap sizes, desegmentation interface shape): `docs/superpowers/specs/2026-09-28-stream-reassembly-design.md`.

## Scope and Acceptance Criteria

- [x] IP fragment reassembly, keyed on (src, dst, identification, protocol), with a bounded timeout.
- [x] TCP segment reassembly, keyed on the existing flow identity, handling out-of-order/overlap/retransmission per a documented policy (first-seen-bytes-win).
- [x] Desegmentation hand-off (`sniff_l7_desegmenting`/`L7Sniff`) so `l7.rs` can say "need more bytes" instead of silently failing; `sniff_l7`'s existing signature/behavior unchanged for all current callers.
- [x] Bounded and evictable: hard per-key and global byte/count caps on both reassemblers (8 MiB worst case combined), enforced inside `feed`, not just at eviction.
- [x] Reassembled buffers feed the existing L7 detectors with no change to their own parsing logic.
- [x] Three-way status (`reassembled` / `incomplete — frames truncated at capture` / `incomplete — frames missing`) rather than ever presenting a partial buffer as complete.
- [x] New `cargo-fuzz` target (`stream_reassembly`), run locally (two independent ~45s runs, no crash, cap assertions held), wired into CI.
- [x] Full Rust + TypeScript verification green (see `TEST_STATUS.md`).

## Constraints / Deliberate Scope Decisions

- No wire field added (`lib/types.ts`/`docs/wire-protocol.md` untouched) — reassembly correctness doesn't require a UI surface; deferred as a follow-up (see Handoff).
- `http2.rs`'s existing TLS-path reassembly, Follow Stream (JAM-17), UDP pseudo-streams/QUIC, and IPv6 fragment extension headers are all untouched/out of scope.
- IPv4-with-AH-extension fragments are explicitly not reassembled (narrow, documented refusal).
- `sniff_http`/`sniff_http_response` were tightened to require a *terminated* start line (previously a truncated `GET /index.h` with no line terminator decoded as a complete request for `/index.h`) — a deliberate, necessary precondition for the desegmentation hand-off to work, not a rewrite of the detectors' own logic. All pre-existing tests stayed green.

## Status

Implementation complete, pushed, PR #239 open. Independent review found 5 issues; all filed as sub-issues of JAM-16:

- JAM-166 `[P1]` reconstructed transport identity lost for flow tracking — **fixed, PR #242 merged into this branch** (commit `1dd1999`).
- JAM-169 `[P1]` TCP overlap policy bypassed by a standalone L7 decision on an already-held stream — not started.
- JAM-167 `[P2]` fragment-reassembled TCP bypasses stream reassembly — not started.
- JAM-168 `[P2]` reassembled L7 field offsets attached to wrong packet bytes — not started.
- JAM-170 `[P2]` memory cap accounting omits coverage-map storage — not started.

Branch rebased onto current `main` (`539f055`) on 2026-10-03 to resolve a merge conflict in PR #239 (only `.ai/` state-file conflicts; source merged cleanly). Remaining 4 findings must still be resolved before PR #239 can merge.
