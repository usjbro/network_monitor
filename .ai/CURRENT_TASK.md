# Current Task

## Objective

JAM-16: Stream reassembly — IP fragments (RFC 791 keying) and TCP segments (existing per-flow identity) — the next Todo child of epic JAM-127 in task order. Dependency (#68 / runtime snap-length control) was already shipped. Flagged in the issue as the epic's highest-risk item: attacker-controlled bytes, memory-exhaustion risk, required documented overlap policy, required new cargo-fuzz target.

## Verified Baseline

- Branch `jamesmbrownjr/jam-16-stream-reassembly-ip-fragments-and-tcp-segments`, worktree `.worktrees/stream-reassembly-ip-fragments-and-tcp-segments`, based on `main` at `3140d89d` (includes JAM-14 and the gate-reclaim-timeout-removal PRs).
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

Implementation complete and independently re-verified by the orchestrating session (build/test/clippy/TS suite reproduced with matching results). Not yet committed at the point this file was last written by the implementing agent — see `HANDOFF.md` for what happens next.
