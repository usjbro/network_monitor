# Session Handoff

## Verified State — 2026-09-28

JAM-16 (stream reassembly: IP fragments and TCP segments) was dispatched to an Opus-backed agent given its security-sensitive-design profile (this repo's own Model Routing guidance). It wrote a design spec, implemented both reassemblers, ran its own security review (found and fixed two robustness issues), and verified build/test/clippy/fuzz/TS locally — all real command output, reproduced independently by the orchestrating session with matching results (see `TEST_STATUS.md`).

## What Shipped

- `capture-agent/src/reassembly.rs` (new): `FragmentReassembler` (IP, keyed on src/dst/id/protocol) and `StreamReassembler` (TCP, keyed on the flow table's own `FlowKey` + direction via newly-public `FlowTable::key_for`). Overlap policy: first-seen-bytes-win (documented security rationale: prevents an attacker from retroactively rewriting bytes already reported). Caps: 8 MiB worst case combined; enforced inside `feed`, not only at eviction.
- `capture-agent/src/l7.rs`: `sniff_l7_desegmenting`/`L7Sniff` (Decided/NeedMoreBytes/Undecided) alongside the unchanged `sniff_l7`. `sniff_http`/`sniff_http_response` now require a terminated start line — fixes a real bug where a truncated request line (e.g. `GET /index.h` with no segment boundary yet) decoded as a complete, wrong request.
- `capture-agent/src/parse.rs`: two new internal `ParsedPacket` fields (`ip_declared_payload_len`, `ip_fragment`) — no wire exposure.
- `capture-agent/fuzz/fuzz_targets/stream_reassembly.rs` (new) + CI wiring (`.github/workflows/ci.yml`, hand-listed fuzz steps + path filter).
- `docs/superpowers/specs/2026-09-28-stream-reassembly-design.md`: the reviewable record of the overlap-policy, cap-size, and desegmentation-interface decisions.

## Two Real Bugs Found While Implementing (Not JAM-16's Own Scope)

1. **`parse_packet` silently drops any frame shorter than its declared IP header length** — meaning a narrowed `snaplen` today makes affected frames disappear entirely rather than show as truncated, so JAM-16's `incomplete — frames truncated at capture` status is correct-but-currently-unreachable from the live capture loop for that specific case (it does fire via a separate signal: the capture loop knows when pcap itself cut a frame at the active snap length, and attributes gaps to that for 5s). Root-causing this needs a separate, larger change to how `parse_packet` handles truncation, with its own wire-surface questions. This is direct, concrete evidence for **JAM-165** ("confirm whether JAM-16 explains the climbing 'frames could not be parsed' counter"), already filed and blocked on this task — added as a comment there rather than filing a duplicate issue.
2. Fixed directly as part of this task (not filed separately, since it's a precondition for the desegmentation hand-off): the truncated-start-line detector bug above.

## Independent Verification (Orchestrating Session)

Reproduced, not just trusted: `cargo build --release --locked`, `cargo test --locked` (315 passing, matches reported counts exactly), `cargo clippy --all-targets --locked -- -D warnings` (clean), `npx vitest run` (497/497). Spot-checked `first_complete_line`/`unterminated_http_start_line` in `l7.rs` directly — bounded (2048-byte probe cap), no panics, correct method-token-boundary handling. Read the full design spec.

## Publication and Continuation

Committing, pushing, and opening the PR from here (the implementing agent was cut off twice — once by a rate limit, once by a handback-enforcement limit — before reaching these steps; all code was already correct and verified, nothing was redone). Independent code-review and security-review passes run before merge, per this repo's standing convention (self-review misses real things). Check the PR on GitHub before continuing: if open, resolve any review/CI findings and merge only when `mergeable_state: clean`; if merged, this task is complete.

## Known Limits and Follow-ups

- Live capture against a real interface was not exercised (no `CAP_NET_RAW` in this environment).
- Wire-visible reassembly status (a `reassembly-incomplete` finding code) is deliberately deferred — needs the Rust + TS + docs + both-sides-test treatment this repo requires for any wire change.
- The `parse_packet`-truncation bug above needs its own tracked follow-up if JAM-165 (already filed, blocked on this task) doesn't fully cover it once re-diagnosed post-merge.

## JAM-166 Follow-on — Reconstructed Flow Attribution

JAM-166 adds the parsed transport packet to `SniffOutcome` when an IP fragment group completes. The capture loop now calls `FlowTable::observe_reassembled`: each physical fragment contributes once to the protocol hierarchy, while the completed TCP/UDP datagram contributes once to its correctly keyed flow and L7 classification. The packet event and capture-file writer continue to use the original captured frame. Regression coverage verifies two physical fragments are counted as two frames while the flow and endpoint rollup count one reconstructed datagram. Full verification on the child branch based on PR #239 head `1b925abd`: `cargo test --locked` (318 passed, 2 live-loopback ignored), clippy clean, release build clean; independent Codex review found no actionable regressions. The child PR targets the PR #239 branch, and JAM-166 remains a blocker until that fix is integrated.
