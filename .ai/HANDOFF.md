# Session Handoff

## JAM-130 remaining issues (JAM-8, JAM-163, JAM-180, JAM-181) — 2026-10-04, merged

Worked JAM-130's open children under James's `/loop` in chat. Each PR had an independent review against source, and the review findings were fixed before merge. All four Linear issues are Done, and every JAM-130 child is now Done.

| PR | Merge | Issue | Change |
|---|---|---|---|
| #253 | `76ec774` | JAM-8 | `docs/security.md`: operator guidance on capture sensitivity, storage and the law (promiscuous mode, snap length, deletion, legal note), linked from `getting-started.md`. Corrected the old claim that ring rotation overwrites the oldest file: it never deletes any file. |
| #254 | `7650794` | JAM-163 | `CONTRIBUTING.md` names Linear as the task source of truth. `docs/wire-protocol.md` describes the real packet-event limiter (100/s, no burst), separately from aggregate accounting, and the per-code finding budgets. |
| #255 | `3afc68e` | JAM-180 | `ring duration` rotation measures from the current file's start. Before, it measured from run start, so it rotated every ~1 s after the first rotation. Found by the #253 review. |
| #256 | `6ac15a7` | JAM-181 | `validate_capture_file_path` rejects `..` and compares symlink-resolved paths, so a capture can't be placed inside the agent's working directory. Found by the #253 review. |

Open, for James to decide:
- Whether to close the JAM-130 epic. It's described as continuous, and its text still lists GitHub #67 (the `github-advanced-security` check), which isn't a Linear child.
- Unfiled: `docs/usage.md`'s `capture ~/captures/…` example doesn't work, because nothing expands `~`.

## Security review fixes (JAM-175 to JAM-179) — 2026-10-04, merged

A repo-wide review found two High and three Low issues. They were filed under JAM-130, fixed one PR each, and squash-merged in severity order. All five Linear issues are Done:

| PR | Merge | Issue | Fix |
|---|---|---|---|
| #247 | `fed1e1e` | JAM-175 | The agent's control socket closes a connection on its first non-JSON line, which blocks browser cross-protocol POSTs to `127.0.0.1:9990`. |
| #248 | `664472c` | JAM-176 | `middleware.ts` returns 421 unless `Host` is a loopback name or listed in `ALLOWED_HOSTS` (blocks DNS rebinding). Malformed entries are skipped with one warning. |
| #249 | `bbd7ed4` | JAM-177 | `/api/install` JSON-encodes the Host-derived origin in the generated script. |
| #250 | `8b444fc` | JAM-178 | `/api/enrichment/lookup` rejects cross-site requests. |
| #251 | `b0a866a` | JAM-179 | CSV export prefixes formula-like string cells with `'` and quotes them, and quotes fields that contain `;` or tab. |

Dependency audits were clean apart from the allowlisted lint-only `braces` advisory.

Operator impact: a step-5 LAN deployment that uses a real hostname must start the relay with `ALLOWED_HOSTS=<mac-hostname>.local`. Otherwise those requests get 421.

Follow-ups, not filed:
- A per-launch token on the agent socket. It's a wire change, and it would also stop other local processes from using the socket.
- The fake throughput and uptime figures that `/api/install`'s `osi-mon` prints.

## JAM-172 fix and JAM-16 merge — 2026-10-04

JAM-172 is fixed in #257 (squash `276ec80`, merged into this branch). A last fragment whose declared end conflicts with the group's known end, or ends before bytes already held, is dropped before any of it is written, and counted in `conflicting_terminal_fragments`. James approved merging #239 with JAM-167, JAM-168 and JAM-170 left as follow-ups. `main` was merged into this branch; only the `.ai/` notes conflicted.

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

## Review Findings and Resolution Status — 2026-10-03

PR #239's independent review found 5 issues required before merge, each filed as a Linear sub-issue of JAM-16:

- **JAM-166 `[P1]`** — reconstructed transport identity lost for flow tracking. **Fixed and merged** via PR #242 (squashed into this branch as commit `1dd1999`, verified independently: `cargo test --locked` 318 passed/0 failed, clippy clean).
- **JAM-169 `[P1]`** — TCP overlap policy can be bypassed by a standalone L7 decision on an already-held stream (`reassembly.rs:1029-1033` at review time). Not started.
- **JAM-167 `[P2]`** — IP-reassembled TCP segments bypass TCP stream reassembly (`reassembly.rs:999-1002`). Not started.
- **JAM-168 `[P2]`** — reassembled L7 field offsets attached to the wrong packet bytes (`main.rs:1611-1613`). Not started.
- **JAM-170 `[P2]`** — stated memory budget omits `filled: Vec<bool>` coverage-map storage (`reassembly.rs:770-772`). Not started.
- **JAM-172 `[P1]`** — found on a second independent review pass (2026-10-03), not part of the original 5: `IpFragmentReassembler::feed` unconditionally overwrites `group.total_len` on any fragment with `more_fragments=false` (`reassembly.rs:441-448`), with no first-seen-wins protection on that field. A single forged last-fragment packet can retroactively truncate an already-buffered datagram to an attacker-chosen length (`take_group` emits `prefix_len.min(total)`) — the same evasion class the data-byte overlap policy defends against, except this field isn't covered by it. Verified directly against the code, not just the subagent's report. **Fixed in #257 (`276ec80`).**
- **JAM-169 `[P1]`** — **fixed and merged** via PR #246 (3 commits squashed onto this branch): `StreamReassembler::sniff`'s standalone-decision fast path now only fires when `TcpReassembler::has_buffer` (entry existence, not `!finished`) reports no buffer at all. Two further gaps were found and fixed during two independent review rounds on that PR itself: (1) a `finished`-but-not-yet-released stream (hit cap) still has real `data`, so checking `!finished` alone reopened the bypass — fixed by checking entry existence; (2) that fix then caused a *new* regression — `feed()` released a finished stream's buffer in place without removing the entry, so a busy, long-lived connection's `has_buffer` kept reporting true forever (idle eviction never fires on live traffic), permanently blinding that direction to all future decisions after any single cap/timeout event — fixed by having `feed()` remove the entry outright on the finished branch. Two novel, non-blocking findings from the same review rounds filed separately: JAM-173 (fragment-completing packet event shows contradictory layer/protocol fields) and JAM-174 (snap-length truncation detector dead during replay, pre-existing).

A separate, already-fixed finding (TCP `rebase()` truncation, commit `1b925ab`) predates this list and is not one of the 5 (now 6, with JAM-172).

Branch rebased onto `main` at `539f055` on 2026-10-03 to clear PR #239's merge conflict — `.ai/` state-file conflicts (resolved by keeping this branch's own entries). `capture-agent/src/main.rs` auto-merged **without a CONFLICT marker but produced broken code**: the `use capture_agent::{...}` import list silently lost its `l7` import (still needed by `packet_osi_layer`), caught by `cargo build` (`error[E0433]`), not by git. Fixed by re-adding `l7` to the import list; re-verified clean (see `TEST_STATUS.md`'s "Post-rebase re-verification" entry — 320 passed, 0 failed, clippy clean). Don't trust a rebase/merge that reports success for a file touched by multiple commits without rebuilding.

## Publication and Continuation

PR #239 is open. Do not merge until JAM-169/167/168/170 are resolved (JAM-169 is the highest-severity remaining item — a documented security guarantee, first-seen-bytes-win, that can currently be silently bypassed). Push the rebase (`git push --force-with-lease`, safe since nothing unmerged is lost — the only non-rebased commits were already squash-merged via #242) before further work. Independent code-review and security-review passes run before merge, per this repo's standing convention.

## Known Limits and Follow-ups

- Live capture against a real interface was not exercised (no `CAP_NET_RAW` in this environment).
- Wire-visible reassembly status (a `reassembly-incomplete` finding code) is deliberately deferred — needs the Rust + TS + docs + both-sides-test treatment this repo requires for any wire change.
- The `parse_packet`-truncation bug above needs its own tracked follow-up if JAM-165 (already filed, blocked on this task) doesn't fully cover it once re-diagnosed post-merge.

## JAM-166 Follow-on — Reconstructed Flow Attribution

JAM-166 adds the parsed transport packet to `SniffOutcome` when an IP fragment group completes. The capture loop now calls `FlowTable::observe_reassembled`: each physical fragment contributes once to the protocol hierarchy, while the completed TCP/UDP datagram contributes once to its correctly keyed flow and L7 classification. The packet event and capture-file writer continue to use the original captured frame. Regression coverage verifies two physical fragments are counted as two frames while the flow and endpoint rollup count one reconstructed datagram. Full verification on the child branch based on PR #239 head `1b925abd`: `cargo test --locked` (318 passed, 2 live-loopback ignored), clippy clean, release build clean; independent Codex review found no actionable regressions. The child PR targets the PR #239 branch, and JAM-166 remains a blocker until that fix is integrated.
