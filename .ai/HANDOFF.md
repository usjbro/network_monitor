# JAM-250 — CI job timeouts and bounded apt retries

Active work in `.worktrees/ci-job-timeouts-apt-retry` on `jamesmbrownjr/jam-250-p3-ci-add-job-timeouts-and-an-apt-get-retry-so-a-hung-runner`. Gate is approved, claimed, and delegated in-session; Linear is In Progress. Added evidence-based job timeouts, bounded apt retries, and the main-branch infrastructure-failure policy. The temporary unreachable-mirror acceptance check (run 37806849918) logged attempts 1/3, 2/3, and 3/3, then failed as expected in about 24 seconds. Its test-only change is reverted in commit `77542d3`. Final PR checks must pass on the restored head; do not treat the intentional probe failure as a product failure. Historical cancelled run 37677784244 does not need rerunning because current main is green. No workflow test scope or trigger changes.

# JAM-168 — reassembled L7 field offsets

Implementation is ready for PR in `.worktrees/p2-keep-reassembled-l7-field-offsets-tied-to-packet-bytes` on `jamesmbrownjr/jam-168-p2-keep-reassembled-l7-field-offsets-tied-to-packet-bytes`. The capture loop now calls `fields::build_packet_fields`, which preserves decoded packet/header fields but suppresses application byte ranges when the L7 result came from reassembly. Regression tests cover a split ClientHello (no invalid SNI range) and an unsplit ClientHello (SNI range still points to `example.com`). Full Rust tests, strict Clippy, release build, diff check, and independent Codex review passed. `cargo fmt --check` reports existing formatting across unrelated files; no broad reformat was retained. PR #277 is open and attached to JAM-168, which is In Review. Cross-review was requested in the task Slack thread; CI is pending. Wait for clean checks and reviewer approval before squash merge.

# JAM-204 — TLS 1.3 record-layer implementation verified locally, 2026-10-07

Implementation and local verification are complete in `.worktrees/tls-decrypt-record-layer` on `jamesmbrownjr/jam-204-tls-decrypt-record-layer`. Added bounded per-direction TCP/TLS framing, handshake parsing and epoch/sequence transitions, bounded early-data trials and late-key waiting, PID-scoped zeroizing key-log secrets, directional HTTP/2 state and decrypted ring tags, additive decryption status events, protocol/security documentation, regression tests, and a `tls_record_stream` fuzz target. Review findings on snaplen propagation, timer expiry, cleartext Finished, retransmissions, HPACK allocation zeroization/accounting, parser termination/desynchronization cleanup, and malformed decode temporaries have been addressed. Full Rust tests (serialized due an existing fixture-name collision), standalone HPACK tests (59 unit/6 doc), single-worker Vitest (82 files/602 tests), lint, release build, warnings-denied Clippy, targeted rustfmt and the prior 1,000-run fuzz smoke passed; see `TEST_STATUS.md`. CI initially found three outdated TypeScript test fixtures missing the new direction field; `07ac312` fixes them and local `npx tsc --noEmit` plus the focused four-test Vitest file pass. GitHub CodeQL subsequently flagged the nonce test's fixed IV fixture, not production key handling; the deterministic test now generates its bytes at runtime and the focused Rust test passes. Latest CI and review rerun are pending. Nine default Rust tests remain environment-gated (live capture privileges or exclusive port 9990).

Next: complete final independent re-review, refresh `git diff --check`, then prepare the PR and tracker handoff. No PR has been opened yet.

# JAM-189 — replay flow-aging clock implemented, 2026-10-06

Worktree: `.worktrees/flow-table-replay-clock`; branch: `jamesmbrownjr/jam-189-p2-flow-table-ages-flows-on-wall-clock-time-during-replay`. The capture loop now feeds replay-clock milliseconds to replay flow observation, and the periodic emitter reads the latest replay timestamp for idle eviction and flow snapshots. The replay observe path expires only the matching stale tuple on arrival in O(1), returning its close ID for a `connection_closed` event; this handles fast replay that processes both connections before a periodic tick. Live mode continues to use agent elapsed time and its existing periodic-only expiry behavior, including during quiet capture; emitter scheduling remains wall-clock driven.

Clock choice: packet/finding rate limiters and packet-event `relative_time_ms` remain on agent elapsed time. This preserves real-time throttling during fast replay and existing UI-relative packet timeline behavior. Flow duration/age/snapshot math follows traffic time as required. The design spec records that replay EOF leaves final flows visible until the running agent is restarted; corrupt far-future timestamp handling remains the separate JAM-190 follow-up.

Regression tests cover UDP tuple reuse after 60.001 seconds of replay time before any periodic sweep (old flow evicted, close id returned, second flow observed) and confirm live observation still relies on the periodic sweep. Release build, full default `cargo test --locked`, and warnings-denied Clippy pass. Crate-wide rustfmt check reports substantial existing differences in untouched files, so formatting was not run across the crate. See TEST_STATUS.md for full results.

Independent pre-PR review found the fragment-result propagation concern (the physical-fragment case is unreachable with the parser's no-ports representation), a single-future-timestamp clock issue, and the stale main base. The fragment-result concern is unreachable with current parser output (fragment packets have no transport ports). A proposed >24-hour confirmation guard was rejected after review showed it corrupts valid long-gap replay; corrupt far-future timestamp handling is explicitly out of scope for JAM-189 and tracked by JAM-190. A fresh Codex review found a snapshot race between replay-clock publication and flow counter updates. `with_flow_observation` now publishes the clock under the flow-table mutex, and the emitter reads it under that mutex; the flow-aging regression exercises this path. Branch is rebased onto PR #271/#272 current main; full Rust tests, release build, and Clippy pass. EOF persistence is documented, and the main-loop composition was checked beside JAM-167. PR #273 needs this fix pushed, CI rerun, and reviewer recheck before merge. The full JAM-189 Slack thread was read. Gate claimed and delegated in-session after James's direct chat approval. No wire/API changes.

---

# JAM-167 — implementation underway, verified locally, 2026-10-06

Claimed and started in `.worktrees/feed-fragment-reassembled-tcp` on `jamesmbrownjr/jam-167-p2-feed-fragment-reassembled-tcp-through-stream-reassembly`. Reconstructed TCP datagrams now resolve their flow key through the capture loop's `FlowTable::key_for` and pass through the existing sequence-aware TCP reassembler; original fragment packet and flow accounting are retained. Added a regression for an HTTP request line split between a fragment-reassembled TCP segment and a later ordinary segment, plus the design-spec note.

The regression was observed failing before implementation and passing after. `cargo test --locked` (422 passed, 8 ignored), release build and strict Clippy pass. Repository-wide rustfmt check reports existing differences across untouched files; no formatter is enforced in CI. Local `codex review --uncommitted` found no actionable regressions and checked both fragment arrival orders. No commit or PR yet; complete the security-focused review before publication.

# JAM-189 — end-to-end replay-aging coverage, 2026-10-07

In `.worktrees/flow-table-replay-clock` on the existing PR #273 branch, added an opt-in authenticated binary replay test. It generates a classic-pcap with two equal UDP tuples 61 seconds apart and verifies a periodic connection snapshot observed after replay EOF reports only the second packet's bytes. The fixed-port replay tests share a mutex so Cargo's default parallel runner cannot race them. A negative-control run with replay observation temporarily changed to the live path failed with 142 bytes instead of 71; the production code was restored.

Verified: both ignored `replay_compatibility` integration tests passed; `cargo test --locked` passed (339 library, 67 binary, 12 control-auth, 2 disk-invariant, 4 pcapng, 1 protocol-regression; 8 ignored); release build and warnings-denied Clippy passed. The test is ignored by default because it needs exclusive `127.0.0.1:9990`. Change is currently uncommitted and not yet included in PR #273.

# JAM-184 — review fix verified, publication next, 2026-10-05

James invoked epic-task-cycle JAM-184 and approved BOTH feed/controls, the revised spec, implementation plan and Native execution directly in this session. Existing gate is approved/delegated; Linear In Progress. All edits remain in `.worktrees/capture-agent-control-token` on `jamesmbrownjr/jam-184-authenticate-the-capture-agent-control-socket-with-a-per`.

Implemented private random per-launch credentials, directory-FD publication after bind, bounded authentication/ACK before subscription/control dispatch, separate 16-pending/64-authenticated caps, relay auth-first/reconnect rotation and safe lifecycle reset. Test doubles and actual live/replay observers authenticate using isolated private token files. Updated protocol/security/setup/troubleshooting/architecture docs. No dependencies, binds, deployment or TLS opt-in changes. Relay HTTP auth remains JAM-196.

Validation: default Rust 419 passed/8 ignored; all five live-loopback tests passed; binary replay compatibility (3 scenarios) and truncation (8 scenarios) passed. Release build/clippy passed. Vitest 600 passed; typecheck/lint/build passed; authenticated Playwright smoke passed. Rust dependency audit clean (isolated cargo-audit CLI installed in /private/tmp); npm audit only the existing allowlisted lint-only braces advisory. See TEST_STATUS.md for commands, red evidence and limitations.

James approved temporarily stopping the main-checkout release agent PID73161. Original process used en0, capturing:true, no file recording, filter:null, snaplen65535. It was restored using the same original binary/cwd and saved launch settings as PID18299; startup/port verified. Temporary stop/restart authorization was exercised only for the live/replay tests; the original agent is running again. Test-only live interface selection fixed to macOS lo0/Linux lo after actual macOS failures; production interface behavior unchanged.

Plan/ledger: `docs/superpowers/plans/2026-10-05-agent-control-authentication.md`; `.superpowers/sdd/2026-10-05-agent-control-authentication/progress.md`. Task 1 e9b746f, Task 2 a1e1ec1, Task 3 4410450. Task 4 fixture/docs and verification ready; independent whole-branch review completed; an Important raw loopback capture leak was fixed before publication. Unit full/split-auth and fragment exclusions plus actual raw-recording regression were observed RED→GREEN; full Rust/live/replay/TS suites and release/clippy passed afterward. Conservative omission applies only to live IPv4 loopback control traffic and unclassifiable TCP fragments involving 127.0.0.1; replay is preserved. Publication/CI/published review and merge remain. No PR yet. Keep unrelated worktrees and operator token files untouched.

Claude Code branch review reported five low observations. Deferred separate connect-error diagnostics and bounded agent-side rejection telemetry; retained the approved 5-second admission deadline. Node documentation already states its narrower file-FD validation; E2E intentionally fails on occupied port3100 rather than reuse an operator server. Published Claude Code code/security review and cloud Codex review covered the final privacy fix: no blockers. Corrected the low regeneration-recipe finding and clarified signal-termination stale-file cleanup; diagnostic enhancements remain deferred. PR #266 is open; consult GitHub/Linear for final publication state. Consult GitHub/Linear for publication state.

Previous handoff follows.

---

# JAM-194 — 2026-10-05

Approved scope implemented in `.worktrees/third-party-pcapng-replay`, branch `jamesmbrownjr/jam-194-p2-pcapng-replay-rejects-valid-third-party-blocks-sections`, based on JAM-174 merge5399704.

Reader now honors section byte order/version, section-local interfaces and per-packet link type/timestamp units; skips validated unknown/nonpacket blocks; rejects unsupported packet blocks explicitly. Replay read failures have distinct diagnostics; native RAW datalink identity maps correctly. Writer, wire, dependencies and TLS ingestion unchanged. Embedded DSB secrets are ignored.

Validation: 405 default Rust tests passed,6ignored; release/clippy clean; opt-in binary tests passed all3compatibility+8truncation scenarios; seeded reader fuzz1,150,653runs/41s clean; independent code/security review clean. Negative binary control caught wrong interface decoding before restoration. See TEST_STATUS.md and approved implementation plan for commands and limitations.

James invoked epic-task-cycle and approved the scope directly in chat, authorizing publication through PR/CI/merge. Consult GitHub/Linear for the publication state. Offset/FCS/interface-address fallback remain follow-ups; no next issue is claimed.

Historical handoff follows.

---

# JAM-174 — 2026-10-05

Worktree: `.worktrees/replay-capture-truncation`; branch: `jamesmbrownjr/jam-174-snap-length-truncation-detector-is-dead-during-pcappcapng`. Implementation is verified. James approved this scope directly in chat; the local gate is approved/delegated.

- `pcapng::ParsedPacket` preserves EPB original length; live/classic libpcap sources preserve `packet.header.len` in `SourceFrame`.
- `note_capture_truncation` checks actual captured bytes < original length before parsing, counts each cut, and preserves reassembly gap attribution. Complete packets at snaplen do not trigger.
- New real-file source tests and gap-attribution tests run by default; opt-in binary replay regression covers both formats, unparseable/decodable cuts, complete frames and warning latching. Fixtures live in `tests/fixtures/replay_capture.rs`.
- `cargo test --locked`: 392 passed, 5 ignored. Release build, warnings-denied clippy, and 40s + seeded 30s reader fuzz checks passed. Independent review's only finding (fixed-port dependency in default tests) was fixed by making the binary test opt-in and adding socket-free source coverage.
- Final verification on 2026-10-05: `cargo test --locked --test replay_truncation -- --ignored` passed across eight classic-pcap/pcapng scenarios; default suite rerun: 392 passed, 5 ignored; clippy rerun clean. The default suite ignores the binary test because it needs exclusive port9990.
- James approved a temporary agent stop in chat; PID94514 had already exited, so no process was stopped or restarted. Binary tests clean up their own child agents.
- The initial raw-IP classic-pcap fixture exposed a separate macOS startup bug: system libpcap returns DLT_RAW12, but the crate's RAW constant is101. Recorded on JAM-194. JAM-174 now uses Ethernet fixtures for portable truncation tests; the test-only change passed independent review.
- Implementation and verification complete. James invoked `epic-task-cycle JAM-174` to authorize publication through commit, PR, CI and merge. Check Linear/GitHub for publication state.
- Independent security review before publication: no introduced findings; original length is scalar metadata, no new allocations/exposure/secrets behavior. Three focused tests rerun by reviewer passed.
- Reader compatibility remains JAM-194; no wire, writer, TLS or deployment changes.

The previous handoff below is historical and is not the current task.

---

# Session Handoff

## JAM-130 remaining issues (JAM-8, JAM-163, JAM-180, JAM-181) — 2026-10-04, merged

Worked JAM-130's open children under James's `/loop` in chat. Each PR had an independent review against source, and the review findings were fixed before merge. All four Linear issues are Done, and every JAM-130 child is now Done.

| PR | Merge | Issue | Change |
|---|---|---|---|
| #253 | `76ec774` | JAM-8 | `docs/security.md`: operator guidance on capture sensitivity, storage and the law (promiscuous mode, snap length, deletion, legal note), linked from `getting-started.md`. Corrected the old claim that ring rotation overwrites the oldest file: it never deletes any file. |
| #254 | `7650794` | JAM-163 | `CONTRIBUTING.md` names Linear as the task source of truth. `docs/wire-protocol.md` describes the real packet-event limiter (100/s, no burst), separately from aggregate accounting, and the per-code finding budgets. |
| #255 | `3afc68e` | JAM-180 | `ring duration` rotation measures from the current file's start. Before, it measured from run start, so it rotated every ~1 s after the first rotation. Found by the #253 review. |
| #256 | `6ac15a7` | JAM-181 | `validate_capture_file_path` rejects `..` and compares symlink-resolved paths, so a capture can't be placed inside the agent's working directory. Found by the #253 review. |

Decided by James on 2026-10-04:
- JAM-130 epic stays open. Two of its "Done when" items are unmet, and both are owner actions in repo Settings → Code security: JAM-187 (record the decision on the `github-advanced-security` check from GitHub #67, whose decision PR #106 was never merged) and JAM-188 (confirm and record the secret scanning and push protection state).
- Filed as JAM-186: `docs/usage.md`'s `capture ~/captures/…` example doesn't work, because nothing expands `~`.

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

Follow-ups, now filed: JAM-184 (a per-launch token on the agent socket) and JAM-185 (the fake throughput and uptime figures that `/api/install`'s `osi-mon` prints).

## JAM-172 fix and JAM-16 merge — 2026-10-04, merged

JAM-16 (#239) merged to `main` as `886d4b4`. CI passed on the PR head `cfc8c19` and on `main`. Two more Codex findings on #239 were confirmed in the merged code and filed under JAM-16: JAM-182 `[P1]` (replay reassembly uses wall-clock time) and JAM-183 `[P2]` (an interface switch doesn't reset reassembly). JAM-130 stays open for JAM-187 and JAM-188. New issues: JAM-184 (agent socket token), JAM-185 (`osi-mon` made-up metrics) and JAM-186 (`~` in `docs/usage.md`).


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

## JAM-193 — Capture-file rejection UI

Implemented in `.worktrees/p2-capture_file_error-sse-event-has-no-ui-handler-rejected` on `jamesmbrownjr/jam-193-p2-capture_file_error-sse-event-has-no-ui-handler-rejected`. The page now consumes the existing `capture_file_error` SSE event and displays its rejection message in a dismissible banner. A new `start_capture_file` request clears a previous rejection so a retry does not leave stale error UI; a fresh error event displays again. Tests cover rejected start, malformed non-string message, display, retry, repeat rejection and dismissal. No wire/agent changes.

Verified: focused Vitest 12/12; full Vitest 82 files / 601 tests; `npm run lint`; `npm run build`; `git diff --check`. One intermediate full Vitest run hit existing timing-related teardown errors in unrelated enrichment tests; rerunning the standard suite passed all 601 tests. PR #268 CI passed before this final retry refinement; a refreshed CI run is required after the next push. Independent code/security reviews found no blocking issue. James declined Chrome automation and said he can perform the required real-browser check; merge is waiting for that result. The final build after rebase showed the existing middleware deprecation warning.

## JAM-170 — reassembly coverage accounting

Implemented in `.worktrees/reassembly-coverage-memory-accounting` on `jamesmbrownjr/jam-170-p2-account-for-reassembly-coverage-storage-in-memory-limits`. The memory counter includes retained capacities of the data and coverage vectors; regression tests and fuzz checks verify aggregate and per-direction bounds. PR #269 is open. JAM-198 merged as PR #270 at `13695b5`, and the post-merge `main` CI run 37410349067 passed, resolving the npm-audit blocker. PR #269 is being updated to the new main base; its checks must pass again before merge.

## JAM-198 — npm audit source-map-js fix

Updated `.worktrees/npm-audit-source-map-js` on `jamesmbrownjr/jam-198-p1-ci-npm-audit-gate-fails-on-source-map-js-ghsa-68fv-2mgg`. `package-lock.json` now resolves `source-map-js` 1.2.2, the patched version for GHSA-68fv-2mgg-jv7q. No manifest range or application code change. Lockfile dependency paths include the root `postcss` and Next.js's nested `postcss`, in addition to development tooling; patching the transitive dependency is preferable to suppressing the advisory.

Verified the npm audit gate using `npm audit --json` plus `.github/scripts/check-npm-audit.mjs`: no `source-map-js` finding remains; the only reported high-severity item is the repository's pre-existing allowlisted GHSA-vfj7-8cjw-p6xm. `npm run lint`, `npm run build`, and `npx vitest run` passed (82 files, 601 tests). Build emitted the existing middleware and Edge Runtime warnings. PR and CI/review state are recorded in the coordination task contract.

## JAM-199 — sharp advisory

JAM-199 was implemented in `.worktrees/npm-audit-sharp` on `jamesmbrownjr/jam-199-p1-ci-npm-audit-gate-fails-on-sharp-ghsa-wq5f-xc86-pv6w-new` and merged as PR #272 (`b4744a8`). Next's existing optional `sharp` dependency now resolves to patched 0.35.5 via `^0.35.4`; no manifest or application-code change was needed. The audit gate, lint, build, all 601 Vitest tests, and PR checks passed. Codex and Claude Code reviews found no findings. Decision recorded: keep fixable high/critical advisories as immediate blockers; do not add a grace period. PR #271 is being updated to the merged main base and needs fresh CI.

## JAM-203 — replay finding timestamps

Implementation and focused/full Rust verification are complete in `.worktrees/replay-capture-time-timestamps`. Replay packet events and packet-triggered findings now use the source frame timestamp; unanswered findings use the expiry timestamp already passed by capture-time replay expiry. Live packet and idle-expiry behavior remain wall-clock based. JAM-190 still owns replay timer clamping. Relative time remains agent elapsed time.

Codex and Claude Code independently reviewed the uncommitted diff and found no blocking issues. Claude noted that a timestamp saturating at `u64::MAX` microseconds can expire all pending transactions; the conversion comment now records this extreme-value behavior and leaves timer hardening with JAM-190. The opt-in replay test asserts fast/realtime finding timestamps and transaction outcomes; only realtime emits the rate-limited target packet event, which is called out for the PR. The worktree is ready for commit and PR; it has not been merged.

## JAM-204 — TLS record-layer review fixes (2026-10-08)

PR #276 is open in `.worktrees/tls-decrypt-record-layer` on `jamesmbrownjr/jam-204-tls-decrypt-record-layer`. Actionable reviewer findings were fixed: plaintext sequence advancement now uses the length before zeroization; periodic key polling replays queued TLS records before expiry; retained ring allocations count against the aggregate TLS buffer budget and are zeroized on eviction; header strings are formatted in zeroizing storage; key-log polling is bounded and consumes only newline-terminated records; and handshake parsing caps messages at 64 KiB and compacts once while zeroing stale bytes. Review follow-up and the reason unused-key TTL remains monotonic wall time are in the implementation plan. Full Rust (serialized), vendored HPACK, full Vitest, TypeScript, lint, strict Clippy, release build, targeted rustfmt, and diff checks pass. Push these changes, request fresh PR/security review, then merge only after required checks and review gates are green. See `.ai/TEST_STATUS.md` for exact commands.
