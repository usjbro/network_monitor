# Test Status

## JAM-174 — verified 2026-10-05

Commands ran in `.worktrees/replay-capture-truncation/capture-agent`.

| Command | Result |
|---|---|
| Baseline `cargo test --locked` | Passed before edits. |
| Pre-fix `cargo test --locked --test replay_truncation` | Failed as expected: small-snaplen pcapng replay emitted 0 warnings, expected 1. |
| `cargo test --locked` | 392 passed, 5 ignored (existing 1 reassembly + 3 live-loopback, and new opt-in binary replay). Includes real-file pcap/pcapng source metadata and truncation count tests, boundary original lengths, and TCP gap attribution. |
| `cargo build --release --locked` | Passed. |
| `cargo clippy --all-targets --locked -- -D warnings` | Passed after all test additions. |
| `cargo +nightly fuzz run pcapng_reader -- -max_total_time=40` | Passed: 1,403,207 executions in 41s. |
| `cargo +nightly fuzz run pcapng_reader /private/tmp/jam174-pcapng-corpus -- -max_total_time=30` | Passed: 1,094,427 executions in 31s, seeded with valid EPBs and original lengths 0/4/128/u32::MAX. |
| `git diff --check` | Passed. |
| Earlier post-fix binary replay attempts | NOT a pass: sandbox denied loopback bind; unsandboxed retry found port 9990 occupied by PID 94514. Truncation warning appeared, but replay did not finish. |

Final verification after James approved resuming on 2026-10-05:

- `cargo test --locked --test replay_truncation -- --ignored`: passed (one test, eight scenarios across pcapng/classic-pcap; actual binary startup, once-only warning, decodable/unparseable cuts, and no warning for complete frames).
- `cargo test --locked` rerun: 392 passed, 5 ignored.
- `cargo clippy --all-targets --locked -- -D warnings` rerun: passed.
- The old agent had already exited; no process needed to be stopped or restarted. Test child agents were cleaned up.
- A classic raw-IP fixture first reproduced a separate macOS DLT12/101 startup mapping failure, recorded on JAM-194. The final truncation fixtures declare Ethernet1 and use Ethernet frames; this test-only change passed independent review.

Publication checks rerun on 2026-10-05: release build, default suite (392 passed, 5 ignored), clippy and opt-in binary replay (eight scenarios) all passed. Independent security review found no introduced issues and reran three focused tests successfully.

Independent review: no remaining findings. No live capture exercised for this change.


# Security review fixes JAM-175 to JAM-179 — verified 2026-10-04

Each fix ran in its own `.worktrees/<slug>` worktree; changed tests failed before the fix and pass after.

| Issue / PR | Command | Result |
|---|---|---|
| JAM-175 / #247 | `cargo test --locked --test live_loopback -- --ignored --test-threads=1` (as root) | 3/3 passed; the new cross-protocol test failed against the unpatched loop (`start_capture_file` from an HTTP body ran). |
| JAM-175 / #247 | `cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo build --release --locked` | Passed (204 lib tests). |
| JAM-176 / #248 | `npx vitest run` + manual `next start` Host probes | 522 tests passed; a foreign Host got 421 on `/`, `/api/control`, `/api/stream`. |
| JAM-177 / #249 | `npx vitest run` | 504 tests passed. |
| JAM-178 / #250 | `npx vitest run` | 504 tests passed. |
| JAM-179 | `npx vitest run` | 509 tests passed. |
| all web PRs | `npm run lint`, `npx tsc --noEmit` | Passed. |

# JAM-27 — verified 2026-09-28

All local commands ran in `.worktrees/offline-name-resolution-mac-vendor-oui-lookup-and-port-service-names`.

| Command | Result |
|---|---|
| `npx vitest run lib/__tests__/mac-vendor.test.ts lib/__tests__/packet-stream-mac-vendor.test.tsx` | 3 targeted tests passed; resolver test asserts no `fetch` calls. |
| `npx vitest run` | 501 tests passed across 75 files. |
| `npx tsc --noEmit` | Passed. |
| `npm run lint` | Passed. |
| `cargo test --locked common_service_ports_are_named_without_network_lookups` | Passed. |
| `cargo test --locked` | Passed; privileged live-loopback tests are ignored by default. |
| `cargo clippy --all-targets --locked -- -D warnings` | Passed. |
| `cargo build --release --locked` | Passed. |
| `git diff --check` | Passed. |

## JAM-164 — verified 2026-09-28

All local commands ran in `.worktrees/live-pcap-per-packet-layer-field-is-hardcoded-to-4-breaking`.

| Command | Result |
|---|---|
| `cargo test --locked packet_osi_layer` | 2 targeted Rust tests passed. |
| `cargo test --locked` | Passed: 202 library tests, 53 binary tests, 6 integration tests; 2 privileged live-loopback tests ignored by default. |
| `cargo clippy --all-targets --locked -- -D warnings` | Passed. |
| `cargo build --release --locked` | Passed. |
| `npx vitest run lib/__tests__/packet-stream-layer-filter.test.tsx` | 1 component test passed. |
| `npx vitest run` | 498 tests passed across 73 files. |
| `npm run lint` | Passed. |
| `npx tsc --noEmit` | Passed. |
| `git diff --check` | Passed. |
| `codex review --uncommitted` and `codex review --commit 8257fca` | No actionable findings. |

PR #240's CI also passed Rust, Web, Playwright E2E, fuzz targets, and all CodeQL analyses. Verify the live checks again before merge.

## JAM-16 — verified 2026-09-28

2026-09-28, in `.worktrees/stream-reassembly-ip-fragments-and-tcp-segments` (branch `jamesmbrownjr/jam-16-stream-reassembly-ip-fragments-and-tcp-segments`, based on `main` at `3140d89d`), for JAM-16 (stream reassembly: IP fragments and TCP segments). Commands below were run twice independently — once by the implementing agent, once by the reviewing session — with matching results.

### Rust (`capture-agent/`)

| Command | Result |
| --- | --- |
| `cargo build --release --locked` | PASS — clean release build |
| `cargo test --locked` | PASS — 259 lib tests + 51 main-bin tests + 2 no_disk_write_invariant + 3 pcapng_roundtrip + 1 protocol_regression = 316 passing, 0 failed, 3 ignored (2 live_loopback need `CAP_NET_RAW`, 1 pre-existing) |
| `cargo clippy --all-targets --locked -- -D warnings` | PASS — zero warnings |
| `cargo +nightly fuzz run stream_reassembly -- -max_total_time=45` | PASS — two independent runs (421,330 and 199,510 executions), no crash, no cap-assertion failure |

New: `capture-agent/src/reassembly.rs` (IP fragment + TCP segment reassemblers, 38 tests), `capture-agent/fuzz/fuzz_targets/stream_reassembly.rs` (new fuzz target, wired into `.github/workflows/ci.yml`'s fuzz job and its path filter). Modified: `parse.rs` (+`ip_declared_payload_len`, `ip_fragment` fields, 7 new tests), `l7.rs` (desegmentation hand-off `sniff_l7_desegmenting`/`L7Sniff`, 11 new tests, plus a truncated-start-line fix to `sniff_http`/`sniff_http_response` — see Decisions/Handoff below), `flow.rs` (`FlowTable::key_for` made public), `fields.rs`/`main.rs` (wiring + snap-length-truncation attribution).

### TypeScript / Web

| Command | Result |
| --- | --- |
| `npx vitest run` | PASS — 72 files, 497/497 tests (no wire/type change — confirms no TS-visible regression) |

No `lib/types.ts` or `docs/wire-protocol.md` change; reassembly is internal to the capture agent (see spec's Deferred section for the wire-visible-status follow-up).

### Security Review

Manual review by the implementing agent (the `security-review` skill's own harness produced an empty diff in that context) plus the fuzz run above. Two robustness issues found and fixed during that review (an `unwrap_or` decoupled from its invariant; an unbounded printable-ASCII scan, now capped at 2048 bytes).

An independent security-review pass by the orchestrating session (on the actual pushed PR diff) then found a real, concrete Medium-High severity bug: `TcpStream::rebase`'s only guard was `shift > MAX_TCP_STREAM_BYTES`, not `shift + already-held bytes`, so a crafted backward-sequence segment could silently truncate away already-filled (first-seen) bytes and their `filled` markers — voiding the documented first-seen-wins guarantee for the truncated range, since a later segment could then write different content there without being counted as a conflict. Reproduced with a failing regression test first (`a_backward_shift_that_would_truncate_already_held_bytes_is_rejected_not_silently_evicted`), then fixed by checking `shift + stream.data.len()` against the cap instead of `shift` alone. Re-verified after the fix: full test suite green (316 passing, +1 for the regression test), clippy clean, fuzz re-run 45s / 179,169 executions with no crash.

### Known Limits

- Live capture against a real interface was not exercised for this task (no `CAP_NET_RAW` in this environment); reassembly correctness is established by the unit/fuzz suite, not a live run.
- A pre-existing, unrelated bug was found in the course of this work: `parse_packet` returns `None` (not a partial parse) for any frame shorter than its declared IP header length, so a narrowed `snaplen` currently causes affected frames to disappear entirely rather than show as truncated. Documented on `ReassemblyStatus` rather than silently assumed fixed; not in JAM-16's scope to fix the root cause. See task contract Handoff for tracker follow-up.

## JAM-166 — verified 2026-10-03

Fix for PR #239 review finding #2 (reconstructed transport identity lost for flow tracking), merged via PR #242 into the JAM-16 branch as commit `1dd1999`. Verified independently in `.worktrees/preserve-reconstructed-transport-identity` before merge (`cargo test --locked` 318 passed/0 failed/2 ignored, clippy clean).

## Post-rebase re-verification — 2026-10-03

Rebased the JAM-16 branch onto `main` at `539f055` to clear PR #239's merge conflict. The rebase produced a **clean-but-wrong merge** in `capture-agent/src/main.rs`'s `use capture_agent::{...}` block: it silently dropped the `l7` import (still needed by `packet_osi_layer`'s `l7::L7Info` reference) because this branch's own commit removed the only other usage (`l7::sniff_l7`, replaced by the reassembler) in the same import list, and `origin/main` had reordered that same hunk — `cargo build` failed with `error[E0433]: cannot find module or crate l7`, not a silent `git rebase` success. Fixed by re-adding `l7` to the import list; no other changes needed.

| Command | Result |
| --- | --- |
| `cargo build --release --locked` | PASS — clean release build |
| `cargo test --locked` | PASS — 261 lib + 53 main-bin + 0/2 ignored (live-loopback) + 2 no_disk_write + 3 pcapng + 1 protocol_regression = 320 passed, 0 failed, 3 ignored |
| `cargo clippy --all-targets --locked -- -D warnings` | PASS — zero warnings |

Remaining PR #239 review findings (JAM-169 `[P1]`, JAM-167/168/170 `[P2]`) are not yet fixed — see `HANDOFF.md`.
