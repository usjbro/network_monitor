# Test Status

## Last Verified

2026-09-28, in `.worktrees/stream-reassembly-ip-fragments-and-tcp-segments` (branch `jamesmbrownjr/jam-16-stream-reassembly-ip-fragments-and-tcp-segments`, based on `main` at `3140d89d`), for JAM-16 (stream reassembly: IP fragments and TCP segments). Commands below were run twice independently — once by the implementing agent, once by the reviewing session — with matching results.

## Rust (`capture-agent/`)

| Command | Result |
| --- | --- |
| `cargo build --release --locked` | PASS — clean release build |
| `cargo test --locked` | PASS — 259 lib tests + 51 main-bin tests + 2 no_disk_write_invariant + 3 pcapng_roundtrip + 1 protocol_regression = 316 passing, 0 failed, 3 ignored (2 live_loopback need `CAP_NET_RAW`, 1 pre-existing) |
| `cargo clippy --all-targets --locked -- -D warnings` | PASS — zero warnings |
| `cargo +nightly fuzz run stream_reassembly -- -max_total_time=45` | PASS — two independent runs (421,330 and 199,510 executions), no crash, no cap-assertion failure |

New: `capture-agent/src/reassembly.rs` (IP fragment + TCP segment reassemblers, 38 tests), `capture-agent/fuzz/fuzz_targets/stream_reassembly.rs` (new fuzz target, wired into `.github/workflows/ci.yml`'s fuzz job and its path filter). Modified: `parse.rs` (+`ip_declared_payload_len`, `ip_fragment` fields, 7 new tests), `l7.rs` (desegmentation hand-off `sniff_l7_desegmenting`/`L7Sniff`, 11 new tests, plus a truncated-start-line fix to `sniff_http`/`sniff_http_response` — see Decisions/Handoff below), `flow.rs` (`FlowTable::key_for` made public), `fields.rs`/`main.rs` (wiring + snap-length-truncation attribution).

## TypeScript / Web

| Command | Result |
| --- | --- |
| `npx vitest run` | PASS — 72 files, 497/497 tests (no wire/type change — confirms no TS-visible regression) |

No `lib/types.ts` or `docs/wire-protocol.md` change; reassembly is internal to the capture agent (see spec's Deferred section for the wire-visible-status follow-up).

## Security Review

Manual review by the implementing agent (the `security-review` skill's own harness produced an empty diff in that context) plus the fuzz run above. Two robustness issues found and fixed during that review (an `unwrap_or` decoupled from its invariant; an unbounded printable-ASCII scan, now capped at 2048 bytes).

An independent security-review pass by the orchestrating session (on the actual pushed PR diff) then found a real, concrete Medium-High severity bug: `TcpStream::rebase`'s only guard was `shift > MAX_TCP_STREAM_BYTES`, not `shift + already-held bytes`, so a crafted backward-sequence segment could silently truncate away already-filled (first-seen) bytes and their `filled` markers — voiding the documented first-seen-wins guarantee for the truncated range, since a later segment could then write different content there without being counted as a conflict. Reproduced with a failing regression test first (`a_backward_shift_that_would_truncate_already_held_bytes_is_rejected_not_silently_evicted`), then fixed by checking `shift + stream.data.len()` against the cap instead of `shift` alone. Re-verified after the fix: full test suite green (316 passing, +1 for the regression test), clippy clean, fuzz re-run 45s / 179,169 executions with no crash.

## Known Limits

- Live capture against a real interface was not exercised for this task (no `CAP_NET_RAW` in this environment); reassembly correctness is established by the unit/fuzz suite, not a live run.
- A pre-existing, unrelated bug was found in the course of this work: `parse_packet` returns `None` (not a partial parse) for any frame shorter than its declared IP header length, so a narrowed `snaplen` currently causes affected frames to disappear entirely rather than show as truncated. Documented on `ReassemblyStatus` rather than silently assumed fixed; not in JAM-16's scope to fix the root cause. See task contract Handoff for tracker follow-up.
