# Session Handoff

## Security review fixes (JAM-175 to JAM-179) — 2026-10-04

A repo-wide review found two High and three Low issues, filed under JAM-130 and fixed one PR each: #247 (JAM-175, agent control socket closes on non-JSON lines, blocking browser cross-protocol POSTs), #248 (JAM-176, Host allowlist + `ALLOWED_HOSTS` against DNS rebinding), #249 (JAM-177, JSON-encoded origin in `/api/install`), #250 (JAM-178, cross-site guard on `/api/enrichment/lookup`), and this PR (JAM-179, CSV formula neutralisation). Dependency audits were clean apart from the allowlisted lint-only `braces` advisory.

Open follow-ups, not filed: a per-launch token on the agent socket (wire change, would also stop other local processes), and the fake metrics `/api/install`'s `osi-mon` prints. James merges each PR; mark the Linear issue Done when its PR merges.

## JAM-27 — 2026-09-28

Implemented an offline exact-prefix lookup using the checked-in IEEE MA-L snapshot (`lib/data/ieee-ma-l.json`) and annotated Ethernet source/destination fields in the packet inspector. Unknown, malformed, multicast, locally administered, and synthetic all-zero addresses do not receive a vendor attribution. Expanded the capture agent's offline common port/service table without changing L7 parser precedence. Added source, refresh, and interpretation notes in `docs/mac-vendor-and-services.md`; no wire schema or opt-in enrichment behavior changed.

The new resolver and packet-inspector tests passed red before implementation and green afterward. Full Vitest (501 tests/75 files), TypeScript, lint, Rust tests, clippy, release build, and diff check pass. See `TEST_STATUS.md` for commands. Implementation is ready for PR/review; no PR has been opened yet.

## JAM-164 — 2026-09-28

PR #240 updates live packet layer tagging in `capture-agent/src/main.rs`: recognized L7 data maps to layer 7, TCP/UDP without recognized L7 maps to layer 4, and ICMP/other unparsed transports map to layer 3. `components/PacketStreamView.tsx` now offers only L3/L4/L7 filters, the layers the live capture path can classify. No wire schema or mapping changes were needed.

The regression tests passed red before the UI change and green afterward. Full Rust and Vitest suites, clippy, release build, lint, typecheck, and `git diff --check` passed. See `TEST_STATUS.md` for exact counts and commands.

## Review and merge state

- PR: https://github.com/usjbro/network_monitor/pull/240
- Linear JAM-164 is In Review and has the PR attached.
- GitHub CI checks passed; mergeable state was `clean` at the last check.
- Codex's independent review found no actionable findings. Claude Code was asked to review in Slack; no reply was present at the last thread read.
- PR #239 (JAM-16) is still open and has unresolved independent-review findings. Check its current status before merging/syncing PR #240; both touch the capture loop in `main.rs`.

Once review is complete and main is current, rerun the affected tests/CI, merge by squash, set JAM-164 to Done, fill this handoff with the merge SHA, and post `done` to the task Slack thread. Then return to the Linear queue.
