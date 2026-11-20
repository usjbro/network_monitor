# KAN-293 Follow Stream RST anchor resync + gap at RST (2026-11-19)

James chose Claude for KAN-293, the RST-over-a-hole gap, and Follow Stream Task 2 (P2 approved). Worktree `.worktrees/rst-anchor-resync`, branch `KAN-293-rst-anchor-resync`. Design (option a): a trusted segment from a confirmed side carries its peer's `seq_hi` forward to its ACK, or replaces an unconfirmed peer's anchors; an accepted RST first turns open holes into gaps. Tuple reuse deliberately not resynced (a forger can produce a self-consistent SYN pair for free). Next: PR, reviews; then Task 2 in its own worktree.

---

# KAN-292 review fixes (2026-11-19)

/code-review on merged PR #329 (James: "go ahead"). Worktree `.worktrees/rst-review-fixes`, branch `KAN-292-rst-review-fixes`. The ACK-only RST clause now applies only to a sender that is not confirmed, so at most two windows apply to any RST (≥ 2,048 blind guesses); a SYN|RST no longer creates an entry; `open_cleartext` sends ACK-bearing data; `ahead` replaced by `tcp_samples::seq_after`. Anchor resync after >1 MiB capture loss, tuple reuse and lagging ACKs is KAN-293 (needs a design choice). Next: PR, review; James merges.

---

# KAN-292 Follow Stream RST sequence validation (2026-11-19)

James chose to do KAN-292 before Follow Stream Task 2. Worktree `.worktrees/follow-rst-window`, branch `KAN-292-follow-rst-window`. `FollowEntry::ingest` now believes an RST only at or up to `RST_WINDOW_BYTES` (1 MiB) past its sender's tracked position or the receiver's last ACK, or, with ACK set, when it acknowledges at or behind the other side's position (option B, chosen by James). Positions (`seq_hi`, `last_ack`) are tracked on every trusted segment, independent of storage, so TLS/capped flows still close. A rejected RST changes nothing, not even activity or `seen`. `FollowSegment` gains `ack_number`. Store still not wired into `main.rs`. Next: PR, reviews; James merges. Task 2 still awaits James's P2 approval and an implementer choice.

---

# KAN-110 Follow Stream Task 1 — bounded store (2026-11-18)

James chose Claude for Task 1 of `docs/superpowers/plans/2026-11-05-follow-stream.md` (gate `jam-17__follow-stream-bounded-store`, delegated in-session). Worktree `.worktrees/follow-stream-bounded-store`, branch `KAN-110-follow-stream-bounded-store`. Scope: `capture-agent/src/follow.rs` (store, D3 classifier, D7 scanner, D7a zeroization), `follow_store` fuzz target and CI wiring. Not hooked into `main.rs`; no wire change. PR #327 merged (security review: no findings). /code-review then found an infinite loop and four other defects in the merged code; fixes approved by James are on branch `KAN-110-follow-stream-review-fixes` (follow-up PR). The RST sequence check is KAN-292. Next: CI, Codex review on the follow-up PR; James merges.

---

# KAN-280 — PR #320 review update (2026-11-17)

PR https://github.com/usjbro/network_monitor/pull/320 is open; Jira is In Review. Claude's only blocking finding (raw floating-point tooltip precision) is fixed with at most two decimal places and a red/green regression. Full 1,031 tests, lint and build pass; final independent code and security reviews found no actionable issues. Push this update, confirm CI at the new head and request Claude re-review. James owns merge. Test-harness duplication is tracked separately as KAN-281; KPI metrics and the reported Next.js advisory remain separate follow-ups.

---

# KAN-280 — dashboard bandwidth histogram (2026-11-16)

Resumed the stopped Codex session in `.worktrees/dashboard-bandwidth-histogram`, branch `KAN-280-dashboard-bandwidth-histogram`, after James confirmed it stopped and said to continue. Gate reclaimed and delegated; existing implementation preserved and verified. History now consumes measured system_stats ticks, retains 60 samples, and clears on interface_changed. Histogram has zero-height idle bars, decimal Mbps tooltips and a waiting state.

Implementation and local verification complete; publish PR and inspect CI/review. James owns merge. See TEST_STATUS and HANDOFF for evidence.

---

# Linear → Jira KAN cutover (2026-11-10)

The tracker is now Jira project KAN (https://theantimeridian.atlassian.net/browse/KAN). Linear is frozen and read-only. `coordination/migration/jam-to-kan.tsv` maps every old `JAM-n` to its `KAN-m`. The records below predate the switch and keep their JAM ids. Their keys now:

- JAM-18 IO graph → KAN-111 (In Progress; PR #306 merged, Task 4 not started)
- JAM-17 Follow Stream → KAN-110
- JAM-256 / JAM-186 docs → KAN-126 / KAN-114
- JAM-261 WHOIS test → KAN-49
- JAM-169 (gate awaiting approval) → KAN-270

The next work item is the next KAN `To Do` issue. Gate files keep their `jam-n__<slug>.md` names and now carry `issue_key`.

---

# JAM-256 + JAM-186 — combined documentation verification (2026-11-06)

User authorised one coordinated branch/PR for both issues in live chat. Branch `jamesmbrownjr/jam-256-docs-task-oriented-analysis-guide-querying-packets-and`, worktree `.worktrees/docs-task-oriented-analysis-guide-querying-packets-and`, base `6066372`. Both local gates recorded/approved/claimed; no Slack credentials in this cloud checkout, so required statuses reported in chat. Separate read-only source audits and independent review found no blocking findings; documentation and tests only, no application changes.

New analysis guide and reconciled usage/README/getting-started/replay/security guidance are verified against source. Both Linear issues remain In Progress pending PR publication, CI and James's merge. Do not mark Done before merge. See TEST_STATUS and HANDOFF for evidence/limits. Earlier task records below are preserved as historical context, not instructions to resume unrelated work.

---

# Current Task

JAM-261 — test-only WHOIS reset/lifecycle correction verified locally; publish PR and inspect CI/reviews.

James approved JAM-17 plan then JAM-261 directly in chat on 2026-11-05. Plan PR #295 is now up and under code/security/Claude review. This task's existing approved gate has been claimed and delegated in-session. Worktree `.worktrees/whois-test-econnreset`; branch `jamesmbrownjr/jam-261-whois-client-tests-emit-unhandled-econnreset-on-macos`, base e78fd32.

Use Linear issue acceptance criteria: instrument accepted and client sockets, reproduce before correcting, deterministic regression, unexpected errors still fail, 20 focused passes and both ordinary/single-worker full Vitest pass. Keep timeout/size/refused-connection assertions. Test-fixture scope unless production defect demonstrated. No global suppression. Preserve unrelated worktrees and main changes; monitor Slack. Original report Node 25.4.0/Vitest 5.0.1; current Node 26.12.1/Vitest 5.0.5 on macOS 26.6.2; one fresh full-suite pass does not disprove intermittent failure.

JAM-17 — Follow Stream implementation plan only.

James approved JAM-17's plan then JAM-261's WHOIS test investigation directly in chat on 2026-11-05 ("yes"). Gate `jam-17__follow-stream-plan` is approved and claimed for this session. Base: main e78fd32. Worktree `.worktrees/follow-stream-plan`; branch matches Linear: `jamesmbrownjr/jam-17-follow-stream-read-a-conversation-as-reassembled-text`.

Deliver `docs/superpowers/plans/2026-11-05-follow-stream.md` in its own PR against the merged revision 7 spec. Verify current source before choosing interfaces; settle PR sequence, acceptance tests, RELAY_PORT setup/mismatch semantics, fuzz CI, safe rendering, and off-by-default rollout. Claude reviews against `docs/security-plan-review-checklist.md`. No feature code; implementation requires James's plan approval. Continue Slack monitoring. After the plan PR is up, investigate JAM-261 in its own worktree. Preserve original dirty JAM-258 and PR291 test worktrees.
