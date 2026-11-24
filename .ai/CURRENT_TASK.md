# KAN-131 Bounded rollups — implementation (2026-11-24)

James approved code gate `kan-131__rollup-bounds` in chat ("approve all": all seven tasks, commit, push, PR; James merges). Worktree `.worktrees/rollup-bounds`, branch `KAN-131-rollup-bounds`. Seven tasks done and reviewed. P9 failed at `36949c3` (10.4 ms vs 5.7 ms at 50,000); James approved one faster attempt, which passed on AC at `25e936d` (1.1 vs 7.5 ms; the pre-registered scan shape gate also passed). Rollups are sent last in each tick, with James's approval, because above about 1,000 live flows the 1,024-event queue dropped them. Security review: no findings. Independent whole-branch review: docs and comment fixes only. PR review fixes then changed code: bounded test reads, enrichment updates, shared sort values, and etherparse 0.20.4 (RUSTSEC-2026-0596, James approved it in #350). Follow-ups filed: KAN-313 (process-name cap), KAN-314 (event queue and stale rows). PR #350 is open (its head moves with review fixes). Remaining: PR review and merge by James.

---

# KAN-131 Bounded rollups — implementation plan (2026-11-23)

James approved gate `kan-131__rollup-bounds-plan` in chat (plan only), then the plan, P1–P9, its Task 3 re-measurement, and commit, push and PR, also in chat. Execution when the code gate is approved: subagent-driven. Spec merged as `7fe5f29` (PR #348). Worktree `.worktrees/rollup-bounds-plan`, branch `KAN-131-rollup-bounds-plan`. Plan `docs/superpowers/plans/2026-11-23-rollup-bounds.md`, seven tasks, one PR for the code. No code. Next: independent review and merge; the code needs its own gate.

---

# KAN-131 Bounded rollups — design spec (2026-11-23)

James assigned KAN-131 to Claude and approved gate `kan-131__rollup-bounds-spec` (spec only; commit, push and PR authorized) in chat. Worktree `.worktrees/rollup-bounds-spec`, branch `KAN-131-rollup-bounds-spec`. Draft `docs/superpowers/specs/2026-11-23-rollup-bounds-design.md`, with benchmark numbers (throwaway, not committed). No code. PR #348. James approved all five decisions in chat, then the fixes for ten review findings (including new event names) and keeping D6 as is. Next: independent review and merge, then a plan with its own gate. All remaining KAN-110 work is assigned to Codex.

---

# KAN-110 Task 3c-2 — Codex continuation (2026-11-20)

James requested review and continuation in this worktree. PR #346 is the only open PR; #342–#345 are merged. Published head `9e91028` passes Rust/Web/Playwright/fuzz/Sonar/Snyk, but CodeQL blocks on replay-test deserialization before size validation (alert 26). Follow-up fixes bound and validate the replay line before parsing, add a regression, and share the remaining duplicated PCAP writer with `io_graph_replay`. Verification: 964 Rust tests pass serially (15 ignored), clippy clean; independent code/security reviews found no actionable defect. Explicit cancellation/write-failure zeroization-observer coverage remains incomplete. James authorized commit/push in live chat. Next: publish and recheck CodeQL/Sonar. James owns merge. Task 4 remains next after this PR.

---

# KAN-110 Follow Stream Task 3c-2: answer get_stream (2026-11-20)

James's standing instruction (2026-11-20): work through every KAN issue in order. Worktree `.worktrees/follow-stream-reply`, branch `KAN-110-follow-stream-reply`. `serve_connection` answers `get_stream` inline from the store; `tests/follow_replay.rs` through the real binary; `follow_store` fuzz pages the response builder. Next: PR, reviews; then KAN-110 Task 4 (relay route).

---

# KAN-110 Follow Stream Task 3c-1: feed the store (2026-11-20)

James's standing instruction (2026-11-20): work through every KAN issue in order. Worktree `.worktrees/follow-stream-feed`, branch `KAN-110-follow-stream-feed`. `main.rs` allocates `FollowStore` only with `FOLLOW_STREAM=1`, feeds it after flow observation, notifies snaplen cuts, ticks it from the emitter with `FlowTable`'s removals, resets it on a successful interface switch. Next: PR, reviews; then 3c-2 (reply writer, budget, `follow_replay.rs`, fuzz).

---

# KAN-110 Follow Stream Task 3b: wire contract and bounded response (2026-11-20)

James approved Task 3b in chat ("approved all"). Worktree `.worktrees/follow-stream-response`, branch `KAN-110-follow-stream-response`. `follow_response.rs` builds `stream_data` (192 KiB bounded writer, page/metadata/turn limits, P2 port check); `wire.rs` decodes `get_stream`; `lib/types.ts`/`lib/agent-mapping.ts` map it from an encoder-generated fixture. `main.rs` ignores `get_stream` until Task 3c. PR open. Next: reviews, CI; James merges.

---

# KAN-294 Follow Stream front-door exclusion (2026-11-19)

James chose option (a). Worktree `.worktrees/follow-stream-front-door`, branch `KAN-294-follow-stream-front-door`. With `FOLLOW_STREAM=1` the agent also reads `FRONT_DOOR_PORT` (default 8443) and excludes that port with the relay port: on loopback pairs, and between this host's own address and itself; another host's front-door session is kept. PR open. Next: reviews, CI; James merges.

---

# KAN-130 Task 4 — flow ladder UI (2026-11-20)

James approved gate `kan-130__flow-ladder-ui` in chat. Worktree `.worktrees/flow-ladder-ui`. `components/FlowLadderView.tsx`; `TcpGraphsView` Graphs | Ladder tabs (`tab`/`onTab`/`ladder`, one poller); Ladder button in `ConnectionsView`; `PacketStreamView` `focusPacketId`/`onFocusHandled` (P7); `app/page.tsx` wiring and `openLadderFrame` (missing / hidden-by-display-filter notices). e2e `flow-ladder.spec.ts`: production live poll median 8.8 ms; no sideways scroll at 320/1280 px. docs/usage.md Flow ladder section; 'never payload' corrected. Vitest 1,167, tsc, lint pass. Next: PR, CI; James merges; then KAN-130 Done.

---

# KAN-130 Task 3 — ladder model `lib/flow-ladder.ts` (2026-11-20)

James approved gate `kan-130__flow-ladder-model` in chat. Worktree `.worktrees/flow-ladder-model`. Pure `buildLadder` (spec D3 gap/interesting/run/row-cap), `arrowText`, `sampleKey`/`packetKey`/`linkSamples` (spec D4; ambiguity fails closed; endpoints split at the last colon, brackets/case normalised). 22 tests in `lib/__tests__/flow-ladder.test.ts`, written first (16 failed against a stub). tsc, lint, 1,149 Vitest pass. No UI yet. Next: PR, CI; James merges; Task 4 needs its own gate.

---

# KAN-130 Task 2 — tcp_samples head and labels on the wire (2026-11-20)

James approved gate `kan-130__flow-ladder-wire` in chat. Worktree `.worktrees/flow-ladder-wire`. `wire.rs` page gains `head` (P2 rule) and `labels` `[index, kind, text]`; measured worst-case line 226,620 B (cap 3,072 stands). TS: `TcpSamplesPage.head/labels`, mapper validates labels (bad ones dropped), `accumulate` keeps head + labels and pins trimmed indices < 16 client-side. Replay tests cover a 4,206-sample TLS flow and an HTTP flow. cargo test/clippy, tsc, lint, 1,127 Vitest pass. Next: PR, CI; James merges; Task 3 needs its own gate.

---

# KAN-130 Task 1 — agent labels, ServerHello check, pinned head (2026-11-20)

James approved gate `kan-130__flow-ladder-agent-labels` in chat. Worktree `.worktrees/flow-ladder-agent-labels`. Plan `docs/superpowers/plans/2026-11-20-flow-sequence-diagram.md` Task 1: `tcp_samples.rs` label table (32/ring, head labels pinned), `label_for`, `is_tls_server_hello_start`, 16-sample head, `RingView.head/head_start_index/labels`; `display_text.rs` (moved from `transaction.rs`); `FlowTable::observe_inner` records labels. No wire change. Worst case now 17,978,368 B (140,456/ring). `cargo test --locked` and clippy pass locally (needed `libpcap-dev` in this container). Next: PR, CI; James merges; Task 2 needs its own gate.

---

# KAN-130 Flow sequence diagram — implementation plan (2026-11-20)

Spec merged (PR #336). James chose D2 (a)+(b) and D5 (out) and approved gate `kan-130__flow-sequence-diagram-plan` in chat. Worktree `.worktrees/flow-sequence-diagram-plan`. Plan `docs/superpowers/plans/2026-11-20-flow-sequence-diagram.md` in four tasks (agent labels/head; wire; `lib/flow-ladder.ts`; UI), decisions P1–P8; spec status, D2/D5 and §7 (P5) updated. James said skip Codex review for KAN-130. Next: plan PR; James merges; each task needs its own gate.

---

# KAN-130 Flow sequence diagram — design spec (2026-11-20)

James approved gate `kan-130__flow-sequence-diagram-spec` in chat (spec only). Worktree `.worktrees/flow-sequence-diagram-spec`, branch `KAN-130-flow-sequence-diagram-spec`. Draft `docs/superpowers/specs/2026-11-20-flow-sequence-diagram-design.md`: the ladder reads KAN-129's sample ring via the existing `/api/tcp-samples` poller (shared panel tab); exact collapse/row-cap rules; best-effort client-side link to the packet view. Open for James: D2 (label table + pinned 16-sample head, a wire change) and D5 (host-pair mode; recommended out). No code. Next: James's decisions, commit/PR on request, then the plan.

---

# KAN-110 Follow Stream Task 3a — bounded control-line reader (2026-11-19)

James split plan Task 3 into 3a/3b/3c and chose Claude for 3a (gate `kan-110__follow-stream-control-reader`, approved in chat). Worktree `.worktrees/follow-stream-control-reader`, branch from `new-task.sh`. Scope: `capture-agent/src/control_line.rs` and its use in `serve_connection`; docs. PR #334 merged (e2f9e45); its /code-review fixes are PR #335 (security review: no findings). Next: CI on #335; James merges. 3b (response builder, wire types, P2) and 3c (main.rs integration, replay test, fuzz) are unassigned; KAN-294 option (a) chosen, unassigned.

---

# KAN-293 review fixes (2026-11-19)

/code-review on #331 (merged as 22b51a1) found two regressions it introduced and a missed tail gap; James: "go ahead". Worktree `.worktrees/rst-anchor-resync`, branch `KAN-293-rst-review-fixes`. The ACK-push resync is replaced by a vouched resync: a side's own segment landing where the confirmed peer last acknowledged confirms it or moves it forward. An accepted RST also records the sender's missed tail as a gap. Next: PR, review; James merges.

---

# KAN-110 Follow Stream Task 2 — startup ports and pre-pipeline exclusion (2026-11-19)

James approved P2 and chose Claude in chat (gate `kan-110__follow-stream-startup-ports`, delegated in-session). Worktree `.worktrees/follow-stream-startup-ports`, branch `KAN-110-follow-stream-startup-ports`. New `capture-agent/src/follow_config.rs` (`follow_enabled`, `parse_relay_port`, `resolve_relay_port`); `exclude_live_control_capture` takes `relay_port: Option<u16>`, read once in `main`. P2's `relayPort` request field and `ack_number` feeding are Task 3. Next: PR, reviews; James merges.

---

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
