# Slack Approval Gate — Design Spec

**Sub-project:** Meta/tooling (no Linear/GitHub issue — extends the agent-coordination-kit merged 2026-09-25)
**Status:** Approved by usjbro (jamesmbrownjr@gmail.com) on 2026-09-25, section by section
**Date:** 2026-09-25

## Purpose

`AGENTS.md`'s Multi-Agent Coordination section already tells a Claude Code session to post plans to Slack and poll for replies, but only *when the user explicitly asks*, and only for the life of that one session. This surfaced as a real gap this session: two PRs (#220, #222) were squash-merged without ever checking for existing GitHub PR review comments, even though another session had already left three real, unresolved findings — an unvalidated task-slug path-escape bug, a curl call that silently treats HTTP 4xx/5xx as success, and a contradiction between two ADRs — all still live on `main` as of this writing. Nothing gated on that feedback because nothing *required* checking for it.

This spec makes posting-and-waiting-for-approval the default behavior for any Linear-tracked task — not something that only happens if a session remembers to ask, and not exempted just because the task looks small — while explicitly not requiring you to leave the chat you're already in when you're directly present.

## Goals

- Any session working a Linear-tracked task posts its plan and does not proceed to implementation/delegation until a human reply is observed — including trivial tasks; triviality of the work is not an exemption. Only ad hoc, non-Linear-tracked work (no issue to gate against) skips this entirely.
- The human can reply either in the same chat session or in Slack, checked by that same session while it remains active. **Amendment (2026-09-25, during Task 5 implementation):** a truly unattended/autonomous watcher — something that resolves a gate after the creating session has ended — is explicitly out of scope. A later live session in the same persistent checkout can manually inspect a pending gate and its Slack thread. The `schedule` skill's cloud agents run in an isolated sandbox on a fresh GitHub clone with no access to local, uncommitted files; `coordination/gates/*.md` (like `coordination/tasks/*.md` before it) is local-only state, so a cloud agent must not create a gate it cannot hand off. Per explicit user direction, this is not being solved here — no background resolver acts after the creating session ends.
- No timeout, ever — silence is never treated as approval. (Within the constraint above: if the session ends first, the gate simply stays `awaiting-approval` until revisited — see Data Flow, Autonomous Case.)
- Reuses existing infrastructure: the coordination-kit webhook and the Slack MCP plugin already available to Claude Code sessions. No new Slack app, bot token, daemon, or scheduled/cloud agent.

## Non-Goals

- No new Slack app or OAuth bot token (rejected explicitly — see Approaches, below).
- No change to `coordination/tasks/*.md` contract semantics. ADR-001 already decided those are for parallel sub-work planning *within* an active epic task, not a tracker for the main task itself; this spec does not reuse or overload that format. Gates are a new, separate concern.
- No auto-approval on timeout, no majority-vote or multi-approver logic — a single human reply on either channel is sufficient.
- No fix, in this spec, for the three review findings described under Purpose (unvalidated `TASK_SLUG`, missing `curl --fail`, ADR-001/ADR-002 contradiction) — those are tracked separately as a follow-up bug-fix task. This design's own new gate-filename construction must not repeat the same class of bug (see Components).
- No multi-channel routing. One Slack channel (`#network-monitor`), as today.
- No watcher that survives the gate-creating session ending (revised 2026-09-25 — see Approaches Considered). A gate whose session ends before a Slack reply arrives simply stays `awaiting-approval`; nothing currently resumes it automatically. Solving that — e.g. by making gates git-tracked/pushed so a cloud agent could see them — is future work, not attempted here.

## Approaches Considered

**A — orchestrator-side gating only, no persistence.** Whichever session owns the task posts and polls in-process using its own Slack MCP plugin access, delegating only after it reads approval. Simplest, but ties gating to a single session's lifetime — doesn't survive that session ending, and gives autonomous/scheduled sessions no path to approval once they've posted (nothing else would ever poll on their behalf).

**B — bot-token poller usable by any shell.** Stand up a Slack App with a bot OAuth token and `channels:history` scope so any process (not just a live Claude Code session) can poll `conversations.replies` directly. Works from anywhere, including plain bash, but requires new Slack infrastructure (an app registration, token storage, new attack surface) for a capability the chosen approach doesn't need.

**C — decoupled gate file, checked by the creating session itself (chosen, revised).** Approval state persists in a gate file (locally, not git-tracked — see Components), independent of any single chat turn. Originally specified as a *separate* scheduled Claude Code agent (via the `schedule`/cron feature) waking periodically to check Slack on behalf of sessions that had already ended — during Task 5's implementation this proved impossible: `schedule`'s cloud agents run on a fresh GitHub clone with no access to local, uncommitted files, so a cloud watcher could never see a real gate file. Revised, per explicit user direction: the *same session* that created the gate polls Slack itself (every 60 seconds) while it remains active, instead of a separate process. This still satisfies "no timeout, dual channel, no new Slack infrastructure" — it just no longer covers the case where the creating session has already ended before a Slack reply arrives (see Non-Goals).

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │  Any interactive session starting a       │
                    │  Linear task                              │
                    └──────────────────┬────────────────────────┘
                                        │ before implementation begins
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │ 1. Write coordination/gates/<id>__<slug>.md│
                    │    status: awaiting-approval               │
                    │ 2. Post plan to #network-monitor via       │
                    │    the existing webhook (slack-notify.sh)  │
                    │ 3. End turn / stop — do not implement      │
                    └──────────────────┬────────────────────────┘
                                        │
                        ┌───────────────┴────────────────┐
                        ▼                                  ▼
        ┌───────────────────────────┐      ┌──────────────────────────────┐
        │ CHANNEL 1: same chat       │      │ CHANNEL 2: Slack reply         │
        │ session's next turn        │      │ (any time, any device)         │
        │ (human replies directly    │      │ picked up by that SAME         │
        │  in the conversation)      │      │ session's own 60s poll loop    │
        └──────────────┬─────────────┘      └───────────────┬────────────────┘
                        │  check gate status first            │  check gate status first
                        │  (still awaiting-approval?)          │  (still awaiting-approval?)
                        ▼                                       ▼
              ┌─────────────────────────────────────────────────────┐
              │  Whichever observes approval FIRST:                  │
              │  - sets status: approved                              │
              │  - decides delegation (router-checklist.md)           │
              │  - runs it (Agent-tool subagent, or new-task.sh)      │
              │  - sets delegated: true                                │
              │  The other path, seeing status already flipped,       │
              │  reports that instead of delegating again.             │
              └─────────────────────────────────────────────────────┘
```

The "watcher" is not a separate agent — it's the gate-creating session's own optional poll loop, run only while that session is active, at 60-second intervals (per explicit user direction — coarser polling is unnecessary here since it's a live in-process loop, not a billed discrete session start like the originally-specified scheduled-agent approach). While polling:

1. Checks `coordination/scripts/gate-status.sh <linear_id> <slug>` for its own gate. If no longer `awaiting-approval` (a chat reply resolved it), stop polling.
2. Finds the tagged parent gate post in `#network-monitor` after `posted_at`, then reads every reply in that thread, including replies that do not repeat the tag. Also reads standalone channel messages that mention the tag.
3. Classifies any qualifying human reply using its own judgment — approve / reject / question — not a rigid parser.
4. On approval: re-checks gate status immediately before acting (to catch a chat-reply approval that landed in the same window), and if still `awaiting-approval`, performs delegation itself and updates the gate.
5. On rejection or an unclear reply: replies in the Slack thread, sets `status: blocked` (rejection) or leaves `status: awaiting-approval` (question needing clarification) — never auto-retries a rejection.
6. If the session ends while a gate is still `awaiting-approval`, polling simply stops with it — see Non-Goals.

## Components

**`coordination/gates/<linear-id>__<slug>.md`** — new directory, new file per gated task. The double underscore separates two validated components unambiguously. Fields:

```
linear_id: JAM-9
slug: field-model-typed-named
status: awaiting-approval   # -> approved | blocked
delegated: false            # -> true once delegation actually runs
delegation_claimed: false    # -> true before dispatch; reset only after human confirms no active dispatch
posted_at: 2026-09-25T14:00:00Z
plan_summary: >
  <short restatement of the task's objective/acceptance criteria>
delegation:                 # filled in once approved
  target: null               # in-session | codex
  agent_type: null           # e.g. network-monitor-developer, if target: in-session
```

`<slug>` in the gate filename must go through the same safe-slug validation that's already an open, unfixed finding against `new-task.sh` (unvalidated `TASK_SLUG` can escape its intended directory). The gate-creation code is new and must not introduce that same bug — validate before use, don't inherit the existing gap by copying the current script's pattern verbatim.

**Gate creation step** — added to the point where a session begins substantive work on a Linear-tracked task (the existing "read `.ai/CURRENT_TASK.md`" step in the required workflow). Writes the gate file, posts to Slack via the existing `coordination/scripts/slack-notify.sh` (tagged with `linear_id`/`slug` in the message text so it's matchable without needing a captured message `ts` — the plain Incoming Webhook doesn't return one), then stops.

**Watcher** — not a separate component; the poll loop described under Architecture, run by the gate-creating session itself, only while it remains active (see `coordination/watcher-prompt.md` for the exact instructions). It finds the tagged parent Slack post and reads all replies in that thread, including replies that do not repeat the tag. Delegation it performs reuses existing mechanisms unchanged: `coordination/router-checklist.md`'s criteria (extended with one more branch — "fits in the current judgment call → Agent-tool subagent in-session" vs. its existing Claude-Code-vs-Codex split) and `coordination/scripts/new-task.sh` for the Codex path.

## Data Flow — Interactive Case (you're present)

1. You ask for work on a Linear task. The session reads `CURRENT_TASK.md`, writes the gate, posts to Slack, tells you it's posted.
2. Either: you reply "approved" in chat, or the session reads approval while polling Slack. The observer transitions `awaiting-approval` to `approved`, then atomically claims delegation. Only the observer whose claim succeeds may dispatch. It records `delegated: true` only after dispatch completes. A later session may claim an `approved` gate with no claim; if a claim exists without completed delegation, it must not dispatch again until the human confirms no active dispatch and explicitly resets the claim.

## Data Flow — Session-Ends-First Case (no longer autonomous — see Non-Goals)

1. A gate is created and posted, but the session ends (or stops polling) before any reply arrives on either channel.
2. The gate stays `awaiting-approval` indefinitely — nothing currently resumes it automatically. A later session revisiting the same task can check `coordination/scripts/gate-status.sh` and either wait for a fresh reply or, if one already landed in Slack while nothing was watching, read it and act on it manually.
3. This gap (no automatic resumption once the creating session is gone) is explicitly out of scope per Non-Goals — closing it would require making gates visible to something other than a live local session (e.g. git-tracked gates a cloud agent could see), which is future work.

## Error Handling

- **Slack post fails, interactive session**: gate still created; warn that Slack-side approval won't work until the post succeeds, but in-chat approval still functions.
- **Slack post fails, autonomous session**: fail gate creation loudly. A successful autonomous post still needs a later live session in the same persistent checkout to inspect the gate and Slack thread manually.
- **No `SLACK_WEBHOOK_URL` configured**: same split as above.
- **Watcher can't reach Slack on a given wake**: skip, retry next wake, no state change.
- **Ambiguous reply**: treated as a question, gate stays `awaiting-approval`, a clarifying reply is posted back on the channel it arrived on.
- **Both channels reply close together**: the approved gate's atomic `delegation_claimed` transition ensures only one observer starts dispatch; the other observes the existing claim or completion.
- **Crash after approval but before a delegation claim**: a later session can claim and resume without asking for approval again.
- **Crash after a delegation claim but before `delegated: true`**: the existing claim prevents automatic duplicate dispatch. A human must confirm no delegation is active before `reset-gate-delegation-claim.sh` allows a retry.
- **Interrupted lock holder**: lock metadata records the owner PID and process start time when available. `recover-gate-lock.sh` refuses a matching live owner, distinguishes a reused PID by its start time, and requires explicit confirmation before removing a stale or ownerless lock.
- **Explicit rejection**: `status: blocked`, stops; requires a new human instruction, never auto-retried.

## Testing Plan

No existing automated test harness covers `coordination/scripts/*` (established convention: `bash -n` clean plus real end-to-end exercise, per how `new-task.sh`/`complete-task.sh` were verified when merged). This follows the same pattern:

- Gate lifecycle exercised for real: create → `awaiting-approval` → `approved`/`blocked` → `delegated`.
- Chat-approval path: create a gated task, approve in-chat, confirm delegation runs and the gate updates correctly.
- Slack-only path: create a gated task, reply only in Slack (not in chat), confirm the same session's own poll loop picks it up on its next 60-second check and delegates — exercised for both delegation targets (in-session Agent subagent, and cross-tool via `new-task.sh`).
- Race case: reply on both channels close together, confirm exactly one delegation occurs.
- Rejection/question path: confirm the gate stays `blocked`/`awaiting-approval` and a reply is actually posted, not dropped.
- Failure path: unset the webhook; confirm autonomous-mode gate creation refuses while interactive-mode gate creation still works with a warning.
- No scheduled/cloud watcher to verify (removed — see Non-Goals and the Approaches Considered amendment).

## Open Questions / Deferred

- `router-checklist.md` needs a small addition for choosing *which* Agent-tool subagent type to delegate to in-session (it currently only decides Claude Code vs. Codex, not which of `network-monitor-developer`/`-architect`/`-reviewer`/`-tester` to spawn). Left for the implementation plan, not re-litigated here — it's an extension of existing criteria, not a new design.
- The three currently-open review findings referenced under Purpose (unvalidated `TASK_SLUG`, `curl --fail`, ADR-001/ADR-002 contradiction) are explicitly out of scope for this spec and tracked as separate follow-up work.
