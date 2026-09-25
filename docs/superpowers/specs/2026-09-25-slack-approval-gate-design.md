# Slack Approval Gate — Design Spec

**Sub-project:** Meta/tooling (no Linear/GitHub issue — extends the agent-coordination-kit merged 2026-09-25)
**Status:** Approved by usjbro (jamesmbrownjr@gmail.com) on 2026-09-25, section by section
**Date:** 2026-09-25

## Purpose

`AGENTS.md`'s Multi-Agent Coordination section already tells a Claude Code session to post plans to Slack and poll for replies, but only *when the user explicitly asks*, and only for the life of that one session. This surfaced as a real gap this session: two PRs (#220, #222) were squash-merged without ever checking for existing GitHub PR review comments, even though another session had already left three real, unresolved findings — an unvalidated task-slug path-escape bug, a curl call that silently treats HTTP 4xx/5xx as success, and a contradiction between two ADRs — all still live on `main` as of this writing. Nothing gated on that feedback because nothing *required* checking for it.

This spec makes posting-and-waiting-for-approval the default behavior for any Linear-tracked task — not something that only happens if a session remembers to ask, and not exempted just because the task looks small — while explicitly not requiring you to leave the chat you're already in when you're directly present.

## Goals

- Any session working a Linear-tracked task posts its plan and does not proceed to implementation/delegation until a human reply is observed — including trivial tasks; triviality of the work is not an exemption. Only ad hoc, non-Linear-tracked work (no issue to gate against) skips this entirely.
- The human can reply either in the same chat session (when one is active and they're present) or in Slack (always available, and the only option for unattended/autonomous sessions).
- No timeout, ever — silence is never treated as approval.
- Reuses existing infrastructure: the coordination-kit webhook, the Slack MCP plugin, and the `schedule`/cron feature already available to Claude Code sessions. No new Slack app, bot token, or daemon.

## Non-Goals

- No new Slack app or OAuth bot token (rejected explicitly — see Approaches, below).
- No change to `coordination/tasks/*.md` contract semantics. ADR-001 already decided those are for parallel sub-work planning *within* an active epic task, not a tracker for the main task itself; this spec does not reuse or overload that format. Gates are a new, separate concern.
- No auto-approval on timeout, no majority-vote or multi-approver logic — a single human reply on either channel is sufficient.
- No fix, in this spec, for the three review findings described under Purpose (unvalidated `TASK_SLUG`, missing `curl --fail`, ADR-001/ADR-002 contradiction) — those are tracked separately as a follow-up bug-fix task. This design's own new gate-filename construction must not repeat the same class of bug (see Components).
- No multi-channel routing. One Slack channel (`#network-monitor`), as today.

## Approaches Considered

**A — orchestrator-side gating only, no persistence.** Whichever session owns the task posts and polls in-process using its own Slack MCP plugin access, delegating only after it reads approval. Simplest, but ties gating to a single session's lifetime — doesn't survive that session ending, and gives autonomous/scheduled sessions no path to approval once they've posted (nothing else would ever poll on their behalf).

**B — bot-token poller usable by any shell.** Stand up a Slack App with a bot OAuth token and `channels:history` scope so any process (not just a live Claude Code session) can poll `conversations.replies` directly. Works from anywhere, including plain bash, but requires new Slack infrastructure (an app registration, token storage, new attack surface) for a capability the chosen approach doesn't need.

**C — decoupled gate file + scheduled watcher agent (chosen).** Approval state persists in a git-tracked gate file, independent of any one session's lifetime. A separate scheduled Claude Code agent — using the `schedule`/cron feature already available, not new infrastructure — wakes periodically, checks Slack for replies, and performs delegation on behalf of whichever session originally posted. This is the only option that satisfies "block indefinitely, survive a session ending" without requiring a new Slack bot token.

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │  Any session starting a Linear task      │
                    │  (interactive or autonomous)              │
                    └──────────────────┬────────────────────────┘
                                        │ before implementation begins
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │ 1. Write coordination/gates/<id>-<slug>.md│
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
        │ (only if interactive &     │      │ picked up by the watcher on    │
        │  human replies there)      │      │ its next scheduled wake        │
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

The watcher is a Claude Code agent created via the existing `schedule` skill (cron-backed), waking on an interval (default 5 minutes — coarser than the existing 30-second interactive-polling convention in `AGENTS.md`, since a scheduled agent wake is a billed, discrete session start, not a tight in-process loop). Each wake it:

1. Lists `coordination/gates/*.md` with `status: awaiting-approval`.
2. For each, reads `#network-monitor` (via its own Slack MCP plugin access — the same mechanism available to any Claude Code session) for messages or thread replies referencing that gate's `linear_id`/`slug`, posted after the gate's `posted_at`.
3. Classifies any qualifying human reply using its own judgment — approve / reject / question — not a rigid parser.
4. On approval: re-reads the gate file immediately before acting (to catch a chat-session approval that landed first), and if still `awaiting-approval`, performs delegation itself and updates the gate.
5. On rejection or an unclear reply: replies in the Slack thread, sets `status: blocked` (rejection) or leaves `status: awaiting-approval` (question needing clarification) — never auto-retries a rejection.

## Components

**`coordination/gates/<linear-id>-<slug>.md`** — new directory, new file per gated task. Fields:

```
linear_id: JAM-9
slug: field-model-typed-named
status: awaiting-approval   # -> approved | blocked
delegated: false            # -> true once delegation actually runs
posted_at: 2026-09-25T14:00:00Z
plan_summary: >
  <short restatement of the task's objective/acceptance criteria>
delegation:                 # filled in once approved
  target: null               # in-session | codex
  agent_type: null           # e.g. network-monitor-developer, if target: in-session
```

`<slug>` in the gate filename must go through the same safe-slug validation that's already an open, unfixed finding against `new-task.sh` (unvalidated `TASK_SLUG` can escape its intended directory). The gate-creation code is new and must not introduce that same bug — validate before use, don't inherit the existing gap by copying the current script's pattern verbatim.

**Gate creation step** — added to the point where a session begins substantive work on a Linear-tracked task (the existing "read `.ai/CURRENT_TASK.md`" step in the required workflow). Writes the gate file, posts to Slack via the existing `coordination/scripts/slack-notify.sh` (tagged with `linear_id`/`slug` in the message text so it's matchable without needing a captured message `ts` — the plain Incoming Webhook doesn't return one), then stops.

**Watcher** — a scheduled Claude Code agent (via the `schedule` skill), running the wake logic described under Architecture. Delegation it performs reuses existing mechanisms unchanged: `coordination/router-checklist.md`'s criteria (extended with one more branch — "fits in the current judgment call → Agent-tool subagent in-session" vs. its existing Claude-Code-vs-Codex split) and `coordination/scripts/new-task.sh` for the Codex path.

## Data Flow — Interactive Case (you're present)

1. You ask for work on a Linear task. The session reads `CURRENT_TASK.md`, writes the gate, posts to Slack, tells you it's posted, and stops.
2. You reply "approved" (or similar) in the same chat, any time later.
3. The session checks the gate: if still `awaiting-approval`, it flips to `approved`, decides delegation, runs it, marks `delegated: true`. If the watcher already flipped it (you replied in Slack instead, or first), the session just reports that.

## Data Flow — Autonomous Case (no one present)

1. A scheduled/unattended session starts a Linear task the same way — writes the gate, posts to Slack, stops (there's no chat to end into in a meaningful sense; the run simply completes having posted).
2. The task sits `awaiting-approval` until a human replies in Slack.
3. The watcher's next wake reads the reply, classifies it, and — if approved — performs delegation on the original session's behalf, since that session is no longer running.

## Error Handling

- **Slack post fails, interactive session**: gate still created; warn that Slack-side approval won't work until the post succeeds, but in-chat approval still functions.
- **Slack post fails, autonomous session**: fail gate creation loudly — an autonomous task with no working Slack channel and no chat present has no path to ever being approved, so it must not be allowed to sit silently stuck.
- **No `SLACK_WEBHOOK_URL` configured**: same split as above.
- **Watcher can't reach Slack on a given wake**: skip, retry next wake, no state change.
- **Ambiguous reply**: treated as a question, gate stays `awaiting-approval`, a clarifying reply is posted back on the channel it arrived on.
- **Both channels reply close together**: check-then-act on `status` ensures exactly one delegation; the second observer reports rather than repeats it.
- **Crash between `status: approved` and `delegated: true`**: the split field lets a retry (next wake, or the session's next turn) detect and resume/retry delegation rather than re-asking for approval.
- **Explicit rejection**: `status: blocked`, stops; requires a new human instruction, never auto-retried.

## Testing Plan

No existing automated test harness covers `coordination/scripts/*` (established convention: `bash -n` clean plus real end-to-end exercise, per how `new-task.sh`/`complete-task.sh` were verified when merged). This follows the same pattern:

- Gate lifecycle exercised for real: create → `awaiting-approval` → `approved`/`blocked` → `delegated`.
- Chat-approval path: create a gated task, approve in-chat, confirm delegation runs and the gate updates correctly.
- Slack-only path (simulating an autonomous session): create a gated task, reply only in Slack, confirm the watcher's next wake picks it up and delegates — exercised for both delegation targets (in-session Agent subagent, and cross-tool via `new-task.sh`).
- Race case: reply on both channels close together, confirm exactly one delegation occurs.
- Rejection/question path: confirm the gate stays `blocked`/`awaiting-approval` and a reply is actually posted, not dropped.
- Failure path: unset the webhook; confirm autonomous gate creation refuses while interactive gate creation still works with a warning.
- Confirm the scheduled watcher actually wakes at its configured interval, via the `schedule` skill's own verification.

## Open Questions / Deferred

- `router-checklist.md` needs a small addition for choosing *which* Agent-tool subagent type to delegate to in-session (it currently only decides Claude Code vs. Codex, not which of `network-monitor-developer`/`-architect`/`-reviewer`/`-tester` to spawn). Left for the implementation plan, not re-litigated here — it's an extension of existing criteria, not a new design.
- The three currently-open review findings referenced under Purpose (unvalidated `TASK_SLUG`, `curl --fail`, ADR-001/ADR-002 contradiction) are explicitly out of scope for this spec and tracked as separate follow-up work.
