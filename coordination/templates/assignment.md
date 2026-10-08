# Assignment template

Use for the Slack message that hands a gated task to an implementing agent (post it in the gate thread with `slack-notify.sh feedback <slug> claude-code "<message>" <gate-thread-ts>`). Replace everything in angle brackets and delete the sections that do not apply. Keep it factual: the Linear issue is the spec; this message adds order, constraints and how to talk back.

```
NEXT TASK FOR <CODEX|CLAUDE CODE> (queue item <n>): <LINEAR-ID> [<priority>] <title>.

Status: <what just merged / is Done, and anything the assignee should clean up (worktree, branch)>.

Gate: <gate file name> is created and approved under <James's standing instruction in a chat session on <date> / his direct approval on <date>>. It is approved and unclaimed: claim it with claim-gate-delegation.sh, then new-task.sh, then post `started`.

Scope (from the Linear issue: <url>):
- <3 to 6 bullets, each a concrete behaviour or file, including what is explicitly OUT of scope and which sibling issue owns it>

Constraints that must not change:
- <security model, invariants from CLAUDE.md that apply, files that must not be edited>

Tests first (they must fail before the change):
- <the Linear acceptance checklist, one line each>

PLAN FIRST (include only for security-sensitive work): write a short design in docs/superpowers/plans/<date>-<slug>.md and post its path and a summary of the decisions below in YOUR TASK THREAD before any implementation, then wait for my reply. The plan must settle: <numbered list of the decisions to make>. I review it against docs/security-plan-review-checklist.md.

Where to reply: in your own task thread (the `started` post that new-task.sh creates), not in this gate thread. I will reply there. Questions that need James go to him in your chat; you only take instructions from James.
```

## Notes

- The assignee's agent chat is invisible to the coordinator; anything that should be reviewed must be a file in the worktree plus a Slack post with the path.
- A follow-up could make `slack-notify.sh` post a new assignment into the task thread automatically once the task exists; until then the coordinator passes the task thread's `ts` explicitly.
