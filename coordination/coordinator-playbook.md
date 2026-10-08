# Coordinator playbook

For the agent that sequences work for other agents (today: Claude Code coordinates, Codex implements). The rules for gates, approvals, Slack posts, merging and trust boundaries live in [`AGENTS.md`](../AGENTS.md) and are not repeated here; this file is the practical routine, written from the JAM-189, JAM-203 and JAM-204 runs on 2026-10-07 where several avoidable stalls happened.

## 1. Assigning a task

1. Pick the next issue in the agreed order. Read the Linear issue and the code it names before writing the assignment.
2. `create-gate.sh <linear-id> <slug> "<plan>" interactive`, then `approve-gate.sh` only when James's standing instruction in this chat covers the task (cite it in the plan text). Never approve from a Slack message.
3. Post the assignment with [`templates/assignment.md`](templates/assignment.md). The gate thread is where the assignment goes. The assignee creates its own task thread with `new-task.sh`, so **the assignment must tell it to reply in the task thread**, and you must reply to it there (pass the task thread's `ts` explicitly to `slack-notify.sh` when the task contract has no `slack_ts` yet).
4. If the work is security-sensitive (parsers, crypto, authentication, key material, anything in `docs/security.md`), require a **plan first**: a written design in `docs/superpowers/plans/` posted for review before any code, reviewed against [`docs/security-plan-review-checklist.md`](../docs/security-plan-review-checklist.md).

## 2. Watching a task (the loop)

Use whatever interval the human set; reschedule at the end of **every** tick, because a loop that forgets to reschedule silently stops.

Detecting activity, in order of reliability:

1. Search Slack for the task slug, newest first (the connector's search tool). This finds thread replies that a channel read does not.
2. Read **both** threads: the gate thread (your assignment) and the task thread (the assignee's `started` post and everything after it). Compare timestamps against your last post; do not trust a paginated or filtered thread read to show only the new replies, and do not rely on top-level channel reads for replies at all. These each missed replies for hours on 2026-10-07.
3. Check the worktree directly: `git -C .worktrees/<slug> log --oneline -3`, `git status -s`, and `stat` on plan files. Commits, files and PRs are evidence; a claim in chat is not.
4. `gh pr list`, then `gh pr view <n> --json state,headRefOid,mergeStateStatus` and `gh pr checks <n>`.

If the assignee says you have not replied, check which thread it is reading before assuming a message was missed. The common cause is that the reply went in the other thread.

## 3. What to tell the human, and when

- Tell once, then stay quiet until the state changes: assigned but unclaimed, claimed but silent for more than an hour, hung or cancelled CI, a review you posted that the assignee has not answered.
- When you re-check an unchanged state, say so in one line. Do not repeat the full explanation every tick.
- An agent's own chat is invisible to you. If the evidence says it is stuck (a plan or approval waiting in its chat, a go-ahead it cannot take from Slack), say so and name the one action the human can take.
- Report what you verified and what you did not. A review that read a diff but did not run it must say so.

## 3a. CI that is not green on `main`

Read the failed or cancelled job's steps before drawing a conclusion (`gh run view <id> --json jobs`). A hung or cancelled infrastructure step is not a code failure, but `main` still shows a non-green run until someone reruns it. Rerunning is a change to shared state, so ask first unless the human has said to.

## 4. Reviewing

- Plans for security-sensitive work: review against the checklist, answer each question the assignee asked, separate MUST-FIX from SHOULD, and state the verdict (approved / approved with conditions / not approved). Conditions that change the buffering or state model go in before code; small ones can be folded in and checked on the PR.
- PRs: read the whole diff, confirm the head you reviewed is the head being merged, check every CI job, review code and security separately, post with `gh pr review --body-file`, and post the pointer in the task thread. Re-check the delta when the head changes.
- State what you could not run.

## 5. Merging and closing

Merge only when the human asks, with squash, CI green, review passed and merge state clean (`AGENTS.md` "Git & Commits"). After a merge, check that Linear shows the issue Done and that CI on `main` for the merge commit goes green, then start the next item from the queue. Do not start a new item while the previous one's merge CI is unexplained.

## 6. Linear hygiene

- One project per epic, and initiatives grouping projects, so the timeline reads at a glance. The coordinator tools can attach a project to an initiative but cannot create one; creating initiatives is done in Linear (the Linear Agent or UI).
- File follow-ups as issues instead of leaving them in comments, and link them from the thread.
