# Architectural and Technical Decisions

Record durable decisions only when supported by repository evidence or an approved requirement. Reference an existing spec/ADR when one already records the decision; do not turn session discussion into an ADR.

## ADR-NNN — [Decision title]

Date:
[YYYY-MM-DD]

Status:
Accepted / Superseded / Proposed

Context:
[Why a decision was required]

Decision:
[What was decided]

Reasoning:
[Concise rationale]

Consequences:
[Important implications]

Evidence / References:
[Paths, issue IDs, docs, commits]

## ADR-001 — Reconcile agent-coordination-kit with Linear/epic-task-cycle

Date:
2026-09-24

Status:
Accepted

Context:
A downloaded `agent-coordination-kit.zip` proposed a parallel task-contract + Slack-webhook coordination system (`coordination/tasks/*.md`, `agent/<slug>` branches) for running multiple agents. This repo already tracks active work through Linear via the `epic-task-cycle` skill and `.ai/CURRENT_TASK.md`, and branches by the Linear issue's own `gitBranchName` (`<github-username>/<linear-id>-<slug>`).

Decision:
`coordination/tasks/*.md` contracts are sub-task planning/discussion for parallel agent work *within* an active Linear-tracked epic task, not a replacement tracker. Linear + `.ai/CURRENT_TASK.md` remain the source of truth for which epic task is active; a coordination task's status must be kept in sync with its parent Linear issue, not just the local contract file. `coordination/scripts/new-task.sh` branches as `<github-username>/<slug>` (derived from `git config user.email`), matching this repo's real convention instead of the kit's `agent/<slug>` default, and creates worktrees under `.worktrees/<slug>/` instead of a sibling directory.

Reasoning:
Avoids two competing "what's actually being worked on" trackers, and keeps branch/worktree naming consistent with every other branch in this repo.

Consequences:
Any agent using `coordination/tasks/` must also update the parent Linear issue's status per `epic-task-cycle` §2 steps 8-11. `coordination/` lives at the main repo root (not per-worktree); `new-task.sh`/`complete-task.sh` resolve `REPO_ROOT` via `git rev-parse --git-common-dir` so they always find it and create sibling worktrees under the main repo's `.worktrees/`, regardless of which worktree they're invoked from.

Evidence / References:
User direction in this session (AskUserQuestion answers, 2026-09-24, on coordination scope and branch naming); `AGENTS.md` Multi-Agent Coordination and Git & Commits sections; `.agents/skills/epic-task-cycle/SKILL.md` §2 steps 2, 8-11.

## ADR-002 — coordination task branch prefix is hardcoded, not derived

Date:
2026-09-24

Status:
Accepted

Context:
`new-task.sh` originally derived its branch prefix from `git config user.email` on the assumption it would yield `jamesmbrownjr`, matching every real branch in this repo (Linear's own `gitBranchName`, e.g. `jamesmbrownjr/jam-9-...`). Running the script for real (user: "exercise it") produced `30867715+usjbro/verify-coordination-kit` instead — `git config user.email` here is GitHub's noreply address (`30867715+usjbro@users.noreply.github.com`), and `git config user.name`/`gh api user` both give `usjbro`. None of these locally-derivable values match `jamesmbrownjr`; that prefix comes from Linear's own branch-name generation for this user, which has no equivalent local command.

Decision:
`new-task.sh` hardcodes `BRANCH_PREFIX="${COORDINATION_BRANCH_PREFIX:-jamesmbrownjr}"` — a fixed default with an environment-variable override, rather than attempting to derive it from git/GitHub config.

Reasoning:
No local command produces the correct value; a wrong-but-plausible-looking derivation (as the original code was) is worse than an explicit, documented constant, since it fails silently and produces branches that don't match the rest of the repo's history.

Consequences:
If this user's Linear-assigned branch handle ever changes, `COORDINATION_BRANCH_PREFIX` must be set (or the default edited) — there's no way for the script to detect that on its own.

Evidence / References:
End-to-end exercise of `new-task.sh` in this session, 2026-09-24: first real run produced the wrong branch name; root-caused via `git config user.email`/`user.name` and `gh api user --jq .login`, all returning `usjbro`-derived values; corrected and re-verified against `jamesmbrownjr/jam-9-...` (this worktree's branch) and `jamesmbrownjr/jam-10-...` (a second real worktree found at `/private/tmp/network-monitor-jam10` during cleanup).
