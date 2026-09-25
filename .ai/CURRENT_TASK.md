# Current Task

## Issue

User-requested agent-coordination-kit merge; no Linear/GitHub issue ID supplied (meta/tooling task, not an epic item).

## Objective

Merge `~/Downloads/agent-coordination-kit.zip` (multi-agent task contracts, a Claude-Code-vs-Codex router checklist, Slack status-notify scripts) into this repo's `AGENTS.md`/`CLAUDE.md` and a new `coordination/` directory, reconciling its generic conventions with this repo's actual Linear/epic-task-cycle workflow, branch naming, and worktree layout rather than copying it unmodified.

## Acceptance Criteria

- [x] Kit content read in full before any merge; scripts checked for malicious/exfiltrating behavior.
- [x] `AGENTS.md` gains Project Structure, Boundaries, Critical Thinking, Testing, Git & Commits, and Multi-Agent Coordination sections with no unresolved `<fill in>` placeholders, grounded in this repo's real architecture.
- [x] `CLAUDE.md` points to `AGENTS.md` as the cross-agent source of truth for those sections without losing existing content.
- [x] `coordination/` created with `router-checklist.md` and `tasks/TEMPLATE.md`/`tasks/example-lateral-movement-rule.md` unchanged, and `scripts/*.sh` adapted to this repo's real branch (`<github-username>/<slug>`) and worktree (`.worktrees/<slug>/`) conventions.
- [x] Multi-Agent Coordination section positions `coordination/tasks/` as sub-task planning *under* an active Linear-tracked epic, per explicit user direction — Linear/`.ai/CURRENT_TASK.md` remains the single source of truth for the active task.
- [x] Scripts are executable and `bash -n` clean.
- [x] `REPO_ROOT` resolution fixed to always land on the main repo root (via `git rev-parse --git-common-dir`) even when invoked from inside a linked worktree, per explicit user direction; `coordination/` moved from the worktree to the main repo root to match. Dry-run confirmed the resolved path from inside this worktree.
- [x] Confirmed and fixed a real breakage this uncovered: bare relative `coordination/...` references in `AGENTS.md`'s prose fail from any worktree cwd (`ls coordination` → not found there) since the directory is uncommitted and only exists at the main root. Reworded that section to say so and to prefer the self-resolving scripts.
- [x] Scripts verified end-to-end, invoked from inside this worktree (the real usage scenario): `new-task.sh` (no linear-id, with linear-id), `complete-task.sh` (both paths), the duplicate-task guard, and the invalid-owner guard. Found and fixed a real bug along the way (see below); all test artifacts (2 branches, 2 worktrees, 2 task files) removed afterward.
- [ ] User review of the merged content.

## Relevant Areas

- `AGENTS.md`, `CLAUDE.md`
- `coordination/` (new)
- `.agents/skills/epic-task-cycle/SKILL.md` (referenced, not modified)

## Constraints

- Do not modify tracker policy, `CONTRIBUTING.md`, or application code.
- Do not commit unless explicitly requested.
- Resolved: `coordination/scripts/*.sh` now always resolve `REPO_ROOT` to the main repo root (`git rev-parse --git-common-dir`, following it to the main `.git`'s parent when it's an absolute path), regardless of which worktree they're invoked from — `coordination/` itself lives at the main repo root, not per-worktree.

## Out of Scope

- Rewriting `router-checklist.md` or `tasks/example-lateral-movement-rule.md` content (kept verbatim per explicit instruction).
- Wiring an actual `SLACK_WEBHOOK_URL`.

## Status

Ready for review — merge complete, scripts syntax-checked but not executed end-to-end.
