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
- [x] `SLACK_WEBHOOK_URL` made durable via `coordination/.env` (gitignored) instead of requiring `export` every shell; mechanically verified with a fake URL, then wired to the user's real Incoming Webhook and confirmed the message actually landed in `#network-monitor` via `slack_read_channel` — not just a clean `curl` exit code.
- [x] Work committed and pushed — `main` is branch-protected (direct push rejected by GitHub), so this went through PRs instead of a direct push: usjbro/network_monitor#220 (`coordination/`) and #222 (`AGENTS.md`/`CLAUDE.md`/`.ai/`; supersedes #221, closed — that branch's merge-base with `main` predated JAM-9's squash-merge, so its diff showed the entire already-merged field-model change as if new).
- [x] Independent code review run on both #220 and #222 (`/code-review`, "careful review" per explicit user direction) — real findings on both, all fixed and re-verified: 4 script bugs in #220 (status mutated before validating owner/branch existed; task file written before the more-failure-prone `git worktree add`, blocking retry on failure; unvalidated status value reaching `sed` unescaped; undocumented `python3` dependency with a silently-swallowed curl failure), plus 5 accuracy issues in #222 (stale `#221` references, `.ai/` vs. undocumented-untracked `.claude/agents/`/`.codex/agents/` claim, an uncaveated pointer to a doc `PROJECT_STATE.md` itself flags as stale, `AGENTS.md`/`CLAUDE.md` duplication undercutting the new "source of truth" claim, a deleted docs pointer with no replacement).
- [x] Per explicit user direction ("update CLAUDE.md/other files if new instructions are needed"), captured this session's durable lessons in the tracked `.claude/skills/epic-task-cycle/SKILL.md` (Environment gotchas: phantom-diff from reusing a squash-merged branch, `main`'s branch protection, review-before-merge) and `AGENTS.md` (same three in Git & Commits, plus a new lead item in Multi-Agent Coordination: check Slack for pending cross-agent questions before starting work, track last-*read* not last-*sent* when polling — drawn directly from missing the JAM-10 question for 45+ minutes).
- [ ] User review/merge of #220 and #222.

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

## Status

Ready for review — merge complete, scripts exercised end-to-end (including a real Slack webhook), independently reviewed with all findings fixed and re-verified, pushed as PR #220 and #222. Awaiting user review/merge.
