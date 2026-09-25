# Network Monitor — Codex Instructions

## Mission

Build and maintain Network Monitor according to verified repository implementation, approved requirements, tests, and project architecture.

## Start Here

For normal development:

1. Read `.ai/CURRENT_TASK.md`.
2. Read `.ai/HANDOFF.md` only when continuing previous work.
3. Inspect relevant implementation and tests.
4. Read relevant subsystem documentation only when necessary.

Do not read the entire repository or all documentation by default.

## Repository Guidance

The repository contains detailed project-specific guidance in `CLAUDE.md`. When a task involves architecture, security boundaries, capture behavior, deployment constraints, TLS visibility, macOS behavior, or another non-obvious subsystem, inspect the applicable guidance there and its referenced documentation before editing.

Do not assume documentation proves implementation exists. Verify against code and tests.

## Project Structure

- `app/`, `components/`, `lib/` — Next.js/React/TypeScript relay and UI (`npm test` / `npx vitest run`).
- `capture-agent/` — the Rust capture agent (`cargo test`); see its own README for macOS `access_bpf` setup.
- `deploy/` — Caddy mTLS reverse proxy for LAN access (loopback-only by default).
- `macos-app/` — the native SwiftUI/WKWebView viewer.
- `docs/` — user-facing docs; `docs/superpowers/specs/` and `docs/superpowers/plans/` hold design specs and implementation plans for nontrivial work (see `CONTRIBUTING.md`).
- `.ai/` — `CURRENT_TASK.md`, `HANDOFF.md`, `DECISIONS.md`, `PROJECT_STATE.md`, `TEST_STATUS.md` (see Sources of Truth below).
- `.claude/agents/`, `.codex/agents/` — per-tool subagent definitions (architect/developer/reviewer/tester) for this repo.
- `.agents/skills/` — shared skills, e.g. `epic-task-cycle` (the Linear branch → PR → merge cycle).
- `coordination/` — cross-agent task contracts and Slack coordination for parallel sub-work; see Multi-Agent Coordination below.

## Sources of Truth

- Repository/GitHub: actual implementation, tests, CI, and commits.
- Linear: tracked work and workflow state.
- Notion: requirements and specifications where applicable.
- `.ai/PROJECT_STATE.md`: concise verified project orientation.
- `.ai/CURRENT_TASK.md`: active unit of work.
- `.ai/HANDOFF.md`: cross-session continuation state.
- `.ai/DECISIONS.md`: durable architectural decisions.
- `.ai/TEST_STATUS.md`: latest verified test state.

When sources disagree, explicitly report the disagreement.

## Required Workflow

1. Read `.ai/CURRENT_TASK.md`.
2. Inspect relevant source code and tests.
3. Read applicable specification/protocol documentation.
4. Confirm acceptance criteria.
5. Write/update tests first where practical and demonstrate missing behavior.
6. Implement the smallest correct change.
7. Run relevant tests, fix failures, then run broader applicable tests.
8. Review `git diff`.
9. Update applicable `.ai/` state and `.ai/HANDOFF.md`.
10. Commit only when explicitly requested or authorized by the task.

## Scope Control

- Stay on the assigned task; avoid unrelated refactoring and speculative functionality.
- Do not change architecture casually; prefer small, reviewable changes.
- Inspect before editing.
- Do not infer functionality from filenames, comments, issue titles, documentation, or UI placeholders.
- Never declare success without verification.

## Boundaries — Always / Ask first / Never

**Always**
- Read `.ai/CURRENT_TASK.md` (and the relevant `coordination/tasks/` contract, if this work is part of one) before editing.
- Treat source and tests as evidence; verify before claiming something works.
- Keep the capture agent and Next.js bound to `127.0.0.1`; LAN access only through `deploy/`.

**Ask first**
- Changing `deploy/Caddyfile`, `next.config.ts`'s webpack/file-watching block, or the `--webpack` flags in `package.json`.
- Adding a new dependency, widening a network bind, or touching the wire protocol (`capture-agent/src/wire.rs`, `lib/agent-mapping.ts`, `lib/types.ts` must change together — see `docs/wire-protocol.md`).
- Anything else `CLAUDE.md`'s Critical Invariants section calls out — that list is the detailed source of truth; this is a summary, not a replacement for reading it.

**Never**
- Commit or push without explicit authorization; merge your own branch.
- Force-push over unmerged work, or `git checkout`/`git switch` inside a worktree.
- Invent host metrics, interface properties, or wire fields the agent doesn't actually emit.

## Critical Thinking

- If a task's stated goal and its owned-files/do-not-edit scope conflict, stop and ask rather than silently expanding scope.
- Root-cause bugs — don't patch symptoms without checking upstream data/state first (the `systematic-debugging` skill covers this in depth).
- A plan or spec's own code sketch can be wrong; verify it against the actual code rather than transcribing it (see `epic-task-cycle`'s §2 step 4 for a concrete rate of this happening).

## Test-Driven Development

TDD is the default. Code compiling, a rendered UI, a Linear issue marked Done, documentation describing a feature, or a relevant file existing does not establish correct behavior. Verify the behavior against requirements and tests.

## Testing

- Every task must leave the relevant test suite(s) green — `npx vitest run` for TypeScript, `cargo test` for the capture agent; see `CONTRIBUTING.md` for the full CI-matching list (fuzzing, audit, live-loopback, Playwright).
- New behavior needs a new test; don't just eyeball it.
- Record actual commands and results in `.ai/TEST_STATUS.md` — compilation, a rendered screen, or a tracker status is not test evidence.

## Context Discipline

- Start with `.ai/CURRENT_TASK.md`; load only relevant files and deeper docs.
- Avoid rereading unchanged large documents; prefer references over copied content.
- Do not load every `.ai/` file automatically.
- Avoid unnecessary subagents or multiple agents independently rediscovering the same state.
- Prefer fresh sessions at meaningful task boundaries.

## Model / Agent Routing

Use the least expensive model capable of reliably completing the task. Route architecture, security design, cross-subsystem work, ambiguous requirements, difficult root-cause analysis, and major performance/data-model decisions to stronger reasoning. Use standard models for normal implementation, testing, debugging, refactoring, review, and documentation; use lighter models for mechanical edits. Escalate only when complexity requires it.

Use agents only when work is genuinely parallel, specialization helps, or independent verification has material value. Keep agent scopes narrow; there is no fixed pipeline.

## Git & Commits

- One task = one git worktree, under `.worktrees/<slug>/` in this repo (see the `using-git-worktrees` skill).
- Branch naming follows the Linear issue's own `gitBranchName` where one exists (`<github-username>/<linear-id>-<slug>`, e.g. `jamesmbrownjr/jam-9-...`) — don't invent a different scheme; confirm it's safe before using it (`epic-task-cycle` §2 step 2).
- Never `git checkout`/`git switch` inside a worktree — it's already on the right branch. If you think you need to switch, stop and ask.
- Commit only when explicitly authorized, with the attribution footer given by current session instructions — never a stale one.
- `git checkout next-env.d.ts` before committing if `npm run dev` ran this session; it's a build side-effect file unrelated to your change.
- Push only when authorized (`git push -u origin <branch>`); merge with squash only once CI is green, review has passed, and GitHub reports `mergeable_state: "clean"` — see `epic-task-cycle`'s full gate list.

## Multi-Agent Coordination

Linear (via `epic-task-cycle`) stays the single source of truth for which epic task is active; `.ai/CURRENT_TASK.md` mirrors it locally. `coordination/` doesn't replace that — it's for planning and discussing parallel sub-work between agents (Claude Code, Codex, or both) working on independently-scoped pieces at the same time, with status kept truthful in both places.

`coordination/` lives at the **main repo root only** — it is not committed and is not copied into any `.worktrees/<slug>/` checkout, so a bare relative path to it resolves correctly only when your cwd already is the main repo root. From inside a worktree, either `cd` to the main repo root first, or just invoke the scripts below by their full path / after `cd`-ing — they resolve the main repo root themselves (`git rev-parse --git-common-dir`) regardless of where they're run from, so prefer them over hand-editing files under `coordination/` directly when your cwd is a worktree.

1. Write one `coordination/tasks/<task-slug>.md` contract per parallel sub-task, giving its owned files, do-not-edit boundaries, and validation — the same role `.ai/CURRENT_TASK.md` plays for a single task, scoped to one concurrent piece of work. If the sub-task contributes to a Linear-tracked epic task, record that issue id in the contract.
2. Create it with `coordination/scripts/new-task.sh <slug> <claude-code|codex> "<goal>" [linear-id]` — it creates the contract, a `.worktrees/<slug>/` worktree (sibling to the others, at the main repo root regardless of the script's own cwd), a branch matching the convention above, and (if `SLACK_WEBHOOK_URL` is exported) posts a 🟡 started message to the shared Slack channel; without it, the task is still created, just without a Slack post.
3. Discuss blockers, interface questions, and plan changes in that Slack thread rather than guessing at another task's interface. See `coordination/router-checklist.md` (main repo root) for whether a piece suits Claude Code or Codex better.
4. On finish, run `coordination/scripts/complete-task.sh <slug> review "<summary>"` (updates the contract and posts to Slack), fill in its Handoff section by hand, and update the corresponding Linear issue's status per `epic-task-cycle` §2 steps 8-11 — the contract and Linear must agree, not just one of them.
5. A human (or reviewer agent) merges one branch at a time and removes its worktree, same as any other task branch.

## Session Completion

For substantial work: test → review → update `TEST_STATUS` and `PROJECT_STATE` when applicable → update `DECISIONS` if needed → update `HANDOFF` → commit only when authorized.

## Commands

```sh
npm install
npm run dev       # Next.js; loopback only
npm run build
npm run start     # production; loopback only
npm run lint
npm run clean
npm test          # Vitest
npx vitest run
```

TypeScript/React tests live in `lib/__tests__/`. The Rust capture agent has its own test suite:

```sh
cd capture-agent
cargo build --release
cargo test
cargo run --release
```

See `CONTRIBUTING.md` for broader CI, fuzzing, audit, and integration-test requirements.

<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
