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
- `.claude/agents/`, `.codex/agents/` — per-tool subagent definitions (architect/developer/reviewer/tester), present in some local checkouts as of this writing but not yet committed to the repo — don't assume they exist in a fresh clone.
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
2. If this task has a Linear id and isn't ad hoc, create a Slack approval gate for it (if one doesn't already exist) and do not proceed past this step until it's approved — see "Slack Approval Gate" below.
3. Inspect relevant source code and tests.
4. Read applicable specification/protocol documentation.
5. Confirm acceptance criteria.
6. Write/update tests first where practical and demonstrate missing behavior.
7. Implement the smallest correct change.
8. Run relevant tests, fix failures, then run broader applicable tests.
9. Review `git diff`.
10. Update applicable `.ai/` state and `.ai/HANDOFF.md`.
11. Commit only when explicitly requested or authorized by the task.

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
- Anything else called out in Critical Invariants below or in relevant subsystem documentation.

**Never**
- Commit or push without explicit authorization; merge your own branch.
- Force-push over unmerged work, or `git checkout`/`git switch` inside a worktree.
- Invent host metrics, interface properties, or wire fields the agent doesn't actually emit.

## Critical Invariants

- Preserve `next.config.ts`'s deliberate Webpack/file-watching behavior and the `--webpack` flags in `package.json`; do not casually remove or “fix” them.
- Next.js and the capture agent bind to `127.0.0.1`. Never expose them by widening their bind. LAN access goes through the existing Caddy/mTLS front door; its LAN-facing change is deliberate/manual and must follow `deploy/README.md`.
- Before changing `deploy/Caddyfile`, read `docs/security.md` and `deploy/README.md`; rerun `deploy/test-mtls-rejection.sh` after the change.
- Startup `CAPTURE_INTERFACE` selection and runtime `set_interface` switching are distinct paths. Preserve their separate semantics.
- TLS decryption is explicit, per-process opt-in via `bin/osi-inspect.js`; this is passive visibility, not a blanket MITM. Keep key material and decrypted payloads ephemeral/in-memory, redacted, zeroed on eviction, and gated to loopback or mTLS as implemented.
- Ownership enrichment and GeoIP enrichment are opt-in; traceroute probes are on demand and bounded.
- Do not invent host metrics or interface properties. The agent emits system/interface identity and traffic counters; it does not emit CPU, memory, uptime, interface speed, or duplex. Add displayed data only with a real producer.
- Do not mistake static OSI metadata for live values. Do not reintroduce simulated traffic or metrics.
- A filename, type, issue, UI placeholder, spec, or comment alone does not prove functionality. Check source, tests, and current wire behavior.
- For `macos-app`, build/test with `CODE_SIGNING_ALLOWED=NO`; use a clean build after changing `NavigationLockDelegate` because optional delegate signature mismatches can evade incremental builds. The client key is Secure-Enclave-backed; the app does not read the CA private key. `deploy/sign-native-app-csr.sh` signs its CSR out of band.

## Read Before Modifying

- Capture-agent wire messages or `lib/agent-mapping.ts`: read `docs/wire-protocol.md`; update the Rust and TypeScript contract together.
- Ownership enrichment: read `docs/enrichment-protocol.md` and `docs/superpowers/specs/2026-08-28-ownership-enrichment-design.md`.
- Traceroute/GeoIP: read `docs/geoip-protocol.md` and `docs/superpowers/specs/2026-09-01-path-visualization-design.md`.
- Deployment or mTLS: read `docs/security.md` and `deploy/README.md`.
- macOS navigation/client-certificate security: read `macos-app/README.md` and `docs/security.md`.
- Significant architecture: read the relevant `docs/superpowers/specs/` entry, then follow the spec → plan process in `CONTRIBUTING.md`.
- TLS visibility or capture files: find and read the relevant design spec and plan under `docs/superpowers/` before extending them.

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
- `main` is GitHub branch-protected (2 required status checks) — a direct `git push origin main` is rejected outright, even for a trivial docs change. Always go through a PR.
- Never commit further work onto a branch whose PR already squash-merged without rebuilding it first — its merge-base with `main` predates the squash, so a new PR from it (or `gh pr diff`) shows the entire already-merged diff again as if new. Fix: fresh branch off current `main`, cherry-pick just the new commits, `git diff --stat origin/main <branch>` to confirm the diff is exactly what's intended before opening the PR.
- Run an independent review (`/code-review` or equivalent) before merging, even for docs/tooling-only changes — self-review misses real things.
- Push only when authorized (`git push -u origin <branch>`); merge with squash only once CI is green, review has passed, and GitHub reports `mergeable_state: "clean"` — see `epic-task-cycle`'s full gate list.

## Multi-Agent Coordination

Linear (via `epic-task-cycle`) stays the single source of truth for which epic task is active; `.ai/CURRENT_TASK.md` mirrors it locally. `coordination/` doesn't replace that — it's for planning and discussing parallel sub-work between agents (Claude Code, Codex, or both) working on independently-scoped pieces at the same time, with status kept truthful in both places.

`coordination/` lives at the **main repo root only** and is not copied into any `.worktrees/<slug>/` checkout, so a bare relative path to it resolves correctly only when your cwd already is the main repo root. From inside a worktree, either `cd` to the main repo root first, or just invoke the scripts below by their full path / after `cd`-ing — they resolve the main repo root themselves (`git rev-parse --git-common-dir`) regardless of where they're run from, so prefer them over hand-editing files under `coordination/` directly when your cwd is a worktree.

Slack posting needs a webhook. Configure it once via `coordination/.env` (`SLACK_WEBHOOK_URL=https://hooks.slack.com/...`, gitignored — the repo-wide `.env*` pattern covers it, never commit it) so it survives across shells/sessions instead of evaporating with an `export`; the scripts fall back to an already-exported `SLACK_WEBHOOK_URL` if no file exists. Note this is a plain Incoming Webhook URL, unrelated to any Claude-side Slack app/plugin connection — a standalone script can't use an MCP tool, so those are two separate integrations.

When the user asks for Slack coordination, post the proposed work in the designated channel and ask for feedback before proceeding when the decision affects scope or approach. Route independent work to the appropriate agent using `coordination/router-checklist.md`; keep ownership and boundaries clear, and discuss blockers in the relevant Slack thread. For the user's PRs, post in Slack asking for review or feedback and link the PR. When a Claude Code change is committed and has a pull request, review the PR and leave a concise GitHub review comment with concrete findings or approval context.

When the user asks for ongoing Slack monitoring, monitor the entire designated channel for new top-level posts and replies in active threads while the session remains active. Poll every 30 seconds unless the user sets another interval. Track the last-read message, not the last-sent message; on rate limits, back off and avoid repeating the same error notification. Review replies against task scope and repository guidance: implement correct, authorized decisions, and post concise clarification questions in the relevant thread.

0. **Check the Slack channel for pending questions from other agents/sessions before starting work** — not just when posting your own updates. Other agents (Codex, ChatGPT, another Claude session) may already be active in this repo and waiting on a decision; a question can sit unanswered for a long time if nobody's actively watching. This is a real, observed failure mode, not a hypothetical: a JAM-10/PR scope question from another agent sat unaddressed for 45+ minutes in one session because polling only checked messages after the checker's *own* last-sent message rather than the last message actually read — track "last read," never "last sent," when polling.
1. Write one `coordination/tasks/<task-slug>.md` contract per parallel sub-task, giving its owned files, do-not-edit boundaries, and validation — the same role `.ai/CURRENT_TASK.md` plays for a single task, scoped to one concurrent piece of work. If the sub-task contributes to a Linear-tracked epic task, record that issue id in the contract.
2. Create it with `coordination/scripts/new-task.sh <slug> <claude-code|codex> "<goal>" [linear-id]` — it creates the contract, a `.worktrees/<slug>/` worktree (sibling to the others, at the main repo root regardless of the script's own cwd), a branch matching the convention above, and (if a webhook is configured) posts a 🟡 started message to the shared Slack channel; without one, the task is still created, just without a Slack post.
3. Discuss blockers, interface questions, and plan changes in that Slack thread rather than guessing at another task's interface. See `coordination/router-checklist.md` (main repo root) for whether a piece suits Claude Code or Codex better.
4. On finish, run `coordination/scripts/complete-task.sh <slug> review "<summary>"` (updates the contract and posts to Slack), fill in its Handoff section by hand, and update the corresponding Linear issue's status per `epic-task-cycle` §2 steps 8-11 — the contract and Linear must agree, not just one of them.
5. A human (or reviewer agent) merges one branch at a time and removes its worktree, same as any other task branch.

## Slack Approval Gate

Any session working a Linear-tracked task — interactive or autonomous, trivial or not — gates on a Slack approval before implementing. Ad hoc work with no Linear id is exempt. Full design: `docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md`.

1. Before implementing, create the gate: `coordination/scripts/create-gate.sh <linear-id> <slug> "<plan-summary>" <interactive|autonomous>`. Use `interactive` when you're in a live chat session with a human present; use `autonomous` for a scheduled/unattended session with no one to ask directly. This posts the plan to `#network-monitor` and writes `coordination/gates/<linear-id>__<slug>.md` with `status: awaiting-approval`. Then stop — do not implement anything for this task yet.
2. Approval can come from either channel, both handled by the same session that created the gate:
   - **In-chat**: when the human replies with approval in the same conversation, check `coordination/scripts/gate-status.sh <linear-id> <slug>`. If it is `awaiting-approval`, run `approve-gate.sh`. Before dispatching, run `claim-gate-delegation.sh`; only the session whose claim succeeds may delegate. If the gate is already `approved` with `delegated=false delegation_claimed=false`, claim and resume without asking for approval again. If it is `approved` with `delegation_claimed=true delegated=false`, do not dispatch: ask the human to confirm no delegation is active, then run `reset-gate-delegation-claim.sh <linear-id> <slug> --confirm-no-active-delegation`, claim again, and dispatch. If `delegated=true`, report it as complete. After successful dispatch, run `mark-gate-delegated.sh <linear-id> <slug> <in-session|codex> [agent-type]`.
   - **Slack reply**: while your session remains active, you can poll `#network-monitor` instead of only waiting on the next chat message — see `coordination/watcher-prompt.md` (every 60 seconds, track last-read, not last-sent). A Slack approval follows the same claim-before-dispatch and interrupted-claim recovery steps as in-chat approval. There is no separate scheduled/cloud watcher: cloud agents cannot see local gate state, so polling only runs in the gate-creating session while it remains active.
3. On an unclear or negative reply, do not guess: for a clear rejection run `coordination/scripts/block-gate.sh <linear-id> <slug> "<reason>"` and reply explaining why in the same thread/chat; for an ambiguous reply, ask a clarifying question and leave the gate `awaiting-approval`. Never auto-retry a rejection.

If the session ends before a gate is resolved, nothing else picks it up automatically — it stays `awaiting-approval` until either a later session revisits the same task and polls/asks again, or someone notices the Slack post and a session gets started to act on it.

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
