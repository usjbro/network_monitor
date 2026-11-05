# Work routing

Which skill, loop, goal and agent to use for each kind of work. Every agent reads this when it starts a task, and the coordinator names the route in each assignment ([`templates/assignment.md`](templates/assignment.md)). The assignee copies it into the `## Route` section of its task contract.

This file only picks tools. [`AGENTS.md`](../AGENTS.md) still owns gates, approvals, Slack, merging and trust boundaries, and `CLAUDE.md` "Model Routing" still picks the model. [`router-checklist.md`](router-checklist.md) picks Claude Code or Codex when a task has no owner yet.

## Rules that beat any skill

Skills are generic, so a skill step can conflict with this repo. When it does, this repo wins:

- **Worktrees and branches:** use `coordination/scripts/new-task.sh`, not the worktree step in `using-git-worktrees` or the branch step in `epic-task-cycle`.
- **Merging:** James merges, or an agent he tells to in chat. Stop `finishing-a-development-branch` at the open PR.
- **Commits and pushes:** only when James asks or the assignment authorizes them, as `AGENTS.md` says. A skill's checklist doesn't authorize them.
- **Design and plan approval:** a skill's "user approved" step means James typing in chat. A Slack reply never counts.
- **Slack:** post only through `slack-notify.sh`.

## Pick the route

Skill names are bare here. Claude Code prefixes the Superpowers ones, as in `superpowers:systematic-debugging`.

| Work | Owner | Skill, in order | Loop or goal | Agent |
|---|---|---|---|---|
| Start a Linear issue | Codex | `epic-task-cycle` when it belongs to an epic | Contract `## Goal`; Codex `/goal` only if James asks (see below) | None |
| Work the queue | Codex, Claude Code for coordination | `epic-task-cycle` per issue | `AGENTS.md` "Continuous Work Queue", only under James's standing instruction | None |
| Write a spec | Claude Code | `brainstorming` | None; James approves | `architect` when subsystems compete; `security-engineer` for security-sensitive work |
| Write a plan | Codex, or Claude Code | `writing-plans` | None; the other agent reviews and gives the verdict. James approves a plan that lands in a PR | None |
| Write new code from an approved plan | Codex | `executing-plans`, or `subagent-driven-development` when tasks are independent; `test-driven-development`; `verification-before-completion` | Contract `## Goal`; Codex `/goal` only if James asks | Optional, see "Agents" |
| Update existing behaviour or fix a small bug | Codex | `test-driven-development`; `verification-before-completion` | Contract `## Goal`; Codex `/goal` only if James asks | None |
| Refactor without changing behaviour | Codex | Existing tests must pass before and after; `verification-before-completion` | None | None |
| Update docs | Whoever owns the task | `verification-before-completion`: check each claim against the code | None | None |
| Debug a failure | Codex; Claude Code for read-only triage | `systematic-debugging`, then `test-driven-development` for the regression test | None while exploring; once the cause is known, as for a fix | `sre` for CI or infrastructure |
| Debug an intermittent failure | Codex | `systematic-debugging` | A fixed repeat count, such as 20 runs before and after. Never loop until it passes | None |
| Review a plan | The agent that didn't write it, normally Claude Code | `docs/security-plan-review-checklist.md` for security-sensitive work; playbook section 4 | None | `security-engineer` for a second read when material |
| Review a PR | The agent that didn't write it | `code-review`, plus `security-review` as the PR hook reminds; on Codex, `codex review` meets that reminder | None. Re-review when the head changes | See "Review add-ons" |
| Answer review feedback | PR author | `receiving-code-review` | None | None |
| Watch tasks and PRs | Claude Code | `loop`; playbook section 2 | `/loop`, with Monitor for GitHub events | None |

## Goals

The contract's `## Goal` and `## Validation` are the normal way to state where a task ends. Codex's `/goal` goes further: it keeps a thread working until the condition is true.

Codex creates a goal only when explicitly asked, and doesn't infer one from an ordinary task. A gate approval or an assignment doesn't count, so `/goal` needs James to run it or ask for it, after the gate is approved. These rules apply either way.

- **Write it from the acceptance criteria.** For example: "JAM-123: all acceptance tests pass, PR open, CI green at the PR head, `review` posted."
- **End with the PR ready for James.** That's the end state in the example. A goal never includes merging, approving a gate or changing scope.
- **Authorize the commit.** A goal that reaches a PR needs the assignment to authorize committing and pushing.
- **PLAN FIRST ends the goal early.** The first goal ends when the plan is posted for review. Set a new goal only after the verdict.
- **Blocked on James, stop.** Post `blocked` rather than working around it.
- **Claude Code:** no `/goal` command is confirmed. Use the task contract's `## Goal` and `## Validation` instead.

## Loops

- `/loop` is for watching state that changes on its own, not for doing the work. Use the interval James set; `AGENTS.md` gives the default for Slack monitoring. Playbook section 2 says how to tick.
- Monitors and wakeups end with the session that started them. Restart them after a handoff.
- `ralph-loop` isn't a route here. It repeats a prompt until a completion promise, which skips the gate and review stops, and it's disabled on Codex. Use it only if James asks by name.

## Agents

Default to none. Use one only under `AGENTS.md` "Model / Agent Routing": parallel work, specialist knowledge or independent checking.

- **Role agents** are user-level, in `~/.claude/agents/` and `~/.codex/agents/`, so a fresh clone or another machine won't have them: `architect`, `backend-engineer`, `frontend-engineer`, `db-engineer`, `data-engineer`, `qa-engineer`, `security-engineer`, `sre`, `tpm`, `product-owner`, `business-analyst`, `prompt-engineer`.
- **Role agents don't edit files in Claude Code.** Their tools there are read-only plus Bash, so use them to analyse and advise.
- **Claude Code coordinates and doesn't implement.** It uses agents for review and analysis, not to write task code, unless James assigns it the implementation.

For an `in-session` gate delegation in Claude Code, which James must assign, record one of these as the `agent-type` in `mark-gate-delegated.sh`. Codex doesn't expose `general-purpose` or the plugin reviewer, so it picks from its own session list:

| Task nature | Agent |
|---|---|
| Cross-subsystem design or ambiguous requirements | `architect` |
| Security-sensitive design | `security-engineer` |
| Approved, scoped implementation | `general-purpose` |
| Reviewing a diff before merge | `pr-review-toolkit:code-reviewer`, recorded as `code-reviewer` because the script rejects colons |
| Checking acceptance criteria with tests | `qa-engineer` |

## Review add-ons

Add these to a PR review when the diff calls for them. They're confirmed for Claude Code. On Codex the plugin agents aren't exposed, so use `codex review` with that focus, or a `default` or `security-engineer` reviewer. Check the session's agent list before naming a plugin agent there.

| The diff has | Add |
|---|---|
| Error handling, catch blocks or fallbacks | `pr-review-toolkit:silent-failure-hunter` |
| New or changed tests, or new behaviour | `pr-review-toolkit:pr-test-analyzer` |
| New types | `pr-review-toolkit:type-design-analyzer` |
| Comment-heavy changes | `pr-review-toolkit:comment-analyzer` |
| Sonar findings or a gate failure | `sonarqube:sonarqube-reviewer`, or the SonarCloud public API if the CLI isn't logged in |
| Parsers, crypto, authentication, key material, anything in `docs/security.md` | `security-engineer`, plus `docs/security-plan-review-checklist.md` |

Run `code-review` at `max` or `ultra` only when James asks. Post reviews with `gh pr review --comment --body-file <file>`, plus a pointer in the task thread.

## Keeping this file true

Only name things you've confirmed are installed and enabled. Check with `codex features list`, `~/.codex/config.toml` and the skill list in a Claude Code session. If a name stops working, fix it here in the same change that notices it.
