# Router checklist — Claude Code vs Codex

Run through this before creating a task file. Whoever plans the work (you, or
a planning session) tags each task with an owner using this checklist.

## Ask these in order

1. **Is the task fully specified, with a clear "done" condition, before any
   code is written?**
   - Yes → lean Codex. It can run semi-autonomously in a sandbox on a
     well-bounded spec without needing mid-task judgment calls.
   - No / requirements will get clarified as you go → Claude Code.

2. **Does it require reasoning across many files or subsystems at once**
   (e.g. changing a wire event that the capture agent, the relay and the
   UI all consume)?
   - Yes → Claude Code for the plan, then Codex implements against it.
     Claude Code is better suited to holding a large, tangled context and
     can spawn subagents to explore parts of the project in parallel.
   - No, it's contained to one module/file → either; prefer Codex to free up
     Claude Code for the harder work.

3. **Do you want to fire it off and check back later, without babysitting?**
   - Yes → Codex (async, sandboxed).
   - No, you want to stay in the loop with fine-grained permission prompts →
     Claude Code.

4. **Is it a refactor, migration, or "implement exactly this interface"
   task?**
   - Yes → Codex.

5. **Is it an architectural decision, a new protocol design, or
   anything where you'd want a subagent to go investigate before writing
   code?**
   - Yes → Claude Code.

## Quick examples from this project

| Task | Owner | Why |
|---|---|---|
| Design a new capture-file feature whose scope is unclear | Claude Code | needs judgment calls before any code |
| Implement an approved plan task with its tests | Codex | fully specified, bounded |
| Change a wire event in the Rust agent and `lib/agent-mapping.ts` | Codex, after Claude Code reviews the plan | crosses subsystems, so the plan comes first |
| Fix a flaky test once the failing fixture is known | Codex | scoped, with a clear done condition |
| Work out why a metric disagrees with the capture | Claude Code | exploratory, needs judgment |

Today's default is that Claude Code coordinates, specs and reviews, and Codex implements. Use the questions above when James asks for a different split.

## When in doubt

Default to Claude Code for the spec or plan on anything new or ambiguous, and
move to Codex once the task has been broken down into scoped, well-specified
pieces.

## Choosing the skill, loop, goal and agent

Once a task has an owner, use [`work-routing.md`](work-routing.md). It also lists the role agents for an `in-session` gate delegation (see `docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md`).
