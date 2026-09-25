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
   (e.g. changing an event schema that the detection engine, the
   location-agents, and the Slack formatter all consume)?
   - Yes → Claude Code. Better suited to holding a large, tangled context
     and making coordinated cross-file edits, and can spawn subagents to
     explore different parts of the project in parallel.
   - No, it's contained to one module/file → either; prefer Codex to free up
     Claude Code for the harder work.

3. **Do you want to fire it off and check back later, without babysitting?**
   - Yes → Codex (async, sandboxed).
   - No, you want to stay in the loop with fine-grained permission prompts →
     Claude Code.

4. **Is it a refactor, migration, or "implement exactly this interface"
   task?**
   - Yes → Codex.

5. **Is it an architectural decision, a new detection-rule design, or
   anything where you'd want a subagent to go investigate before writing
   code?**
   - Yes → Claude Code.

## Quick examples from this project

| Task | Owner | Why |
|---|---|---|
| Add a new correlation rule for lateral-movement detection, design unclear | Claude Code | needs judgment calls on what signal to correlate |
| Refactor the Slack status-formatter to a shared template function | Codex | fully specified, single-module |
| Change the location-agent → Slack event schema everywhere it's used | Claude Code | cross-cutting, multiple subsystems |
| Migrate the alert queue from polling to webhooks per attached spec | Codex | scoped, async, sandboxable |
| Investigate why probing detection has false positives at Location B | Claude Code | exploratory, needs judgment |

## When in doubt

Default to Claude Code for the first pass on anything new or ambiguous, and
move to Codex once the task has been broken down into scoped, well-specified
pieces.
