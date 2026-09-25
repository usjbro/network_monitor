---
task: <task-slug>
owner: claude-code | codex
status: open | in-progress | blocked | review | done
branch: jamesmbrownjr/<task-slug>
depends_on: []
created: <date>
---

## Goal

One or two sentences: what "done" looks like.

## Owned files

The only files/directories this task may edit.

- `path/to/file`

## Do not edit

Explicitly out of scope, especially anything another in-flight task owns.

- `path/to/other/thing`

## Validation

How to prove it's done — exact commands.

- `<test command>`

## Handoff

Filled in by the agent when finished. This is what the next
agent/human reads — not the chat transcript.

- **Files changed:**
- **Test results:**
- **Risks / follow-ups:**
- **Branch:** `jamesmbrownjr/<task-slug>`
