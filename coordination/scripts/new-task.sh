#!/usr/bin/env bash
# Create a new coordination task: worktree + branch + task contract file, and
# announce it in Slack.
#
# Usage:
#   ./new-task.sh <task-slug> <claude-code|codex> "<one-line goal>" [linear-id]
#
# linear-id (optional) is the parent Linear issue this task contributes to
# (e.g. JAM-9) — recorded in the contract and folded into the branch name to
# match this repo's <branch-prefix>/<linear-id>-<slug> convention. Leave it
# off for coordination work with no Linear-tracked parent.
#
# Requires: git, and a Slack webhook for the Slack post (optional — the task
# is still created without one, just no Slack message goes out). Configure
# it once via coordination/.env (SLACK_WEBHOOK_URL=https://hooks.slack.com/...,
# gitignored) so it persists across shells, or export SLACK_WEBHOOK_URL
# yourself for a one-off.

set -euo pipefail

TASK_SLUG="${1:?usage: new-task.sh <task-slug> <claude-code|codex> \"<goal>\" [linear-id]}"
OWNER="${2:?usage: new-task.sh <task-slug> <claude-code|codex> \"<goal>\" [linear-id]}"
GOAL="${3:-"<fill in>"}"
LINEAR_ID="${4:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"
TASKS_DIR="$REPO_ROOT/coordination/tasks"

# Every real branch in this repo (Linear's own gitBranchName, e.g.
# jamesmbrownjr/jam-9-...) uses this prefix — it is NOT derivable from local
# git config: `git config user.email` resolves to GitHub's noreply address
# (30867715+usjbro@users.noreply.github.com) and `git config user.name` /
# `gh api user` both give "usjbro", neither of which matches. Override with
# COORDINATION_BRANCH_PREFIX if that handle ever changes.
BRANCH_PREFIX="${COORDINATION_BRANCH_PREFIX:-jamesmbrownjr}"

if [[ -n "$LINEAR_ID" ]]; then
  LINEAR_ID_LOWER="$(echo "$LINEAR_ID" | tr '[:upper:]' '[:lower:]')"
  BRANCH="${BRANCH_PREFIX}/${LINEAR_ID_LOWER}-${TASK_SLUG}"
else
  BRANCH="${BRANCH_PREFIX}/${TASK_SLUG}"
fi

WORKTREE_DIR="$REPO_ROOT/.worktrees/${TASK_SLUG}"
TASK_FILE="${TASKS_DIR}/${TASK_SLUG}.md"

if [[ "$OWNER" != "claude-code" && "$OWNER" != "codex" ]]; then
  echo "owner must be 'claude-code' or 'codex'" >&2
  exit 1
fi

if [[ -f "$TASK_FILE" ]]; then
  echo "Task file already exists: $TASK_FILE" >&2
  exit 1
fi

# Create the worktree/branch FIRST — it's the more failure-prone step (name
# collision, a stale .worktrees/<slug> left from an aborted prior run, main
# not up to date). If it fails, nothing has been written yet, so a retry
# isn't blocked by a leftover task file tripping the check above.
git -C "$REPO_ROOT" worktree add "$WORKTREE_DIR" -b "$BRANCH" main

mkdir -p "$TASKS_DIR"

cat > "$TASK_FILE" <<EOF
---
task: ${TASK_SLUG}
owner: ${OWNER}
status: open
branch: ${BRANCH}
linear_id: ${LINEAR_ID}
depends_on: []
created: $(date +%Y-%m-%d)
---

## Goal

${GOAL}

## Owned files

- <fill in>

## Do not edit

- <fill in>

## Validation

- <fill in>

## Handoff

- **Files changed:**
- **Test results:**
- **Risks / follow-ups:**
- **Branch:** \`${BRANCH}\`
EOF

echo "Task file:  $TASK_FILE"
echo "Worktree:   $WORKTREE_DIR"
echo "Branch:     $BRANCH"
echo
echo "Next: cd $WORKTREE_DIR && (claude / codex) — point the agent at the task file."
if [[ -n "$LINEAR_ID" ]]; then
  echo "Remember: also update ${LINEAR_ID}'s status in Linear when this task's status changes."
fi

if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
  "$SCRIPT_DIR/slack-notify.sh" "started" "$TASK_SLUG" "$OWNER" "$GOAL" || true
fi
