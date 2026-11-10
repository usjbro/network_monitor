#!/usr/bin/env bash
# Create a new coordination task: worktree + branch + task contract file, and
# announce it in Slack.
#
# Usage:
#   ./new-task.sh <task-slug> <claude-code|codex> "<one-line goal>" [issue-key]
#
# issue-key (optional) is the parent Jira issue this task contributes to
# (e.g. KAN-12) — recorded in the contract as issue_key and folded into the
# branch name as Jira's default KAN-12-<slug> (lib.sh task_branch). Leave it
# off for coordination work with no tracked parent; the branch is then
# <branch-prefix>/<slug>.
#
# Requires: git, and Slack credentials for the started post (optional — the
# task is still created without them, just no Slack message goes out).
# Configure once via coordination/.env (gitignored): SLACK_BOT_TOKEN (+
# optionally SLACK_CHANNEL_ID) for the chat.postMessage path (needed to
# originate this task's own thread), or SLACK_WEBHOOK_URL as a fallback that
# can't originate one — see slack-notify.sh.

set -euo pipefail

TASK_SLUG="${1:?usage: new-task.sh <task-slug> <claude-code|codex> \"<goal>\" [issue-key]}"
OWNER="${2:?usage: new-task.sh <task-slug> <claude-code|codex> \"<goal>\" [issue-key]}"
GOAL="${3:-"<fill in>"}"
ISSUE_KEY="${4:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"
TASKS_DIR="$REPO_ROOT/coordination/tasks"

BRANCH="$(task_branch "$TASK_SLUG" "$ISSUE_KEY")"

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
issue_key: ${ISSUE_KEY}
depends_on: []
created: $(date +%Y-%m-%d)
slack_ts:
---

## Goal

${GOAL}

## Route

Skills, goal or loop, and agent, from \`coordination/work-routing.md\`.

- <fill in>

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
if [[ -n "$ISSUE_KEY" ]]; then
  echo "Remember: also update ${ISSUE_KEY}'s status in Jira when this task's status changes."
fi

if slack_configured; then
  SLACK_MESSAGE="${GOAL}
Worktree: \`${WORKTREE_DIR}\`"
  slack_post_and_record "$TASK_FILE" "started" "$TASK_SLUG" "$OWNER" "$SLACK_MESSAGE" || true
fi
