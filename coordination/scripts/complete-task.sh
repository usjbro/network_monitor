#!/usr/bin/env bash
# Mark a task as done/review and announce it in Slack.
#
# Usage:
#   ./complete-task.sh <task-slug> <review|done> "<one-line summary>"

set -euo pipefail

TASK_SLUG="${1:?usage: complete-task.sh <task-slug> <review|done> \"<summary>\"}"
NEW_STATUS="${2:?usage: complete-task.sh <task-slug> <review|done> \"<summary>\"}"
SUMMARY="${3:-"<no summary given>"}"

# Always resolve to the main repo root, even when invoked from inside a
# linked worktree — see the matching comment in new-task.sh.
GIT_COMMON_DIR="$(git rev-parse --git-common-dir)"
case "$GIT_COMMON_DIR" in
  /*) REPO_ROOT="$(cd "$(dirname "$GIT_COMMON_DIR")" && pwd)" ;;
  *)  REPO_ROOT="$(git rev-parse --show-toplevel)" ;;
esac
TASK_FILE="${REPO_ROOT}/coordination/tasks/${TASK_SLUG}.md"

if [[ ! -f "$TASK_FILE" ]]; then
  echo "No task file found: $TASK_FILE" >&2
  exit 1
fi

# Update the status field in the frontmatter.
sed -i.bak "s/^status: .*/status: ${NEW_STATUS}/" "$TASK_FILE"
rm -f "${TASK_FILE}.bak"

OWNER="$(grep '^owner:' "$TASK_FILE" | cut -d' ' -f2)"
BRANCH="$(grep '^branch:' "$TASK_FILE" | cut -d' ' -f2)"
LINEAR_ID="$(grep '^linear_id:' "$TASK_FILE" | cut -d' ' -f2- || true)"

echo "Marked ${TASK_SLUG} as ${NEW_STATUS}."
echo "Branch: ${BRANCH}"
echo
echo "Now fill in the Handoff section of $TASK_FILE by hand (files changed,"
echo "test results, risks) before a human reviews and merges."
if [[ -n "${LINEAR_ID:-}" ]]; then
  echo "Remember: also update ${LINEAR_ID}'s status in Linear (epic-task-cycle §2 steps 8-11) — this file and Linear must agree."
fi

if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
  "$(dirname "$0")/slack-notify.sh" "$NEW_STATUS" "$TASK_SLUG" "$OWNER" "$SUMMARY" || true
fi
