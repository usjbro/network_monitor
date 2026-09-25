#!/usr/bin/env bash
# Mark a task as done/review and announce it in Slack.
#
# Usage:
#   ./complete-task.sh <task-slug> <review|done> "<one-line summary>"

set -euo pipefail

TASK_SLUG="${1:?usage: complete-task.sh <task-slug> <review|done> \"<summary>\"}"
NEW_STATUS="${2:?usage: complete-task.sh <task-slug> <review|done> \"<summary>\"}"
SUMMARY="${3:-"<no summary given>"}"

if [[ "$NEW_STATUS" != "review" && "$NEW_STATUS" != "done" ]]; then
  echo "status must be 'review' or 'done'" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"
TASK_FILE="${REPO_ROOT}/coordination/tasks/${TASK_SLUG}.md"

if [[ ! -f "$TASK_FILE" ]]; then
  echo "No task file found: $TASK_FILE" >&2
  exit 1
fi

# Extract everything we need BEFORE mutating the file, so a task file
# missing an owner:/branch: line (hand-edited, or from an older script
# version) aborts here — under set -e, via the unset-var check below — with
# the file untouched, rather than after its status has already been
# rewritten but before the confirmation/Slack post ever runs.
OWNER="$(grep '^owner:' "$TASK_FILE" | cut -d' ' -f2)"
BRANCH="$(grep '^branch:' "$TASK_FILE" | cut -d' ' -f2)"
LINEAR_ID="$(grep '^linear_id:' "$TASK_FILE" | cut -d' ' -f2- || true)"
: "${OWNER:?$TASK_FILE has no owner: line}"
: "${BRANCH:?$TASK_FILE has no branch: line}"

# Update the status field in the frontmatter.
sed -i.bak "s/^status: .*/status: ${NEW_STATUS}/" "$TASK_FILE"
rm -f "${TASK_FILE}.bak"

echo "Marked ${TASK_SLUG} as ${NEW_STATUS}."
echo "Branch: ${BRANCH}"
echo
echo "Now fill in the Handoff section of $TASK_FILE by hand (files changed,"
echo "test results, risks) before a human reviews and merges."
if [[ -n "${LINEAR_ID:-}" ]]; then
  echo "Remember: also update ${LINEAR_ID}'s status in Linear (epic-task-cycle §2 steps 8-11) — this file and Linear must agree."
fi

if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
  "$SCRIPT_DIR/slack-notify.sh" "$NEW_STATUS" "$TASK_SLUG" "$OWNER" "$SUMMARY" || true
fi
