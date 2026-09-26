#!/usr/bin/env bash
# Post a task status update to the shared coordination Slack channel.
#
# Usage:
#   ./slack-notify.sh <status> <task-slug> <owner> "<message>"
#
# Requires a Slack webhook (Slack app → Incoming Webhooks, pointed at the
# shared coordination channel) — set via coordination/.env
# (SLACK_WEBHOOK_URL=https://hooks.slack.com/..., gitignored) or exported
# directly. Also requires curl and python3 (used to JSON-encode the message).

set -euo pipefail

STATUS="${1:?status}"
TASK_SLUG="${2:?task-slug}"
OWNER="${3:?owner}"
MESSAGE="${4:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

if [[ -z "${SLACK_WEBHOOK_URL:-}" ]]; then
  echo "SLACK_WEBHOOK_URL not set — skipping Slack post." >&2
  exit 0
fi

EMOJI="🔧"
case "$STATUS" in
  started)            EMOJI="🟡" ;;
  awaiting-approval)  EMOJI="⏳" ;;
  blocked)            EMOJI="🔴" ;;
  review)             EMOJI="🟣" ;;
  done)               EMOJI="✅" ;;
esac

# Keep this format consistent with whatever else posts to the channel so
# everything reads as one stream.
TEXT="${EMOJI} *${OWNER}* — task \`${TASK_SLUG}\` → *${STATUS}*
${MESSAGE}"

PAYLOAD=$(python3 -c '
import json, sys
print(json.dumps({"text": sys.argv[1]}))
' "$TEXT")

# Callers invoke this with `|| true` (a failed Slack post shouldn't fail the
# task-creation/completion flow), so make sure a failure is at least visible
# here rather than silently swallowed with no trace.
if ! curl -sS --fail-with-body -X POST -H "Content-type: application/json" \
     --data "$PAYLOAD" "$SLACK_WEBHOOK_URL" > /dev/null; then
  echo "Slack post failed (curl error, or Slack returned an HTTP error) — task status was still updated locally." >&2
  exit 1
fi
