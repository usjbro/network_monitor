#!/usr/bin/env bash
# Post a task status update to the shared coordination Slack channel.
#
# Usage:
#   ./slack-notify.sh <status> <task-slug> <owner> "<message>"
#
# Requires SLACK_WEBHOOK_URL to be exported (Slack app → Incoming Webhooks,
# pointed at the shared coordination channel).

set -euo pipefail

STATUS="${1:?status}"
TASK_SLUG="${2:?task-slug}"
OWNER="${3:?owner}"
MESSAGE="${4:-}"

if [[ -z "${SLACK_WEBHOOK_URL:-}" ]]; then
  echo "SLACK_WEBHOOK_URL not set — skipping Slack post." >&2
  exit 0
fi

EMOJI="🔧"
case "$STATUS" in
  started)   EMOJI="🟡" ;;
  blocked)   EMOJI="🔴" ;;
  review)    EMOJI="🟣" ;;
  done)      EMOJI="✅" ;;
esac

# Keep this format consistent with whatever else posts to the channel so
# everything reads as one stream.
TEXT="${EMOJI} *${OWNER}* — task \`${TASK_SLUG}\` → *${STATUS}*
${MESSAGE}"

PAYLOAD=$(python3 -c '
import json, sys
print(json.dumps({"text": sys.argv[1]}))
' "$TEXT")

curl -sS -X POST -H "Content-type: application/json" \
  --data "$PAYLOAD" \
  "$SLACK_WEBHOOK_URL" > /dev/null
