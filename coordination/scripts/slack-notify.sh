#!/usr/bin/env bash
# Post a task status update to the shared coordination Slack channel.
#
# Usage:
#   ./slack-notify.sh <status> <task-slug> <owner> "<message>"
#
# Requires a Slack webhook (Slack app → Incoming Webhooks, pointed at the
# shared coordination channel) — set via coordination/.env
# (SLACK_WEBHOOK_URL=https://hooks.slack.com/..., gitignored) or exported
# directly.

set -euo pipefail

STATUS="${1:?status}"
TASK_SLUG="${2:?task-slug}"
OWNER="${3:?owner}"
MESSAGE="${4:-}"

# Load a locally-configured SLACK_WEBHOOK_URL if present, for a direct/
# standalone invocation of this script — new-task.sh/complete-task.sh
# already load it themselves before calling this, so this is a no-op in
# that path. coordination/.env is gitignored (repo-wide .env* pattern).
ENV_FILE="$(cd "$(dirname "$0")/.." && pwd)/.env"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

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
