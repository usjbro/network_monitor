#!/usr/bin/env bash
# Post a task status update to the shared coordination Slack channel.
#
# Usage:
#   ./slack-notify.sh <status> <task-slug> <owner> "<message>" [thread-ts]
#
# Statuses with their own emoji: started, awaiting-approval, pr-opened,
# feedback, blocked, review, done. When each one is required is in
# AGENTS.md "Slack Status Posts".
#
# Posting path, in order of preference:
#
#   1. chat.postMessage with a bot token — set SLACK_BOT_TOKEN (and
#      optionally SLACK_CHANNEL_ID, default C0C39FJT9DX) via coordination/.env
#      (gitignored) the same way SLACK_WEBHOOK_URL is today, or export it
#      directly. The bot posts as a distinct identity per owner (see
#      OWNER_DISPLAY_NAME below) so its messages are never mistaken for a
#      human's, and it can thread: pass thread-ts (this script's own printed
#      ts from an earlier call, or a task/gate's stored slack_ts) to reply
#      in-thread instead of starting a new top-level post. When thread-ts is
#      omitted, this script looks up coordination/tasks/<task-slug>.md's or
#      coordination/gates/<task-slug>.md's own slack_ts field automatically,
#      so callers don't have to thread every post by hand.
#   2. The incoming webhook (SLACK_WEBHOOK_URL) — kept only as a fallback for
#      when no bot token is configured. Incoming webhooks cannot thread or
#      set a per-owner identity; a webhook post always appears as whatever
#      generic identity the webhook integration itself was configured with,
#      and any thread-ts given is ignored with a warning.
#
# On a successful bot-token post, this script prints the message's own ts to
# stdout (and nothing else) so a caller can capture it, e.g. to store as a
# task/gate's slack_ts. The webhook path prints nothing on success — Slack's
# incoming-webhook API doesn't return a ts.
#
# Requires curl and python3 (used to build/parse JSON). Never pass the bot
# token as a literal curl argument (visible to other processes via `ps`);
# it's fed to curl via a `-K -` config read from stdin instead.

set -euo pipefail

STATUS="${1:?status}"
TASK_SLUG="${2:?task-slug}"
OWNER="${3:?owner}"
MESSAGE="${4:-}"
THREAD_TS="${5:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

if ! slack_configured; then
  echo "Neither SLACK_BOT_TOKEN nor SLACK_WEBHOOK_URL is set — skipping Slack post." >&2
  exit 0
fi

EMOJI="🔧"
case "$STATUS" in
  started)            EMOJI="🟡" ;;
  awaiting-approval)  EMOJI="⏳" ;;
  pr-opened)          EMOJI="🔗" ;;
  feedback)           EMOJI="❓" ;;
  blocked)             EMOJI="🔴" ;;
  review)             EMOJI="🟣" ;;
  done)               EMOJI="✅" ;;
esac

# Keep this format consistent with whatever else posts to the channel so
# everything reads as one stream.
TEXT="${EMOJI} *${OWNER}* — task \`${TASK_SLUG}\` → *${STATUS}*
${MESSAGE}"

if [[ -n "${SLACK_BOT_TOKEN:-}" ]]; then
  SLACK_CHANNEL_ID="${SLACK_CHANNEL_ID:-C0C39FJT9DX}"

  # Distinct display identity per owner so an agent's posts are never
  # mistaken for the human user's or for each other's (chat:write.customize
  # scope required on the bot token for username/icon_emoji to take effect).
  case "$OWNER" in
    claude-code) USERNAME="Claude Code"; ICON_EMOJI="robot_face" ;;
    codex)       USERNAME="Codex";       ICON_EMOJI="computer" ;;
    gate)        USERNAME="Coordination Gate"; ICON_EMOJI="vertical_traffic_light" ;;
    *)           USERNAME=""; ICON_EMOJI="" ;;
  esac

  if [[ -z "$THREAD_TS" ]]; then
    THREAD_TS="$(lookup_slack_ts "$REPO_ROOT/coordination/tasks/${TASK_SLUG}.md")"
    if [[ -z "$THREAD_TS" ]]; then
      THREAD_TS="$(lookup_slack_ts "$REPO_ROOT/coordination/gates/${TASK_SLUG}.md")"
    fi
  fi

  PAYLOAD=$(python3 -c '
import json, sys
channel, text, username, icon_emoji, thread_ts = sys.argv[1:6]
body = {"channel": channel, "text": text}
if username:
    body["username"] = username
if icon_emoji:
    body["icon_emoji"] = ":" + icon_emoji + ":"
if thread_ts:
    body["thread_ts"] = thread_ts
print(json.dumps(body))
' "$SLACK_CHANNEL_ID" "$TEXT" "$USERNAME" "$ICON_EMOJI" "$THREAD_TS")

  PAYLOAD_FILE="$(mktemp)"
  RESPONSE_FILE="$(mktemp)"
  trap 'rm -f "$PAYLOAD_FILE" "$RESPONSE_FILE"' EXIT
  printf '%s' "$PAYLOAD" > "$PAYLOAD_FILE"

  # Config (including the Authorization header) is read from stdin (-K -),
  # and the request body from a separate file (data = @...) rather than
  # stdin too, since only one of them can occupy stdin. Neither ever appears
  # as a curl argument a concurrent `ps` could read, and the token is never
  # echoed or logged by this script.
  HTTP_STATUS="$(curl -sS -o "$RESPONSE_FILE" -w '%{http_code}' -K - <<CURLCFG
url = "https://slack.com/api/chat.postMessage"
header = "Authorization: Bearer ${SLACK_BOT_TOKEN}"
header = "Content-Type: application/json; charset=utf-8"
data = "@${PAYLOAD_FILE}"
CURLCFG
)" || HTTP_STATUS="curl-failed"

  if [[ "$HTTP_STATUS" != "200" ]]; then
    echo "Slack post failed (curl/HTTP error, status ${HTTP_STATUS}) — task status was still updated locally." >&2
    exit 1
  fi

  # Slack returns HTTP 200 even for a rejected request; the real result is
  # the body's "ok" field, so that's what determines success here.
  if ! RESULT_TS="$(python3 -c '
import json, sys
resp = json.load(open(sys.argv[1]))
if not resp.get("ok"):
    print(resp.get("error", "unknown error"), file=sys.stderr)
    sys.exit(1)
print(resp["ts"])
' "$RESPONSE_FILE")"; then
    echo "Slack post rejected (ok:false) — task status was still updated locally." >&2
    exit 1
  fi

  echo "$RESULT_TS"
  exit 0
fi

# Fallback: incoming webhook. No threading, no per-owner identity.
if [[ -n "$THREAD_TS" ]]; then
  echo "Warning: SLACK_BOT_TOKEN not set — posting via webhook, which cannot thread; this post will start a new top-level message instead of replying to ${THREAD_TS}." >&2
fi

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
