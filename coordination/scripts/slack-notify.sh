#!/usr/bin/env bash
# Post a task status update to the shared coordination Slack channel.
#
# Usage:
#   ./slack-notify.sh <status> <task-slug> <owner> "<message>" [thread-ts]
#
# Statuses with their own emoji: started, awaiting-approval, pr-opened,
# feedback, blocked, review, done, idle (an agent has nothing claimed and
# is looking for the next Linear issue — see AGENTS.md "Continuous Work
# Queue"), reclaimed (a stale, delegated-but-stalled gate was
# automatically reclaimed). When each one is required is in AGENTS.md
# "Slack Status Posts".
#
# Posting path, in order of preference:
#
#   1. chat.postMessage with a bot token — set SLACK_BOT_TOKEN (and
#      optionally SLACK_CHANNEL_ID, default C0C39FJT9DX) via coordination/.env
#      (gitignored) the same way SLACK_WEBHOOK_URL is today, or export it
#      directly. The bot posts as a distinct identity per owner so its
#      messages are never mistaken for a human's.
#   2. The incoming webhook (SLACK_WEBHOOK_URL) — kept only as a fallback for
#      when no bot token is configured. It can't set a per-owner identity
#      (a webhook post always appears as whatever generic identity the
#      webhook integration itself was configured with), and its response
#      never returns a ts to capture — but Slack's webhook JSON body does
#      support thread_ts, so it CAN reply into a thread whose ts is already
#      known; it just can't originate a new one a later post could thread
#      under.
#
# Either path can thread: pass thread-ts (this script's own printed ts from
# an earlier bot-token call, or a task/gate's stored slack_ts) to reply
# in-thread instead of starting a new top-level post. When thread-ts is
# omitted, this script looks up coordination/tasks/<task-slug>.md's or
# coordination/gates/<task-slug>.md's own slack_ts field automatically, so
# callers don't have to thread every post by hand.
#
# On a successful bot-token post, this script prints the message's own ts to
# stdout (and nothing else) so a caller can capture it, e.g. to store as a
# task/gate's slack_ts. The webhook path prints nothing on success — Slack's
# incoming-webhook API doesn't return a ts, so only a bot-token post's ts can
# ever become a task/gate's recorded slack_ts.
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

# task-slug is used below to build a coordination/tasks|gates/<task-slug>.md
# path for the slack_ts auto-lookup. It's also a gate's "<linear-id>__<slug>"
# tag (which validate_slug's stricter pattern would reject for its "__"), so
# just block the one thing that would let it escape that directory.
case "$TASK_SLUG" in
  */*)
    echo "invalid task-slug: '${TASK_SLUG}' must not contain '/'" >&2
    exit 1
    ;;
esac

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
  idle)               EMOJI="⚪" ;;
  reclaimed)          EMOJI="🔄" ;;
esac

# Keep this format consistent with whatever else posts to the channel so
# everything reads as one stream.
TEXT="${EMOJI} *${OWNER}* — task \`${TASK_SLUG}\` → *${STATUS}*
${MESSAGE}"

# Auto-lookup applies to both posting paths below: a webhook can't create a
# new thread (its response has no ts to capture), but it CAN reply into a
# thread whose ts is already known — Slack's incoming-webhook JSON body
# supports thread_ts same as chat.postMessage; the only real limitation is
# that the webhook response never returns one to capture for later.
if [[ -z "$THREAD_TS" ]]; then
  THREAD_TS="$(lookup_slack_ts "$REPO_ROOT/coordination/tasks/${TASK_SLUG}.md")"
  if [[ -z "$THREAD_TS" ]]; then
    THREAD_TS="$(lookup_slack_ts "$REPO_ROOT/coordination/gates/${TASK_SLUG}.md")"
  fi
fi

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
  # the body's "ok" field, so that's what determines success here. Also
  # reject a "ts" that isn't Slack's own <digits>.<digits> shape before it
  # goes anywhere — callers (create-gate.sh, new-task.sh) write this value
  # verbatim into a gate/task file's YAML frontmatter via gate_set_field,
  # whose own contract requires no embedded newline; this is the one call
  # site feeding it a value that ultimately originates from a network
  # response rather than a CLI argument, so don't rely on Slack's response
  # always being well-formed.
  if ! RESULT_TS="$(python3 -c '
import json, re, sys
resp = json.load(open(sys.argv[1]))
if not resp.get("ok"):
    print(resp.get("error", "unknown error"), file=sys.stderr)
    sys.exit(1)
ts = resp.get("ts", "")
if not re.fullmatch(r"[0-9]+\.[0-9]+", ts):
    print(f"unexpected ts format in Slack response: {ts!r}", file=sys.stderr)
    sys.exit(1)
print(ts)
' "$RESPONSE_FILE")"; then
    echo "Slack post rejected or returned an unexpected response — task status was still updated locally." >&2
    exit 1
  fi

  echo "$RESULT_TS"
  exit 0
fi

# Fallback: incoming webhook. No per-owner identity, and its response
# never returns a ts to capture — but it CAN reply into an already-known
# thread (Slack supports thread_ts in the webhook JSON body itself); it
# just can't originate a new one a later post could thread under.
PAYLOAD=$(python3 -c '
import json, sys
text, thread_ts = sys.argv[1:3]
body = {"text": text}
if thread_ts:
    body["thread_ts"] = thread_ts
print(json.dumps(body))
' "$TEXT" "$THREAD_TS")

# Callers invoke this with `|| true` (a failed Slack post shouldn't fail the
# task-creation/completion flow), so make sure a failure is at least visible
# here rather than silently swallowed with no trace.
if ! curl -sS --fail-with-body -X POST -H "Content-type: application/json" \
     --data "$PAYLOAD" "$SLACK_WEBHOOK_URL" > /dev/null; then
  echo "Slack post failed (curl error, or Slack returned an HTTP error) — task status was still updated locally." >&2
  exit 1
fi
