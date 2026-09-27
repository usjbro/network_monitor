#!/usr/bin/env bash
# Exercises slack-notify.sh against a fake curl, so no real Slack webhook or
# bot token is ever hit. Covers both posting paths: the bot-token
# chat.postMessage path (per-owner username/icon, thread-ts passthrough and
# auto-lookup, ok:false handling, ts printed on success) and the webhook
# fallback (unthreaded, no per-owner identity).
# Run: bash coordination/scripts/tests/test-slack-notify.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOTIFY="$SCRIPT_DIR/../slack-notify.sh"
FAILURES=0
FAKE_TOKEN="xoxb-fake-token-should-never-leak"

WORK_DIR="$(mktemp -d)"
FAKE_BIN="$WORK_DIR/bin"
mkdir -p "$FAKE_BIN"
PAYLOAD_FILE="$WORK_DIR/payload.json"     # posted body, both paths
CURLCFG_FILE="$WORK_DIR/curlcfg"          # bot-token path: the -K config (stdin)
CURL_ARGS_FILE="$WORK_DIR/curl-args"      # bot-token/webhook: the literal argv fake curl saw
RESPONSE_BODY_FILE="$WORK_DIR/response-body.json"

# Fake curl handles both call shapes slack-notify.sh uses:
#   - bot-token path: curl -sS -o <file> -w '%{http_code}' -K - <<config
#   - webhook path:   curl -sS --fail-with-body -X POST -H ... --data <json> <url>
# It records argv (to prove the token never appears there) and, for the
# bot-token path, the stdin config (to inspect headers/data-file separately)
# and the posted JSON body (extracted from the config's `data = "@file"`
# line, or from --data directly for the webhook path).
cat > "$FAKE_BIN/curl" <<'FAKECURL'
#!/usr/bin/env bash
set -uo pipefail
printf '%s\n' "$*" > "${TEST_CURL_ARGS_FILE:-/dev/null}"

OUT_FILE=""
HAS_K=0
DATA_ARG=""
args=("$@")
i=0
while [[ $i -lt ${#args[@]} ]]; do
  case "${args[$i]}" in
    -o) OUT_FILE="${args[$((i+1))]}"; i=$((i+2)) ;;
    -w) i=$((i+2)) ;;
    -K) HAS_K=1; i=$((i+2)) ;;
    --data) DATA_ARG="${args[$((i+1))]}"; i=$((i+2)) ;;
    *) i=$((i+1)) ;;
  esac
done

if [[ $HAS_K -eq 1 ]]; then
  CONFIG="$(cat)"
  printf '%s' "$CONFIG" > "${TEST_CURLCFG_FILE:-/dev/null}"
  DATA_FILE="$(printf '%s\n' "$CONFIG" | sed -n 's/^data = "@\(.*\)"$/\1/p')"
  if [[ -n "$DATA_FILE" ]]; then
    cp "$DATA_FILE" "${TEST_PAYLOAD_FILE:-/dev/null}"
  fi
  if [[ -n "$OUT_FILE" ]]; then
    cp "${TEST_RESPONSE_BODY_FILE:-/dev/null}" "$OUT_FILE"
  fi
  printf '%s' "${TEST_HTTP_STATUS:-200}"
  exit 0
fi

if [[ -n "$DATA_ARG" ]]; then
  printf '%s' "$DATA_ARG" > "${TEST_PAYLOAD_FILE:-/dev/null}"
fi
exit "${TEST_WEBHOOK_EXIT:-0}"
FAKECURL
chmod +x "$FAKE_BIN/curl"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

reset_files() { : > "$PAYLOAD_FILE"; : > "$CURLCFG_FILE"; : > "$CURL_ARGS_FILE"; }

json_get() {
  # json_get <file> <dotted.key> — prints the value, or nothing if absent.
  python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
for part in sys.argv[2].split("."):
    if not isinstance(d, dict) or part not in d:
        sys.exit(0)
    d = d[part]
print(d)
' "$1" "$2"
}

run_bot() {
  # run_bot <status> <slug> <owner> <message> [thread-ts]
  TEST_CURL_ARGS_FILE="$CURL_ARGS_FILE" TEST_CURLCFG_FILE="$CURLCFG_FILE" \
    TEST_PAYLOAD_FILE="$PAYLOAD_FILE" TEST_RESPONSE_BODY_FILE="$RESPONSE_BODY_FILE" \
    TEST_HTTP_STATUS="${TEST_HTTP_STATUS:-200}" \
    SLACK_BOT_TOKEN="$FAKE_TOKEN" SLACK_WEBHOOK_URL="" PATH="$FAKE_BIN:$PATH" \
    "$NOTIFY" "$@"
}

# ---------------------------------------------------------------------------
# Existing webhook-path emoji mapping (kept: webhook stays a supported
# fallback with the same message format as before).
expect_emoji() {
  local status="$1" emoji="$2"
  reset_files
  if TEST_PAYLOAD_FILE="$PAYLOAD_FILE" SLACK_WEBHOOK_URL="https://example.invalid/webhook" SLACK_BOT_TOKEN="" \
      PATH="$FAKE_BIN:$PATH" "$NOTIFY" "$status" "some-task" "claude-code" "msg" >/dev/null 2>&1 \
      && python3 -c 'import json,sys; t=json.load(open(sys.argv[1]))["text"]; sys.exit(0 if t.startswith(sys.argv[2] + " ") and ("*" + sys.argv[3] + "*") in t else 1)' \
         "$PAYLOAD_FILE" "$emoji" "$status"; then
    echo "PASS: status '$status' posts with $emoji"
  else
    echo "FAIL: status '$status' should post with $emoji — got: $(cat "$PAYLOAD_FILE")"
    FAILURES=$((FAILURES + 1))
  fi
}

expect_emoji started "🟡"
expect_emoji pr-opened "🔗"
expect_emoji feedback "❓"
expect_emoji review "🟣"
expect_emoji done "✅"

# No webhook, no bot token -> skips without posting and exits 0.
reset_files
if TEST_PAYLOAD_FILE="$PAYLOAD_FILE" SLACK_WEBHOOK_URL="" SLACK_BOT_TOKEN="" PATH="$FAKE_BIN:$PATH" \
    "$NOTIFY" started "some-task" "claude-code" "msg" >/dev/null 2>&1 && [[ ! -s "$PAYLOAD_FILE" ]]; then
  echo "PASS: no bot token or webhook skips the post"
else
  echo "FAIL: no bot token or webhook should skip the post without error"
  FAILURES=$((FAILURES + 1))
fi

# The webhook path can't originate a new thread (its response returns no
# ts), but it CAN reply into an already-known one — Slack's webhook JSON
# body supports thread_ts same as chat.postMessage.
reset_files
TEST_PAYLOAD_FILE="$PAYLOAD_FILE" SLACK_WEBHOOK_URL="https://example.invalid/webhook" SLACK_BOT_TOKEN="" \
    PATH="$FAKE_BIN:$PATH" "$NOTIFY" started "some-task" "claude-code" "msg" "1111.2222" >/dev/null 2>&1
if [[ "$(json_get "$PAYLOAD_FILE" thread_ts)" == "1111.2222" ]]; then
  echo "PASS: webhook path includes a known thread-ts in its payload"
else
  echo "FAIL: webhook path should include thread_ts=1111.2222 — got: $(cat "$PAYLOAD_FILE")"
  FAILURES=$((FAILURES + 1))
fi

# ---------------------------------------------------------------------------
# Bot-token path.

# Per-owner username/icon.
: > "$RESPONSE_BODY_FILE"
printf '{"ok":true,"ts":"1700000000.000001"}' > "$RESPONSE_BODY_FILE"

check_identity() {
  local owner="$1" want_username="$2" want_icon="$3"
  reset_files
  run_bot started some-task "$owner" msg >/dev/null 2>&1
  local got_username got_icon
  got_username="$(json_get "$PAYLOAD_FILE" username)"
  got_icon="$(json_get "$PAYLOAD_FILE" icon_emoji)"
  if [[ "$got_username" == "$want_username" && "$got_icon" == "$want_icon" ]]; then
    echo "PASS: owner '$owner' posts as username='$got_username' icon='$got_icon'"
  else
    echo "FAIL: owner '$owner' expected username='$want_username' icon='$want_icon', got username='$got_username' icon='$got_icon'"
    FAILURES=$((FAILURES + 1))
  fi
}

check_identity claude-code "Claude Code" ":robot_face:"
check_identity codex "Codex" ":computer:"
check_identity gate "Coordination Gate" ":vertical_traffic_light:"

# Unrecognized owner gets no identity override at all (no spoofed default).
reset_files
run_bot started some-task some-unknown-owner msg >/dev/null 2>&1
if [[ -z "$(json_get "$PAYLOAD_FILE" username)" && -z "$(json_get "$PAYLOAD_FILE" icon_emoji)" ]]; then
  echo "PASS: unrecognized owner posts with no username/icon override"
else
  echo "FAIL: unrecognized owner should not get a username/icon override — got: $(cat "$PAYLOAD_FILE")"
  FAILURES=$((FAILURES + 1))
fi

# Explicit thread-ts is passed straight through.
reset_files
run_bot review some-task claude-code msg "1600000000.111111" >/dev/null 2>&1
if [[ "$(json_get "$PAYLOAD_FILE" thread_ts)" == "1600000000.111111" ]]; then
  echo "PASS: explicit thread-ts is passed through as thread_ts"
else
  echo "FAIL: expected thread_ts=1600000000.111111 — got: $(cat "$PAYLOAD_FILE")"
  FAILURES=$((FAILURES + 1))
fi

# When no thread-ts is given, it's looked up from the task contract's own
# slack_ts field.
TASKS_DIR="$WORK_DIR/coordination-tasks"
mkdir -p "$TASKS_DIR"
cat > "$TASKS_DIR/auto-thread-task.md" <<'EOF'
---
task: auto-thread-task
owner: claude-code
status: open
slack_ts: 1650000000.555555
---
EOF
# lookup_slack_ts (via lib.sh's REPO_ROOT resolution) reads from
# $REPO_ROOT/coordination/tasks/<slug>.md — point REPO_ROOT-derived lookups
# at this fixture by running from a throwaway repo whose coordination/tasks
# holds it. Simpler: call lookup via the real repo's tasks dir would pollute
# it, so instead verify the auto-lookup unit directly through lib.sh.
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../lib.sh"
GOT_TS="$(lookup_slack_ts "$TASKS_DIR/auto-thread-task.md")"
if [[ "$GOT_TS" == "1650000000.555555" ]]; then
  echo "PASS: lookup_slack_ts reads a task contract's stored slack_ts"
else
  echo "FAIL: expected lookup_slack_ts to read 1650000000.555555 — got: $GOT_TS"
  FAILURES=$((FAILURES + 1))
fi
GOT_TS_MISSING="$(lookup_slack_ts "$TASKS_DIR/no-such-task.md")"
if [[ -z "$GOT_TS_MISSING" ]]; then
  echo "PASS: lookup_slack_ts is silent for a missing file"
else
  echo "FAIL: expected empty result for a missing file — got: $GOT_TS_MISSING"
  FAILURES=$((FAILURES + 1))
fi

# End-to-end: the auto-lookup actually fires through $NOTIFY itself (not
# just the lib.sh unit above) for BOTH posting paths, since TASK_SLUG
# resolves against the real $REPO_ROOT/coordination/tasks/, not a fixture
# directory. Uses a unique slug and cleans up immediately after.
REAL_TASKS_DIR="$REPO_ROOT/coordination/tasks"
E2E_SLUG="test-slack-notify-e2e-$$"
mkdir -p "$REAL_TASKS_DIR"
printf -- '---\nslack_ts: 1660000000.777777\n---\n' > "$REAL_TASKS_DIR/${E2E_SLUG}.md"

reset_files
run_bot started "$E2E_SLUG" claude-code msg >/dev/null 2>&1
if [[ "$(json_get "$PAYLOAD_FILE" thread_ts)" == "1660000000.777777" ]]; then
  echo "PASS: bot-token path auto-threads under a real task file's stored slack_ts"
else
  echo "FAIL: expected auto-lookup thread_ts=1660000000.777777 — got: $(cat "$PAYLOAD_FILE")"
  FAILURES=$((FAILURES + 1))
fi

reset_files
TEST_PAYLOAD_FILE="$PAYLOAD_FILE" SLACK_WEBHOOK_URL="https://example.invalid/webhook" SLACK_BOT_TOKEN="" \
    PATH="$FAKE_BIN:$PATH" "$NOTIFY" started "$E2E_SLUG" claude-code msg >/dev/null 2>&1
if [[ "$(json_get "$PAYLOAD_FILE" thread_ts)" == "1660000000.777777" ]]; then
  echo "PASS: webhook path also auto-threads under a real task file's stored slack_ts"
else
  echo "FAIL: expected auto-lookup thread_ts=1660000000.777777 on the webhook path — got: $(cat "$PAYLOAD_FILE")"
  FAILURES=$((FAILURES + 1))
fi
rm -f "$REAL_TASKS_DIR/${E2E_SLUG}.md"

# ok:false is treated as a failure even though Slack returns HTTP 200.
reset_files
printf '{"ok":false,"error":"invalid_auth"}' > "$RESPONSE_BODY_FILE"
STDOUT="$(run_bot started some-task claude-code msg 2>/dev/null)"
STDERR="$(run_bot started some-task claude-code msg 2>&1 1>/dev/null)"
RC=0
run_bot started some-task claude-code msg >/dev/null 2>&1 || RC=$?
if [[ $RC -ne 0 && -z "$STDOUT" && "$STDERR" == *"invalid_auth"* ]]; then
  echo "PASS: ok:false is treated as a failure and reports the error"
else
  echo "FAIL: ok:false should fail with the Slack error — rc=$RC stdout='$STDOUT' stderr='$STDERR'"
  FAILURES=$((FAILURES + 1))
fi

# On success, the message's ts is printed to stdout (and nothing else).
reset_files
printf '{"ok":true,"ts":"1700000000.999999"}' > "$RESPONSE_BODY_FILE"
STDOUT="$(run_bot done some-task codex msg 2>/dev/null)"
if [[ "$STDOUT" == "1700000000.999999" ]]; then
  echo "PASS: successful post prints the message ts to stdout"
else
  echo "FAIL: expected stdout '1700000000.999999' — got: '$STDOUT'"
  FAILURES=$((FAILURES + 1))
fi

# A "ts" that isn't Slack's own <digits>.<digits> shape (e.g. an injected
# newline, since this value later gets written verbatim into a gate/task
# file's YAML frontmatter) is rejected rather than passed through.
reset_files
printf '{"ok":true,"ts":"1700000000.1\\nstatus: approved"}' > "$RESPONSE_BODY_FILE"
STDOUT="$(run_bot started some-task claude-code msg 2>/dev/null)"
RC=0
run_bot started some-task claude-code msg >/dev/null 2>&1 || RC=$?
if [[ $RC -ne 0 && -z "$STDOUT" ]]; then
  echo "PASS: a malformed ts (e.g. containing a newline) is rejected, not printed"
else
  echo "FAIL: expected a malformed ts to be rejected — rc=$RC stdout='$STDOUT'"
  FAILURES=$((FAILURES + 1))
fi

# The token is fed to curl only via the -K stdin config, never as a literal
# argument — so it must never appear in the recorded argv, even though it
# does (legitimately) appear in the recorded stdin config.
reset_files
printf '{"ok":true,"ts":"1700000000.000002"}' > "$RESPONSE_BODY_FILE"
run_bot started some-task claude-code msg >/dev/null 2>&1
if [[ "$(cat "$CURL_ARGS_FILE")" != *"$FAKE_TOKEN"* && "$(cat "$CURLCFG_FILE")" == *"$FAKE_TOKEN"* ]]; then
  echo "PASS: token appears in the stdin config, never in curl's argv"
else
  echo "FAIL: token leaked into curl argv, or missing from the config entirely — args: $(cat "$CURL_ARGS_FILE")"
  FAILURES=$((FAILURES + 1))
fi

# A task-slug containing '/' is rejected outright — it's used to build a
# coordination/tasks|gates/<task-slug>.md path for the slack_ts auto-lookup,
# and this is the one character that would let it escape that directory.
reset_files
RC=0
STDERR="$(run_bot started "../../etc/passwd" claude-code msg 2>&1 1>/dev/null)" || true
run_bot started "../../etc/passwd" claude-code msg >/dev/null 2>&1 || RC=$?
if [[ $RC -ne 0 && "$STDERR" == *"must not contain"* && ! -s "$CURL_ARGS_FILE" ]]; then
  echo "PASS: a task-slug containing '/' is rejected before any Slack request"
else
  echo "FAIL: expected rejection of a task-slug containing '/' — rc=$RC stderr='$STDERR'"
  FAILURES=$((FAILURES + 1))
fi

# A non-200 HTTP status (transport-level failure) is also a failure.
reset_files
printf '{}' > "$RESPONSE_BODY_FILE"
RC=0
STDERR="$(TEST_HTTP_STATUS=500 run_bot started some-task claude-code msg 2>&1 1>/dev/null)" || true
TEST_HTTP_STATUS=500 run_bot started some-task claude-code msg >/dev/null 2>&1 || RC=$?
if [[ $RC -ne 0 && "$STDERR" == *"500"* ]]; then
  echo "PASS: a non-200 HTTP status is treated as a failure"
else
  echo "FAIL: expected failure mentioning status 500 — rc=$RC stderr='$STDERR'"
  FAILURES=$((FAILURES + 1))
fi

if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES test(s) failed."
  exit 1
fi
echo "All tests passed."
