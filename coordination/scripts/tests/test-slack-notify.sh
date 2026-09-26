#!/usr/bin/env bash
# Exercises slack-notify.sh's status → emoji mapping against a fake curl, so
# no real webhook is ever hit. Run: bash coordination/scripts/tests/test-slack-notify.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOTIFY="$SCRIPT_DIR/../slack-notify.sh"
FAILURES=0

FAKE_BIN="$(mktemp -d)"
PAYLOAD_FILE="$(mktemp)"
cat > "$FAKE_BIN/curl" <<'EOF'
#!/usr/bin/env bash
# Record the --data argument (the JSON payload) and succeed.
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--data" ]]; then printf '%s' "$2" > "$TEST_PAYLOAD_FILE"; fi
  shift
done
EOF
chmod +x "$FAKE_BIN/curl"

cleanup() { rm -rf "$FAKE_BIN" "$PAYLOAD_FILE"; }
trap cleanup EXIT

expect_emoji() {
  local status="$1" emoji="$2"
  : > "$PAYLOAD_FILE"
  if TEST_PAYLOAD_FILE="$PAYLOAD_FILE" SLACK_WEBHOOK_URL="https://example.invalid/webhook" \
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

# No webhook -> skips without posting and exits 0.
: > "$PAYLOAD_FILE"
if TEST_PAYLOAD_FILE="$PAYLOAD_FILE" SLACK_WEBHOOK_URL="" PATH="$FAKE_BIN:$PATH" \
    "$NOTIFY" started "some-task" "claude-code" "msg" >/dev/null 2>&1 && [[ ! -s "$PAYLOAD_FILE" ]]; then
  echo "PASS: no webhook skips the post"
else
  echo "FAIL: no webhook should skip the post without error"
  FAILURES=$((FAILURES + 1))
fi

if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES test(s) failed."
  exit 1
fi
echo "All tests passed."
