#!/usr/bin/env bash
# Exercises create-gate.sh's interactive/autonomous failure handling without
# needing a real Slack webhook. Run: bash coordination/scripts/tests/test-create-gate.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CREATE_GATE="$SCRIPT_DIR/../create-gate.sh"
FAILURES=0
TEST_LINEAR_ID="ZZZ-999"
TEST_SLUG="test-create-gate-$$"

# Temporarily hide the main repo's coordination/.env so this worktree's
# "no .env" scenario is testable (the worktree itself has no .env, and we
# want lib.sh's sourcing to be a no-op).
MAIN_REPO_ENV="/Users/jamesbrown/Documents/GitHub/network_monitor/coordination/.env"
MAIN_REPO_ENV_BACKUP="${MAIN_REPO_ENV}.backup-test-$$"
if [[ -f "$MAIN_REPO_ENV" ]]; then
  mv "$MAIN_REPO_ENV" "$MAIN_REPO_ENV_BACKUP"
fi

cleanup() {
  # Restore the main repo's .env file
  if [[ -f "$MAIN_REPO_ENV_BACKUP" ]]; then
    mv "$MAIN_REPO_ENV_BACKUP" "$MAIN_REPO_ENV"
  fi
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/../lib.sh"
  rm -f "$(gate_path "$TEST_LINEAR_ID" "$TEST_SLUG" 2>/dev/null)" 2>/dev/null || true
}
trap cleanup EXIT

# Case 1: autonomous mode, no webhook configured -> must refuse, no gate file.
if SLACK_WEBHOOK_URL="" "$CREATE_GATE" "$TEST_LINEAR_ID" "$TEST_SLUG" "test plan" autonomous >/dev/null 2>&1; then
  echo "FAIL: autonomous mode with no webhook should refuse to create a gate"
  FAILURES=$((FAILURES + 1))
else
  echo "PASS: autonomous mode with no webhook refuses"
fi
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../lib.sh"
GATE_FILE="$(gate_path "$TEST_LINEAR_ID" "$TEST_SLUG")"
if [[ -f "$GATE_FILE" ]]; then
  echo "FAIL: autonomous refusal must not leave a gate file behind"
  FAILURES=$((FAILURES + 1))
  rm -f "$GATE_FILE"
else
  echo "PASS: autonomous refusal leaves no gate file"
fi

# Case 2: autonomous mode, webhook set but unreachable -> must refuse.
if SLACK_WEBHOOK_URL="http://127.0.0.1:1/unreachable" "$CREATE_GATE" "$TEST_LINEAR_ID" "$TEST_SLUG" "test plan" autonomous >/dev/null 2>&1; then
  echo "FAIL: autonomous mode with an unreachable webhook should refuse to create a gate"
  FAILURES=$((FAILURES + 1))
else
  echo "PASS: autonomous mode with an unreachable webhook refuses"
fi
[[ -f "$GATE_FILE" ]] && { echo "FAIL: gate file should not exist after refusal"; rm -f "$GATE_FILE"; FAILURES=$((FAILURES + 1)); }

# Case 3: interactive mode, no webhook configured -> still creates the gate, warns.
if SLACK_WEBHOOK_URL="" "$CREATE_GATE" "$TEST_LINEAR_ID" "$TEST_SLUG" "test plan" interactive >/dev/null 2>/tmp/create-gate-warn-$$; then
  echo "PASS: interactive mode with no webhook still creates the gate"
else
  echo "FAIL: interactive mode with no webhook should still create the gate"
  FAILURES=$((FAILURES + 1))
fi
if [[ -f "$GATE_FILE" ]]; then
  echo "PASS: gate file exists after interactive no-webhook creation"
  STATUS="$(grep '^status:' "$GATE_FILE" | cut -d' ' -f2)"
  [[ "$STATUS" == "awaiting-approval" ]] && echo "PASS: status is awaiting-approval" || { echo "FAIL: status is '$STATUS', expected awaiting-approval"; FAILURES=$((FAILURES + 1)); }
else
  echo "FAIL: gate file missing after interactive no-webhook creation"
  FAILURES=$((FAILURES + 1))
fi
grep -qi "warning" /tmp/create-gate-warn-$$ && echo "PASS: a warning was printed" || { echo "FAIL: expected a warning on stderr"; FAILURES=$((FAILURES + 1)); }
rm -f /tmp/create-gate-warn-$$ "$GATE_FILE"

# Case 4: interactive mode, webhook set but unreachable -> still creates the gate, warns.
if SLACK_WEBHOOK_URL="http://127.0.0.1:1/unreachable" "$CREATE_GATE" "$TEST_LINEAR_ID" "$TEST_SLUG" "test plan" interactive >/dev/null 2>/tmp/create-gate-warn-$$; then
  echo "PASS: interactive mode with unreachable webhook still creates the gate"
else
  echo "FAIL: interactive mode with unreachable webhook should still create the gate"
  FAILURES=$((FAILURES + 1))
fi
if [[ -f "$GATE_FILE" ]]; then
  echo "PASS: gate file exists after interactive unreachable-webhook creation"
  STATUS="$(grep '^status:' "$GATE_FILE" | cut -d' ' -f2)"
  [[ "$STATUS" == "awaiting-approval" ]] && echo "PASS: status is awaiting-approval" || { echo "FAIL: status is '$STATUS', expected awaiting-approval"; FAILURES=$((FAILURES + 1)); }
else
  echo "FAIL: gate file missing after interactive unreachable-webhook creation"
  FAILURES=$((FAILURES + 1))
fi
grep -qi "warning" /tmp/create-gate-warn-$$ && echo "PASS: a warning was printed for failed Slack post" || { echo "FAIL: expected a warning on stderr"; FAILURES=$((FAILURES + 1)); }
rm -f /tmp/create-gate-warn-$$ "$GATE_FILE"

# Case 5: creating a gate that already exists must fail.
mkdir -p "$(dirname "$GATE_FILE")"
echo "status: awaiting-approval" > "$GATE_FILE"
if SLACK_WEBHOOK_URL="" "$CREATE_GATE" "$TEST_LINEAR_ID" "$TEST_SLUG" "test plan" interactive >/dev/null 2>&1; then
  echo "FAIL: creating an already-existing gate should fail"
  FAILURES=$((FAILURES + 1))
else
  echo "PASS: creating an already-existing gate fails"
fi
rm -f "$GATE_FILE"

if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES test(s) failed."
  exit 1
fi
echo "All tests passed."
