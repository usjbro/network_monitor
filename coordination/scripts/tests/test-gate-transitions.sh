#!/usr/bin/env bash
# Exercises gate-status.sh/approve-gate.sh/block-gate.sh/mark-gate-delegated.sh/
# list-pending-gates.sh, including the double-approval race.
# Run: bash coordination/scripts/tests/test-gate-transitions.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/.."
# shellcheck disable=SC1091
source "$BIN/lib.sh"
FAILURES=0
TEST_LINEAR_ID="ZZZ-999"
TEST_SLUG="test-transitions-$$"
GATE_FILE="$(gate_path "$TEST_LINEAR_ID" "$TEST_SLUG")"

cleanup() { rm -f "$GATE_FILE"; }
trap cleanup EXIT

mkdir -p "$(dirname "$GATE_FILE")"
cat > "$GATE_FILE" <<EOF
---
linear_id: ${TEST_LINEAR_ID}
slug: ${TEST_SLUG}
status: awaiting-approval
delegated: false
posted_at: 2026-09-25T00:00:00Z
delegation_target:
delegation_agent_type:
---

## Plan

test
EOF

STATUS_OUT="$("$BIN/gate-status.sh" "$TEST_LINEAR_ID" "$TEST_SLUG")"
[[ "$STATUS_OUT" == "status=awaiting-approval delegated=false" ]] \
  && echo "PASS: gate-status.sh reports initial state" \
  || { echo "FAIL: gate-status.sh reports initial state — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }

LIST_OUT="$("$BIN/list-pending-gates.sh")"
echo "$LIST_OUT" | grep -q "^${TEST_LINEAR_ID} ${TEST_SLUG} " \
  && echo "PASS: list-pending-gates.sh lists the pending gate" \
  || { echo "FAIL: list-pending-gates.sh lists the pending gate — got: $LIST_OUT"; FAILURES=$((FAILURES + 1)); }

# Race: two concurrent approve-gate.sh calls on the same gate — exactly one
# must succeed (print "approved", exit 0), the other must exit 2.
RESULT_A="$(mktemp)"; RESULT_B="$(mktemp)"
( "$BIN/approve-gate.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" > "$RESULT_A" 2>&1; echo $? >> "$RESULT_A" ) &
PID_A=$!
( "$BIN/approve-gate.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" > "$RESULT_B" 2>&1; echo $? >> "$RESULT_B" ) &
PID_B=$!
wait "$PID_A" "$PID_B"
CODE_A="$(tail -n1 "$RESULT_A")"; CODE_B="$(tail -n1 "$RESULT_B")"
if [[ "$CODE_A $CODE_B" == "0 2" || "$CODE_A $CODE_B" == "2 0" ]]; then
  echo "PASS: exactly one of two concurrent approve-gate.sh calls succeeds"
else
  echo "FAIL: exactly one of two concurrent approve-gate.sh calls succeeds — got exit codes '$CODE_A' and '$CODE_B'"
  FAILURES=$((FAILURES + 1))
fi
rm -f "$RESULT_A" "$RESULT_B"

STATUS_OUT="$("$BIN/gate-status.sh" "$TEST_LINEAR_ID" "$TEST_SLUG")"
[[ "$STATUS_OUT" == "status=approved delegated=false" ]] \
  && echo "PASS: gate is approved after the race, delegated still false" \
  || { echo "FAIL: gate is approved after the race — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }

"$BIN/mark-gate-delegated.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" in-session network-monitor-developer >/dev/null
STATUS_OUT="$("$BIN/gate-status.sh" "$TEST_LINEAR_ID" "$TEST_SLUG")"
[[ "$STATUS_OUT" == "status=approved delegated=true" ]] \
  && echo "PASS: mark-gate-delegated.sh flips delegated" \
  || { echo "FAIL: mark-gate-delegated.sh flips delegated — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }
grep -q "^delegation_target: in-session$" "$GATE_FILE" \
  && echo "PASS: delegation_target recorded" \
  || { echo "FAIL: delegation_target not recorded"; FAILURES=$((FAILURES + 1)); }

# mark-gate-delegated.sh must reject an agent-type containing sed-special
# characters ("&" or "/") rather than splicing them into the frontmatter.
BEFORE_CONTENT="$(cat "$GATE_FILE")"
"$BIN/mark-gate-delegated.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" in-session "bad&value" >/dev/null 2>&1
BAD_AGENT_TYPE_CODE=$?
AFTER_CONTENT="$(cat "$GATE_FILE")"
if [[ "$BAD_AGENT_TYPE_CODE" -ne 0 && "$BEFORE_CONTENT" == "$AFTER_CONTENT" ]]; then
  echo "PASS: mark-gate-delegated.sh rejects an unsafe agent-type without corrupting the gate file"
else
  echo "FAIL: mark-gate-delegated.sh rejects an unsafe agent-type — exit code '$BAD_AGENT_TYPE_CODE', file changed: $([[ "$BEFORE_CONTENT" == "$AFTER_CONTENT" ]] && echo no || echo yes)"
  FAILURES=$((FAILURES + 1))
fi

# block-gate.sh on a fresh gate.
cat > "$GATE_FILE" <<EOF
---
linear_id: ${TEST_LINEAR_ID}
slug: ${TEST_SLUG}
status: awaiting-approval
delegated: false
posted_at: 2026-09-25T00:00:00Z
delegation_target:
delegation_agent_type:
---

## Plan

test
EOF
"$BIN/block-gate.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" "scope too broad" >/dev/null
STATUS_OUT="$("$BIN/gate-status.sh" "$TEST_LINEAR_ID" "$TEST_SLUG")"
[[ "$STATUS_OUT" == "status=blocked delegated=false" ]] \
  && echo "PASS: block-gate.sh sets status=blocked" \
  || { echo "FAIL: block-gate.sh sets status=blocked — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }
grep -q "scope too broad" "$GATE_FILE" \
  && echo "PASS: block-gate.sh records the reason" \
  || { echo "FAIL: block-gate.sh does not record the reason"; FAILURES=$((FAILURES + 1)); }

if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES test(s) failed."
  exit 1
fi
echo "All tests passed."
