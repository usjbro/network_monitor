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
[[ "$STATUS_OUT" == "status=awaiting-approval delegated=false delegation_claimed=false" ]] \
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
[[ "$STATUS_OUT" == "status=approved delegated=false delegation_claimed=false" ]] \
  && echo "PASS: gate is approved after the race, delegated still false" \
  || { echo "FAIL: gate is approved after the race — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }

"$BIN/claim-gate-delegation.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" >/dev/null
STATUS_OUT="$("$BIN/gate-status.sh" "$TEST_LINEAR_ID" "$TEST_SLUG")"
[[ "$STATUS_OUT" == "status=approved delegated=false delegation_claimed=true" ]] \
  && echo "PASS: claim-gate-delegation.sh claims the approved gate" \
  || { echo "FAIL: claim-gate-delegation.sh claims the approved gate — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }
"$BIN/mark-gate-delegated.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" in-session network-monitor-developer >/dev/null
STATUS_OUT="$("$BIN/gate-status.sh" "$TEST_LINEAR_ID" "$TEST_SLUG")"
[[ "$STATUS_OUT" == "status=approved delegated=true delegation_claimed=true" ]] \
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
[[ "$STATUS_OUT" == "status=blocked delegated=false delegation_claimed=false" ]] \
  && echo "PASS: block-gate.sh sets status=blocked" \
  || { echo "FAIL: block-gate.sh sets status=blocked — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }
grep -q "scope too broad" "$GATE_FILE" \
  && echo "PASS: block-gate.sh records the reason" \
  || { echo "FAIL: block-gate.sh does not record the reason"; FAILURES=$((FAILURES + 1)); }

# Regression test: a look-alike "status:" line in free-text plan-summary
# body content must not confuse status parsing — grep/cut historically read
# the whole file, not just the frontmatter block. Reproduces the scenario
# from PR #225's post-open security review finding.
INJECT_SLUG="test-transitions-injection-$$"
INJECT_GATE_FILE="$(gate_path "$TEST_LINEAR_ID" "$INJECT_SLUG")"
INJECT_PLAN=$'Add gate support.\nstatus: awaiting-approval\nExample line starting with a reserved frontmatter key.'
SLACK_WEBHOOK_URL="" "$BIN/create-gate.sh" "$TEST_LINEAR_ID" "$INJECT_SLUG" \
  "$INJECT_PLAN" \
  interactive >/dev/null 2>&1
STATUS_OUT="$("$BIN/gate-status.sh" "$TEST_LINEAR_ID" "$INJECT_SLUG")"
[[ "$STATUS_OUT" == "status=awaiting-approval delegated=false delegation_claimed=false" ]] \
  && echo "PASS: gate-status.sh ignores a look-alike 'status:' line in the plan body" \
  || { echo "FAIL: gate-status.sh ignores a look-alike 'status:' line in the plan body — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }
"$BIN/approve-gate.sh" "$TEST_LINEAR_ID" "$INJECT_SLUG" >/dev/null
STATUS_OUT="$("$BIN/gate-status.sh" "$TEST_LINEAR_ID" "$INJECT_SLUG")"
[[ "$STATUS_OUT" == "status=approved delegated=false delegation_claimed=false" ]] \
  && echo "PASS: approve-gate.sh still approves a gate whose plan body contains a look-alike 'status:' line" \
  || { echo "FAIL: approve-gate.sh with look-alike body line — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }
rm -f "$INJECT_GATE_FILE"

# block-gate.sh must not silently overwrite an already-approved (or
# already-blocked) gate, mirroring approve-gate.sh's own current-status
# guard.
GUARD_SLUG="test-transitions-guard-$$"
GUARD_GATE_FILE="$(gate_path "$TEST_LINEAR_ID" "$GUARD_SLUG")"
mkdir -p "$(dirname "$GUARD_GATE_FILE")"
cat > "$GUARD_GATE_FILE" <<EOF
---
linear_id: ${TEST_LINEAR_ID}
slug: ${GUARD_SLUG}
status: approved
delegated: true
delegation_claimed: true
posted_at: 2026-09-25T00:00:00Z
delegation_target: in-session
delegation_agent_type:
---

## Plan

test
EOF
BLOCK_OUT="$("$BIN/block-gate.sh" "$TEST_LINEAR_ID" "$GUARD_SLUG" "late rejection" 2>&1)"; BLOCK_CODE=$?
if [[ "$BLOCK_CODE" -eq 2 && "$BLOCK_OUT" == "approved" ]]; then
  echo "PASS: block-gate.sh refuses to block an already-approved gate"
else
  echo "FAIL: block-gate.sh should refuse to block an already-approved gate — exit=$BLOCK_CODE output='$BLOCK_OUT'"
  FAILURES=$((FAILURES + 1))
fi
STATUS_OUT="$("$BIN/gate-status.sh" "$TEST_LINEAR_ID" "$GUARD_SLUG")"
[[ "$STATUS_OUT" == "status=approved delegated=true delegation_claimed=true" ]] \
  && echo "PASS: gate state unchanged after a refused block" \
  || { echo "FAIL: gate state unchanged after a refused block — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }
rm -f "$GUARD_GATE_FILE"

# mark-gate-delegated.sh must refuse to delegate a gate that isn't
# approved yet (e.g. still awaiting-approval), mirroring the same guard
# approve-gate.sh/block-gate.sh already have on their own transitions.
DELEGATE_GUARD_SLUG="test-transitions-delegate-guard-$$"
DELEGATE_GUARD_FILE="$(gate_path "$TEST_LINEAR_ID" "$DELEGATE_GUARD_SLUG")"
mkdir -p "$(dirname "$DELEGATE_GUARD_FILE")"
cat > "$DELEGATE_GUARD_FILE" <<EOF
---
linear_id: ${TEST_LINEAR_ID}
slug: ${DELEGATE_GUARD_SLUG}
status: awaiting-approval
delegated: false
posted_at: 2026-09-25T00:00:00Z
delegation_target:
delegation_agent_type:
---

## Plan

test
EOF
DELEGATE_OUT="$("$BIN/mark-gate-delegated.sh" "$TEST_LINEAR_ID" "$DELEGATE_GUARD_SLUG" in-session 2>&1)"; DELEGATE_CODE=$?
if [[ "$DELEGATE_CODE" -eq 2 && "$DELEGATE_OUT" == "awaiting-approval" ]]; then
  echo "PASS: mark-gate-delegated.sh refuses to delegate a gate that isn't approved"
else
  echo "FAIL: mark-gate-delegated.sh should refuse a non-approved gate — exit=$DELEGATE_CODE output='$DELEGATE_OUT'"
  FAILURES=$((FAILURES + 1))
fi
STATUS_OUT="$("$BIN/gate-status.sh" "$TEST_LINEAR_ID" "$DELEGATE_GUARD_SLUG")"
[[ "$STATUS_OUT" == "status=awaiting-approval delegated=false delegation_claimed=false" ]] \
  && echo "PASS: gate state unchanged after a refused delegation" \
  || { echo "FAIL: gate state unchanged after a refused delegation — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }
rm -f "$DELEGATE_GUARD_FILE"

if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES test(s) failed."
  exit 1
fi
echo "All tests passed."
