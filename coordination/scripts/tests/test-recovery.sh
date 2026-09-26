#!/usr/bin/env bash
# Regression tests for recovering interrupted approval-gate operations.
# Run: bash coordination/scripts/tests/test-recovery.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/.."
# shellcheck disable=SC1091
source "$BIN/lib.sh"
FAILURES=0
TEST_LINEAR_ID="ZZZ-999"
TEST_SLUG="test-recovery-$$"
GATE_FILE="$(gate_path "$TEST_LINEAR_ID" "$TEST_SLUG")"
LOCK_DIR="${GATE_FILE}.lock"
LOCK_PROBE_GATE="${GATE_FILE}.probe"
LOCK_PROBE_DIR="${LOCK_PROBE_GATE}.lock"
MALFORMED_SLUG="test-recovery-malformed-$$"
MALFORMED_GATE="$(gate_path "$TEST_LINEAR_ID" "$MALFORMED_SLUG")"

for command in claim-gate-delegation.sh reset-gate-delegation-claim.sh recover-gate-lock.sh; do
  if [[ ! -x "$BIN/$command" ]]; then
    echo "FAIL: missing executable $BIN/$command"
    exit 1
  fi
done

cleanup() {
  rm -f "$GATE_FILE" "$MALFORMED_GATE"
  rm -rf "$LOCK_DIR" "$LOCK_PROBE_DIR"
}
trap cleanup EXIT

mkdir -p "$(dirname "$GATE_FILE")"
cat > "$GATE_FILE" <<EOF_GATE
---
linear_id: ${TEST_LINEAR_ID}
slug: ${TEST_SLUG}
status: approved
delegated: false
delegation_claimed: false
posted_at: 2026-09-25T00:00:00Z
delegation_target:
delegation_agent_type:
---

## Plan

recovery test
EOF_GATE

# An approved, unclaimed gate is resumable; claiming it atomically prevents a
# second session from launching a duplicate delegation.
"$BIN/mark-gate-delegated.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" codex >/dev/null 2>&1
MARK_WITHOUT_CLAIM_CODE=$?
if [[ "$MARK_WITHOUT_CLAIM_CODE" -ne 0 ]]; then
  echo "PASS: unclaimed delegation cannot be marked complete"
else
  echo "FAIL: mark-gate-delegated accepted an unclaimed gate"
  FAILURES=$((FAILURES + 1))
fi

# A failed gate rewrite must never let a claimant report success and dispatch.
printf '%s\n' '---' "linear_id: $TEST_LINEAR_ID" "slug: $MALFORMED_SLUG" \
  'status: approved' 'delegated: false' 'delegation_claimed: false' > "$MALFORMED_GATE"
MALFORMED_BEFORE="$(cat "$MALFORMED_GATE")"
CLAIM_OUT="$("$BIN/claim-gate-delegation.sh" "$TEST_LINEAR_ID" "$MALFORMED_SLUG" 2>&1)"
CLAIM_CODE=$?
if [[ "$CLAIM_CODE" -ne 0 && "$(cat "$MALFORMED_GATE")" == "$MALFORMED_BEFORE" \
  && "$CLAIM_OUT" != "delegation-claimed" ]]; then
  echo "PASS: failed claim rewrite does not report delegation success"
else
  echo "FAIL: failed claim rewrite exited $CLAIM_CODE with output '$CLAIM_OUT'"
  FAILURES=$((FAILURES + 1))
fi
"$BIN/claim-gate-delegation.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" >/dev/null 2>&1
FIRST_CLAIM_CODE=$?
if [[ "$FIRST_CLAIM_CODE" -eq 0 ]]; then
  echo "PASS: first session claims an approved gate"
else
  echo "FAIL: first claim exited $FIRST_CLAIM_CODE"
  FAILURES=$((FAILURES + 1))
fi
"$BIN/claim-gate-delegation.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" >/dev/null 2>&1
SECOND_CLAIM_CODE=$?
if [[ "$SECOND_CLAIM_CODE" -ne 0 ]]; then
  echo "PASS: duplicate claim is refused"
else
  echo "FAIL: duplicate claim was accepted"
  FAILURES=$((FAILURES + 1))
fi
STATUS_OUT="$("$BIN/gate-status.sh" "$TEST_LINEAR_ID" "$TEST_SLUG")"
[[ "$STATUS_OUT" == "status=approved delegated=false delegation_claimed=true" ]] \
  && echo "PASS: status reports the incomplete delegation claim" \
  || { echo "FAIL: status does not expose claim — got '$STATUS_OUT'"; FAILURES=$((FAILURES + 1)); }
"$BIN/mark-gate-delegated.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" codex >/dev/null 2>&1
MARK_CODE=$?
if [[ "$MARK_CODE" -eq 0 ]]; then
  echo "PASS: claimed delegation can be marked complete"
else
  echo "FAIL: mark claimed delegation exited $MARK_CODE"
  FAILURES=$((FAILURES + 1))
fi
"$BIN/reset-gate-delegation-claim.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" --confirm-no-active-delegation >/dev/null 2>&1
RESET_COMPLETE_CODE=$?
if [[ "$RESET_COMPLETE_CODE" -ne 0 ]]; then
  echo "PASS: completed delegation cannot be reset"
else
  echo "FAIL: completed delegation was reset"
  FAILURES=$((FAILURES + 1))
fi

# A claim left by an interrupted process can only be reset with explicit
# confirmation, after checking that no delegation is active.
cat > "$GATE_FILE" <<EOF_GATE
---
linear_id: ${TEST_LINEAR_ID}
slug: ${TEST_SLUG}
status: approved
delegated: false
delegation_claimed: true
posted_at: 2026-09-25T00:00:00Z
delegation_target: codex
delegation_agent_type:
---

## Plan

recovery test
EOF_GATE
"$BIN/reset-gate-delegation-claim.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" >/dev/null 2>&1
RESET_UNCONFIRMED_CODE=$?
"$BIN/reset-gate-delegation-claim.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" --confirm-no-active-delegation >/dev/null 2>&1
RESET_CONFIRMED_CODE=$?
"$BIN/claim-gate-delegation.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" >/dev/null 2>&1
RECLAIM_CODE=$?
if [[ "$RESET_UNCONFIRMED_CODE" -ne 0 && "$RESET_CONFIRMED_CODE" -eq 0 && "$RECLAIM_CODE" -eq 0 ]]; then
  echo "PASS: confirmed orphaned claim can be reset and reclaimed"
else
  echo "FAIL: claim recovery codes were unconfirmed=$RESET_UNCONFIRMED_CODE confirmed=$RESET_CONFIRMED_CODE reclaim=$RECLAIM_CODE"
  FAILURES=$((FAILURES + 1))
fi

# Normal lock use records its owner, cleans up after success, and preserves
# a wrapped command's failure status.
OWNER_OUT="$(with_gate_lock "$LOCK_PROBE_GATE" bash -c 'cat "$1"' _ "$LOCK_PROBE_DIR/pid")"
if [[ "$OWNER_OUT" == "$$" && ! -e "$LOCK_PROBE_DIR" ]]; then
  echo "PASS: normal lock records its owner and cleans up"
else
  echo "FAIL: normal lock owner/cleanup — owner='$OWNER_OUT' lock_exists=$([[ -e "$LOCK_PROBE_DIR" ]] && echo yes || echo no)"
  FAILURES=$((FAILURES + 1))
fi
START_PS_DIR="$(mktemp -d)"
cat > "$START_PS_DIR/ps" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'Fri Sep 25 18:00:00 2026'
EOF
chmod +x "$START_PS_DIR/ps"
START_OUT="$(PATH="$START_PS_DIR:$PATH" with_gate_lock "$LOCK_PROBE_GATE" bash -c 'cat "$1"' _ "$LOCK_PROBE_DIR/start")"
if [[ "$START_OUT" == "Fri Sep 25 18:00:00 2026" && ! -e "$LOCK_PROBE_DIR" ]]; then
  echo "PASS: lock records process start time when available"
else
  echo "FAIL: lock did not record and clean up process start time"
  FAILURES=$((FAILURES + 1))
fi
rm -f "$START_PS_DIR/ps"
rmdir "$START_PS_DIR"
with_gate_lock "$LOCK_PROBE_GATE" bash -c 'exit 17'
WRAPPED_EXIT=$?
if [[ "$WRAPPED_EXIT" -eq 17 && ! -e "$LOCK_PROBE_DIR" ]]; then
  echo "PASS: lock cleanup preserves the wrapped command's exit status"
else
  echo "FAIL: lock cleanup exit=$WRAPPED_EXIT lock_exists=$([[ -e "$LOCK_PROBE_DIR" ]] && echo yes || echo no)"
  FAILURES=$((FAILURES + 1))
fi

# Recovery must refuse a lock owned by a live process, recover a dead owner
# only with explicit confirmation, and require that same confirmation when
# there is no owner record (interruption immediately after mkdir).
mkdir "$LOCK_DIR"
printf '%s\n' "$$" > "$LOCK_DIR/pid"
if "$BIN/recover-gate-lock.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" --confirm-no-live-operation >/dev/null 2>&1; then
  echo "FAIL: recovery removed a lock owned by this live test process"
  FAILURES=$((FAILURES + 1))
else
  echo "PASS: recovery refuses a live lock owner"
fi
printf '%s\n' 'a different process start time' > "$LOCK_DIR/start"
FAKE_PS_DIR="$(mktemp -d)"
cat > "$FAKE_PS_DIR/ps" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'the current process start time'
EOF
chmod +x "$FAKE_PS_DIR/ps"
if PATH="$FAKE_PS_DIR:$PATH" "$BIN/recover-gate-lock.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" --confirm-no-live-operation >/dev/null 2>&1 \
  && [[ ! -e "$LOCK_DIR" ]]; then
  echo "PASS: recovery recognizes a reused PID from a different process start"
else
  echo "FAIL: recovery could not clear a stale lock with a reused PID"
  FAILURES=$((FAILURES + 1))
fi
rm -f "$FAKE_PS_DIR/ps"
rmdir "$FAKE_PS_DIR"
rm -rf "$LOCK_DIR"
mkdir "$LOCK_DIR"
printf '%s\n' 99999999 > "$LOCK_DIR/pid"
if "$BIN/recover-gate-lock.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" >/dev/null 2>&1; then
  echo "FAIL: stale lock recovery did not require confirmation"
  FAILURES=$((FAILURES + 1))
else
  echo "PASS: stale lock recovery requires confirmation"
fi
if "$BIN/recover-gate-lock.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" --confirm-no-live-operation >/dev/null 2>&1 && [[ ! -e "$LOCK_DIR" ]]; then
  echo "PASS: confirmed stale lock is removed"
else
  echo "FAIL: confirmed stale lock was not removed"
  FAILURES=$((FAILURES + 1))
fi
mkdir "$LOCK_DIR"
if "$BIN/recover-gate-lock.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" >/dev/null 2>&1; then
  echo "FAIL: ownerless lock recovery did not require confirmation"
  FAILURES=$((FAILURES + 1))
else
  echo "PASS: ownerless lock recovery requires confirmation"
fi
if "$BIN/recover-gate-lock.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" --confirm-no-live-operation >/dev/null 2>&1 && [[ ! -e "$LOCK_DIR" ]]; then
  echo "PASS: confirmed ownerless lock is removed"
else
  echo "FAIL: confirmed ownerless lock was not removed"
  FAILURES=$((FAILURES + 1))
fi
mkdir "$LOCK_DIR"
printf '%s\n' 'orphaned start metadata' > "$LOCK_DIR/start"
if "$BIN/recover-gate-lock.sh" "$TEST_LINEAR_ID" "$TEST_SLUG" --confirm-no-live-operation >/dev/null 2>&1 && [[ ! -e "$LOCK_DIR" ]]; then
  echo "PASS: confirmed ownerless lock with orphaned start metadata is removed"
else
  echo "FAIL: ownerless lock with orphaned start metadata was not removed"
  FAILURES=$((FAILURES + 1))
fi

if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES test(s) failed."
  exit 1
fi
echo "All tests passed."
