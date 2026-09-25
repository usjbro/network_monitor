#!/usr/bin/env bash
# Automated tests for lib.sh's validate_slug/gate_path/with_gate_lock.
# Run: bash coordination/scripts/tests/test-lib.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$SCRIPT_DIR/../lib.sh"
FAILURES=0

assert_exits_nonzero() {
  local desc="$1"; shift
  if bash -c "$*" >/dev/null 2>&1; then
    echo "FAIL: $desc — expected nonzero exit, got 0"
    FAILURES=$((FAILURES + 1))
  else
    echo "PASS: $desc"
  fi
}

assert_exits_zero() {
  local desc="$1"; shift
  if bash -c "$*" >/dev/null 2>&1; then
    echo "PASS: $desc"
  else
    echo "FAIL: $desc — expected exit 0, got nonzero"
    FAILURES=$((FAILURES + 1))
  fi
}

assert_exits_nonzero "validate_slug rejects '../../outside'" \
  "source '$LIB'; validate_slug '../../outside' slug"
assert_exits_nonzero "validate_slug rejects empty string" \
  "source '$LIB'; validate_slug '' slug"
assert_exits_nonzero "validate_slug rejects uppercase" \
  "source '$LIB'; validate_slug 'Field-Model' slug"
assert_exits_nonzero "validate_slug rejects a slash" \
  "source '$LIB'; validate_slug 'a/b' slug"
assert_exits_zero "validate_slug accepts a normal slug" \
  "source '$LIB'; validate_slug 'field-model-typed-named' slug"

assert_exits_nonzero "gate_path rejects traversal in linear-id" \
  "source '$LIB'; gate_path '../../etc' 'slug'"

RESOLVED="$(bash -c "source '$LIB'; gate_path 'JAM-9' 'field-model-typed-named'")"
if [[ "$RESOLVED" == *"/coordination/gates/jam-9-field-model-typed-named.md" ]]; then
  echo "PASS: gate_path resolves and lower-cases linear-id"
else
  echo "FAIL: gate_path resolves and lower-cases linear-id — got '$RESOLVED'"
  FAILURES=$((FAILURES + 1))
fi

TMP_GATE="$(mktemp -u)"
ORDER_FILE="$(mktemp)"
(
  bash -c "source '$LIB'; with_gate_lock '$TMP_GATE' bash -c 'sleep 0.3; echo first >> \"$ORDER_FILE\"'"
) &
FIRST_PID=$!
sleep 0.05
bash -c "source '$LIB'; with_gate_lock '$TMP_GATE' bash -c 'echo second >> \"$ORDER_FILE\"'"
wait "$FIRST_PID"
CONTENTS="$(cat "$ORDER_FILE" | tr '\n' ' ')"
if [[ "$CONTENTS" == "first second " ]]; then
  echo "PASS: with_gate_lock serializes concurrent holders"
else
  echo "FAIL: with_gate_lock serializes concurrent holders — got: $CONTENTS"
  FAILURES=$((FAILURES + 1))
fi
rm -f "$ORDER_FILE"
rmdir "${TMP_GATE}.lock" 2>/dev/null || true

if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES test(s) failed."
  exit 1
fi
echo "All tests passed."
