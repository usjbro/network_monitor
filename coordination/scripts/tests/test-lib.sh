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
if [[ "$RESOLVED" == *"/coordination/gates/jam-9__field-model-typed-named.md" ]]; then
  echo "PASS: gate_path resolves and lower-cases linear-id"
else
  echo "FAIL: gate_path resolves and lower-cases linear-id — got '$RESOLVED'"
  FAILURES=$((FAILURES + 1))
fi

PATH_A="$(bash -c "source '$LIB'; gate_path 'JAM-1' '2-foo'")"
PATH_B="$(bash -c "source '$LIB'; gate_path 'JAM-1-2' 'foo'")"
if [[ "$PATH_A" != "$PATH_B" ]]; then
  echo "PASS: distinct Linear ID and slug pairs have distinct gate paths"
else
  echo "FAIL: distinct Linear ID and slug pairs collide at '$PATH_A'"
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

# gate_field/gate_set_field must only read/write the YAML frontmatter block
# (between the first two "---" lines), not any line elsewhere in the file
# that happens to share a "field:" prefix — e.g. a task's free-text Plan or
# Blocked body can legitimately contain an illustrative line like
# "status: awaiting-approval" that isn't a real field.
FIELD_TEST_FILE="$(mktemp)"
cat > "$FIELD_TEST_FILE" <<'EOF'
---
linear_id: ZZZ-1
slug: field-scope-test
status: awaiting-approval
delegated: false
---

## Plan

Note: this gate's own file will contain a line like
status: awaiting-approval
purely as illustrative text, not a real field.
EOF

FIELD_OUT="$(bash -c "source '$LIB'; gate_field '$FIELD_TEST_FILE' status")"
if [[ "$FIELD_OUT" == "awaiting-approval" ]]; then
  echo "PASS: gate_field reads only the frontmatter status, ignoring a look-alike body line"
else
  echo "FAIL: gate_field reads only the frontmatter status — got '$FIELD_OUT'"
  FAILURES=$((FAILURES + 1))
fi

bash -c "source '$LIB'; gate_set_field '$FIELD_TEST_FILE' status approved"
FRONTMATTER_STATUS="$(awk '/^---$/{c++;next} c==1 && index($0,"status:")==1{print;exit}' "$FIELD_TEST_FILE")"
BODY_LINE_COUNT="$(grep -c '^status: awaiting-approval$' "$FIELD_TEST_FILE")"
if [[ "$FRONTMATTER_STATUS" == "status: approved" && "$BODY_LINE_COUNT" -eq 1 ]]; then
  echo "PASS: gate_set_field rewrites only the frontmatter status, leaving the look-alike body line untouched"
else
  echo "FAIL: gate_set_field scoping — frontmatter='$FRONTMATTER_STATUS' body_matches=$BODY_LINE_COUNT"
  FAILURES=$((FAILURES + 1))
fi
rm -f "$FIELD_TEST_FILE"

MALFORMED_FILE="$(mktemp)"
printf '%s\n' '---' 'status: awaiting-approval' > "$MALFORMED_FILE"
MALFORMED_BEFORE="$(cat "$MALFORMED_FILE")"
if bash -c "source '$LIB'; gate_set_field '$MALFORMED_FILE' status approved" >/dev/null 2>&1; then
  echo "FAIL: gate_set_field accepted malformed frontmatter"
  FAILURES=$((FAILURES + 1))
elif [[ "$(cat "$MALFORMED_FILE")" == "$MALFORMED_BEFORE" ]]; then
  echo "PASS: malformed frontmatter is rejected without replacing the gate"
else
  echo "FAIL: malformed frontmatter replaced the gate despite an error"
  FAILURES=$((FAILURES + 1))
fi
rm -f "$MALFORMED_FILE" "$MALFORMED_FILE".*

# gate_set_field must preserve the gate file's permission mode — the
# mktemp+mv rewrite pattern silently downgrades it to mktemp's default
# (0600) otherwise, unlike an in-place sed -i edit.
PERM_TEST_FILE="$(mktemp)"
printf -- '---\nstatus: awaiting-approval\n---\n' > "$PERM_TEST_FILE"
chmod 644 "$PERM_TEST_FILE"
bash -c "source '$LIB'; gate_set_field '$PERM_TEST_FILE' status approved"
PERM_AFTER="$(stat -c '%a' "$PERM_TEST_FILE" 2>/dev/null)" || PERM_AFTER="$(stat -f '%Lp' "$PERM_TEST_FILE")"
if [[ "$PERM_AFTER" == "644" ]]; then
  echo "PASS: gate_set_field preserves the gate file's permission mode"
else
  echo "FAIL: gate_set_field preserves the gate file's permission mode — got '$PERM_AFTER', expected 644"
  FAILURES=$((FAILURES + 1))
fi
rm -f "$PERM_TEST_FILE"

if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES test(s) failed."
  exit 1
fi
echo "All tests passed."
