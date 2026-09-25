# Slack Approval Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Any session working a Linear-tracked task posts its plan to Slack and does not implement or delegate until a human approves — either by replying in the same chat (interactive sessions) or in Slack (always available, the only path for unattended sessions) — with state persisted so approval survives the originating session ending.

**Architecture:** A new `coordination/gates/<linear-id>-<slug>.md` file per gated task, mutated by small single-purpose bash scripts under `coordination/scripts/` (reusing the existing `lib.sh`/`REPO_ROOT` pattern). A scheduled Claude Code agent (the existing `schedule`/cron feature) wakes periodically, checks Slack for replies against pending gates, and performs delegation on behalf of sessions that already ended. Both the owning chat session and the watcher check-then-act on the same gate file so only one of them ever delegates.

**Tech Stack:** bash (existing `coordination/scripts/*` conventions), the Slack MCP plugin (reads), the existing Incoming Webhook (`slack-notify.sh`, posts). (Revised 2026-09-25: no `schedule`/CronCreate watcher — see Task 5.)

**Spec:** `docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md`

## Global Constraints

- Never commit `coordination/.env` (gitignored; holds the Slack webhook URL).
- `coordination/` lives at the main repo root only, not per-worktree; every new script sources `coordination/scripts/lib.sh` and uses its `REPO_ROOT` (resolved via `git rev-parse --git-common-dir`), never a bare relative path.
- All new filesystem-path components built from user/agent input (a slug, a Linear id) must go through `validate_slug` — this is a direct fix for the open, unrelated finding against `new-task.sh`'s unvalidated `TASK_SLUG` (PR #220 review comment, 2026-09-25); new code must not repeat that class of bug.
- No automated test harness exists for `coordination/scripts/*` today; this plan adds one (plain bash assertion scripts under `coordination/scripts/tests/`) for the new pure-logic pieces (slug validation, gate-path resolution, locking) where TDD is practical, and falls back to real end-to-end manual exercise (this repo's existing convention) for the Slack/scheduling pieces that need live external services.
- Commit only when the work is verified (tests pass / real exercise confirms behavior), matching this repo's existing per-task commit cadence.
- This task itself has no Linear id (meta/tooling, like the agent-coordination-kit merge it extends) — it is therefore exempt from the very gate it builds, same as that prior task was.

## Review Focus

- A crafted `linear-id`/`slug` containing `../` must not let a gate file escape `coordination/gates/` — Task 1's `validate_slug`/`gate_path` tests.
- Two near-simultaneous approvals (a chat reply and a Slack reply landing close together) must never cause double delegation — Task 3's `with_gate_lock` race test, exercised again live in Task 6.
- An autonomous (unattended) session must refuse to create a gate it can never get approved (no webhook, or the Slack post fails) rather than leaving a task silently stuck — Task 2's failure-path tests.
- `slack-notify.sh`'s `curl` call has no `--fail`, so a Slack-side 4xx/5xx (bad/revoked webhook) currently reports as success — this directly breaks Task 2's autonomous-mode safety guarantee (an autonomous gate could be created believing its plan posted when Slack actually rejected it, leaving it approvable by no one), so this one specific fix is pulled into Task 2 despite being otherwise out of this plan's scope.
- A reply that's ambiguous (neither a clear approval nor a clear rejection) must not be guessed at — it must leave the gate `awaiting-approval` and prompt for clarification, not silently proceed — exercised live in Task 6.

---

### Task 1: Gate path/lock helpers in `lib.sh`

**Files:**
- Modify: `coordination/scripts/lib.sh:24` (append after existing content)
- Create: `coordination/scripts/tests/test-lib.sh`

**Interfaces:**
- Produces: `validate_slug(value, label="value")` — exits 1 with a message on stderr if `value` is empty or doesn't match `^[a-z0-9][a-z0-9-]*$`; otherwise returns 0 silently. Called by later tasks' scripts.
- Produces: `gate_path(linear_id, slug)` — lower-cases `linear_id`, validates both arguments via `validate_slug`, echoes `$REPO_ROOT/coordination/gates/<linear_id_lower>-<slug>.md`. Called by every script in Tasks 2-3.
- Produces: `with_gate_lock(gate_file, cmd...)` — acquires an exclusive `mkdir`-based lock at `<gate_file>.lock` (retrying up to 20 times at 0.1s intervals, failing with a stderr message if it can't acquire one), runs `cmd...`, releases the lock, and returns `cmd`'s exit code. Called by every gate-mutating script in Task 3.

- [ ] **Step 1: Write the failing tests**

Create `coordination/scripts/tests/test-lib.sh`:

```bash
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `bash coordination/scripts/tests/test-lib.sh`
Expected: FAIL — `validate_slug: command not found` (the functions don't exist in `lib.sh` yet).

- [ ] **Step 3: Implement the helpers**

Append to `coordination/scripts/lib.sh` (after its existing line 24):

```bash

# Validates a value intended for use as a filesystem path component (a task
# or gate slug, or a lower-cased Linear id). Rejects anything empty, or
# containing characters other than lowercase letters, digits, and hyphens —
# in particular this rejects "/" and "..", the exact gap an open review
# finding flagged against new-task.sh's unvalidated TASK_SLUG (PR #220
# review comment, 2026-09-25): a value like "../../outside" let
# WORKTREE_DIR/TASK_FILE escape their intended directories. New path
# components built from user input must run through this first.
validate_slug() {
  local value="$1"
  local label="${2:-value}"
  if [[ -z "$value" || ! "$value" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
    echo "invalid ${label}: '${value}' (must match ^[a-z0-9][a-z0-9-]*\$)" >&2
    exit 1
  fi
}

# Computes the gate file path for a given Linear id + slug, validating both
# first. linear_id is lower-cased to match this repo's existing branch
# convention (see new-task.sh's LINEAR_ID_LOWER).
gate_path() {
  local linear_id_lower slug="$2"
  linear_id_lower="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  validate_slug "$linear_id_lower" "linear-id"
  validate_slug "$slug" "slug"
  echo "$REPO_ROOT/coordination/gates/${linear_id_lower}-${slug}.md"
}

# Runs "$@" while holding an exclusive, atomic lock on gate_file, so the two
# gate observers (a chat session's next turn, and the scheduled watcher)
# can't both act on the same gate transition. Uses mkdir as the lock
# primitive rather than flock, which isn't reliably available on macOS
# (where this repo runs); mkdir's atomicity is POSIX-guaranteed.
with_gate_lock() {
  local gate_file="$1"; shift
  local lock_dir="${gate_file}.lock"
  local attempts=0
  until mkdir "$lock_dir" 2>/dev/null; do
    attempts=$((attempts + 1))
    if [[ $attempts -ge 20 ]]; then
      echo "could not acquire lock on ${gate_file} after ${attempts} attempts (0.1s each)" >&2
      return 1
    fi
    sleep 0.1
  done
  local rc=0
  "$@" || rc=$?
  rmdir "$lock_dir"
  return $rc
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `bash coordination/scripts/tests/test-lib.sh`
Expected: `All tests passed.` with every line above printing `PASS:`.

- [ ] **Step 5: Commit**

```bash
git add coordination/scripts/lib.sh coordination/scripts/tests/test-lib.sh
git commit -m "coordination: add gate path validation and locking helpers to lib.sh"
```

---

### Task 2: `create-gate.sh`, and the `slack-notify.sh` fixes it depends on

**Files:**
- Modify: `coordination/scripts/slack-notify.sh:29-34` (add `awaiting-approval` status, fix `curl` to treat HTTP errors as failures)
- Create: `coordination/scripts/create-gate.sh`
- Create: `coordination/scripts/tests/test-create-gate.sh`

**Interfaces:**
- Consumes: `REPO_ROOT`, `validate_slug`, `gate_path` (Task 1, via `lib.sh`).
- Produces: `create-gate.sh <linear-id> <slug> "<plan-summary>" <interactive|autonomous>` — writes `<gate_path>` with frontmatter `linear_id`, `slug`, `status: awaiting-approval`, `delegated: false`, `posted_at` (UTC `date -u +%Y-%m-%dT%H:%M:%SZ`), `delegation_target:` (empty), `delegation_agent_type:` (empty), and a `## Plan` body containing the plan summary. Exits 1 without writing anything if the gate already exists, or if Slack posting is required but unavailable in `autonomous` mode.

- [ ] **Step 1: Write the failing tests**

Create `coordination/scripts/tests/test-create-gate.sh`:

```bash
#!/usr/bin/env bash
# Exercises create-gate.sh's interactive/autonomous failure handling without
# needing a real Slack webhook. Run: bash coordination/scripts/tests/test-create-gate.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CREATE_GATE="$SCRIPT_DIR/../create-gate.sh"
FAILURES=0
TEST_LINEAR_ID="ZZZ-999"
TEST_SLUG="test-create-gate-$$"

cleanup() {
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

# Case 4: creating a gate that already exists must fail.
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `bash coordination/scripts/tests/test-create-gate.sh`
Expected: FAIL — `create-gate.sh: No such file or directory` (script doesn't exist yet).

- [ ] **Step 3: Fix `slack-notify.sh` first (Review Focus: autonomous-mode safety depends on this)**

Modify `coordination/scripts/slack-notify.sh` lines 28-34 from:

```bash
EMOJI="🔧"
case "$STATUS" in
  started)   EMOJI="🟡" ;;
  blocked)   EMOJI="🔴" ;;
  review)    EMOJI="🟣" ;;
  done)      EMOJI="✅" ;;
esac
```

to:

```bash
EMOJI="🔧"
case "$STATUS" in
  started)            EMOJI="🟡" ;;
  awaiting-approval)  EMOJI="⏳" ;;
  blocked)            EMOJI="🔴" ;;
  review)             EMOJI="🟣" ;;
  done)               EMOJI="✅" ;;
esac
```

And modify lines 49-53 from:

```bash
if ! curl -sS -X POST -H "Content-type: application/json" \
     --data "$PAYLOAD" "$SLACK_WEBHOOK_URL" > /dev/null; then
  echo "Slack post failed (curl error) — task status was still updated locally." >&2
  exit 1
fi
```

to:

```bash
if ! curl -sS --fail-with-body -X POST -H "Content-type: application/json" \
     --data "$PAYLOAD" "$SLACK_WEBHOOK_URL" > /dev/null; then
  echo "Slack post failed (curl error, or Slack returned an HTTP error) — task status was still updated locally." >&2
  exit 1
fi
```

(`--fail-with-body` makes `curl` exit nonzero on an HTTP 4xx/5xx response instead of treating it as success — this is the one open review finding pulled into this plan; see Review Focus.)

- [ ] **Step 4: Implement `create-gate.sh`**

Create `coordination/scripts/create-gate.sh`:

```bash
#!/usr/bin/env bash
# Create a Slack approval gate for a Linear-tracked task: writes
# coordination/gates/<linear-id>-<slug>.md with status: awaiting-approval
# and posts the plan to the shared Slack channel. See
# docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md.
#
# Usage:
#   ./create-gate.sh <linear-id> <slug> "<plan-summary>" <interactive|autonomous>
#
# mode "interactive": if the Slack post fails or no webhook is configured,
#   the gate is still created (approval can still come from this chat
#   session) — a warning is printed.
# mode "autonomous": the gate can only ever be approved via Slack (there is
#   no chat session to fall back to), so a missing/failed Slack post fails
#   gate creation instead of leaving a task stuck awaiting an approval path
#   that can never arrive.

set -euo pipefail

LINEAR_ID="${1:?usage: create-gate.sh <linear-id> <slug> \"<plan-summary>\" <interactive|autonomous>}"
SLUG="${2:?usage: create-gate.sh <linear-id> <slug> \"<plan-summary>\" <interactive|autonomous>}"
PLAN_SUMMARY="${3:?usage: create-gate.sh <linear-id> <slug> \"<plan-summary>\" <interactive|autonomous>}"
MODE="${4:?usage: create-gate.sh <linear-id> <slug> \"<plan-summary>\" <interactive|autonomous>}"

if [[ "$MODE" != "interactive" && "$MODE" != "autonomous" ]]; then
  echo "mode must be 'interactive' or 'autonomous'" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$LINEAR_ID" "$SLUG")"
LINEAR_ID_LOWER="$(echo "$LINEAR_ID" | tr '[:upper:]' '[:lower:]')"
GATE_TAG="${LINEAR_ID_LOWER}-${SLUG}"

if [[ -f "$GATE_FILE" ]]; then
  echo "Gate already exists: $GATE_FILE" >&2
  exit 1
fi

if [[ -z "${SLACK_WEBHOOK_URL:-}" ]]; then
  if [[ "$MODE" == "autonomous" ]]; then
    echo "SLACK_WEBHOOK_URL not set — an autonomous gate has no other approval path, refusing to create it." >&2
    exit 1
  fi
  echo "Warning: SLACK_WEBHOOK_URL not set — this gate can only be approved in this chat session, not remotely via Slack." >&2
elif ! "$SCRIPT_DIR/slack-notify.sh" "awaiting-approval" "$GATE_TAG" "gate" "$PLAN_SUMMARY"; then
  if [[ "$MODE" == "autonomous" ]]; then
    echo "Slack post failed — an autonomous gate has no other approval path, refusing to create it." >&2
    exit 1
  fi
  echo "Warning: Slack post failed — this gate can only be approved in this chat session, not remotely via Slack." >&2
fi

mkdir -p "$REPO_ROOT/coordination/gates"

cat > "$GATE_FILE" <<EOF
---
linear_id: ${LINEAR_ID}
slug: ${SLUG}
status: awaiting-approval
delegated: false
posted_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
delegation_target:
delegation_agent_type:
---

## Plan

${PLAN_SUMMARY}
EOF

echo "Gate created: $GATE_FILE"
echo "Status: awaiting-approval"
```

Make it executable: `chmod +x coordination/scripts/create-gate.sh`

- [ ] **Step 5: Run the tests to verify they pass**

Run: `bash coordination/scripts/tests/test-create-gate.sh`
Expected: `All tests passed.`

Also run: `bash -n coordination/scripts/create-gate.sh && bash -n coordination/scripts/slack-notify.sh`
Expected: no output (both parse cleanly).

- [ ] **Step 6: Commit**

```bash
git add coordination/scripts/create-gate.sh coordination/scripts/slack-notify.sh coordination/scripts/tests/test-create-gate.sh
git commit -m "coordination: add create-gate.sh; make slack-notify.sh fail on HTTP errors"
```

---

### Task 3: Gate state-transition scripts

**Files:**
- Create: `coordination/scripts/gate-status.sh`
- Create: `coordination/scripts/approve-gate.sh`
- Create: `coordination/scripts/block-gate.sh`
- Create: `coordination/scripts/mark-gate-delegated.sh`
- Create: `coordination/scripts/list-pending-gates.sh`
- Create: `coordination/scripts/tests/test-gate-transitions.sh`

**Interfaces:**
- Consumes: `REPO_ROOT`, `gate_path`, `with_gate_lock` (Task 1).
- Produces: `gate-status.sh <linear-id> <slug>` → prints `status=<awaiting-approval|approved|blocked> delegated=<true|false>` to stdout, exit 1 if no such gate.
- Produces: `approve-gate.sh <linear-id> <slug>` → exit 0 and prints `approved` if it performed the `awaiting-approval` → `approved` transition; exit 2 and prints the gate's current status if someone else already transitioned it.
- Produces: `block-gate.sh <linear-id> <slug> "<reason>"` → sets `status: blocked`, appends a `## Blocked` section with the reason.
- Produces: `mark-gate-delegated.sh <linear-id> <slug> <in-session|codex> [agent-type]` → sets `delegated: true`, `delegation_target`, `delegation_agent_type`.
- Produces: `list-pending-gates.sh` → prints one `<linear_id> <slug> <posted_at>` line per gate with `status: awaiting-approval`, nothing if none exist or `coordination/gates/` doesn't exist yet.

- [ ] **Step 1: Write the failing tests**

Create `coordination/scripts/tests/test-gate-transitions.sh`:

```bash
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `bash coordination/scripts/tests/test-gate-transitions.sh`
Expected: FAIL — the five scripts don't exist yet.

- [ ] **Step 3: Implement the five scripts**

Create `coordination/scripts/gate-status.sh`:

```bash
#!/usr/bin/env bash
# Prints a gate's status: "status=<awaiting-approval|approved|blocked>
# delegated=<true|false>". Read-only — used by both an interactive session
# (before acting on an in-chat approval) and the watcher (before acting on
# a Slack reply) to avoid double-delegating.
#
# Usage:
#   ./gate-status.sh <linear-id> <slug>

set -euo pipefail

LINEAR_ID="${1:?usage: gate-status.sh <linear-id> <slug>}"
SLUG="${2:?usage: gate-status.sh <linear-id> <slug>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$LINEAR_ID" "$SLUG")"

if [[ ! -f "$GATE_FILE" ]]; then
  echo "no such gate: $GATE_FILE" >&2
  exit 1
fi

STATUS="$(grep '^status:' "$GATE_FILE" | cut -d' ' -f2)"
DELEGATED="$(grep '^delegated:' "$GATE_FILE" | cut -d' ' -f2)"
echo "status=${STATUS} delegated=${DELEGATED}"
```

Create `coordination/scripts/approve-gate.sh`:

```bash
#!/usr/bin/env bash
# Atomically flips a gate from "awaiting-approval" to "approved". Exits 0
# and prints "approved" if this call performed the transition; exits 2 and
# prints the gate's current status if someone else already approved or
# blocked it first. Callers use that distinction to avoid double-delegating
# (see docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md,
# Error Handling: "Both channels reply close together").
#
# Usage:
#   ./approve-gate.sh <linear-id> <slug>

set -euo pipefail

LINEAR_ID="${1:?usage: approve-gate.sh <linear-id> <slug>}"
SLUG="${2:?usage: approve-gate.sh <linear-id> <slug>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$LINEAR_ID" "$SLUG")"

if [[ ! -f "$GATE_FILE" ]]; then
  echo "no such gate: $GATE_FILE" >&2
  exit 1
fi

_approve_locked() {
  local current
  current="$(grep '^status:' "$GATE_FILE" | cut -d' ' -f2)"
  if [[ "$current" != "awaiting-approval" ]]; then
    echo "$current"
    return 2
  fi
  sed -i.bak "s/^status: .*/status: approved/" "$GATE_FILE"
  rm -f "${GATE_FILE}.bak"
  echo "approved"
}

with_gate_lock "$GATE_FILE" _approve_locked
```

Create `coordination/scripts/block-gate.sh`:

```bash
#!/usr/bin/env bash
# Marks a gate "blocked" (explicit rejection) and appends why. Does not
# post to Slack itself — the calling agent (which read the rejection)
# already has Slack access and replies in-thread directly; this only
# mutates state.
#
# Usage:
#   ./block-gate.sh <linear-id> <slug> "<reason>"

set -euo pipefail

LINEAR_ID="${1:?usage: block-gate.sh <linear-id> <slug> \"<reason>\"}"
SLUG="${2:?usage: block-gate.sh <linear-id> <slug> \"<reason>\"}"
REASON="${3:?usage: block-gate.sh <linear-id> <slug> \"<reason>\"}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$LINEAR_ID" "$SLUG")"

if [[ ! -f "$GATE_FILE" ]]; then
  echo "no such gate: $GATE_FILE" >&2
  exit 1
fi

_block_locked() {
  sed -i.bak "s/^status: .*/status: blocked/" "$GATE_FILE"
  rm -f "${GATE_FILE}.bak"
  {
    echo
    echo "## Blocked"
    echo
    echo "$REASON"
  } >> "$GATE_FILE"
}

with_gate_lock "$GATE_FILE" _block_locked
echo "Gate blocked: $GATE_FILE"
```

Create `coordination/scripts/mark-gate-delegated.sh`:

```bash
#!/usr/bin/env bash
# Records that delegation actually ran for an approved gate, so a later
# retry (after a crash between "approved" and "delegated") can tell the
# difference between "not yet delegated" and "already delegated" instead
# of re-approving or silently dropping the task.
#
# Usage:
#   ./mark-gate-delegated.sh <linear-id> <slug> <in-session|codex> [agent-type]

set -euo pipefail

LINEAR_ID="${1:?usage: mark-gate-delegated.sh <linear-id> <slug> <in-session|codex> [agent-type]}"
SLUG="${2:?usage: mark-gate-delegated.sh <linear-id> <slug> <in-session|codex> [agent-type]}"
TARGET="${3:?usage: mark-gate-delegated.sh <linear-id> <slug> <in-session|codex> [agent-type]}"
AGENT_TYPE="${4:-}"

if [[ "$TARGET" != "in-session" && "$TARGET" != "codex" ]]; then
  echo "target must be 'in-session' or 'codex'" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$LINEAR_ID" "$SLUG")"

if [[ ! -f "$GATE_FILE" ]]; then
  echo "no such gate: $GATE_FILE" >&2
  exit 1
fi

_mark_locked() {
  sed -i.bak \
    -e "s/^delegated: .*/delegated: true/" \
    -e "s/^delegation_target:.*/delegation_target: ${TARGET}/" \
    -e "s/^delegation_agent_type:.*/delegation_agent_type: ${AGENT_TYPE}/" \
    "$GATE_FILE"
  rm -f "${GATE_FILE}.bak"
}

with_gate_lock "$GATE_FILE" _mark_locked
echo "Gate delegated: $GATE_FILE (target=${TARGET}${AGENT_TYPE:+, agent_type=${AGENT_TYPE}})"
```

Create `coordination/scripts/list-pending-gates.sh`:

```bash
#!/usr/bin/env bash
# Lists every gate currently awaiting approval, one per line, as
# "<linear_id> <slug> <posted_at>" — used by the watcher on each scheduled
# wake to know what to check Slack for.
#
# Usage:
#   ./list-pending-gates.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATES_DIR="$REPO_ROOT/coordination/gates"

if [[ ! -d "$GATES_DIR" ]]; then
  exit 0
fi

for gate_file in "$GATES_DIR"/*.md; do
  [[ -e "$gate_file" ]] || continue
  status="$(grep '^status:' "$gate_file" | cut -d' ' -f2)"
  if [[ "$status" == "awaiting-approval" ]]; then
    linear_id="$(grep '^linear_id:' "$gate_file" | cut -d' ' -f2)"
    slug="$(grep '^slug:' "$gate_file" | cut -d' ' -f2)"
    posted_at="$(grep '^posted_at:' "$gate_file" | cut -d' ' -f2)"
    echo "${linear_id} ${slug} ${posted_at}"
  fi
done
```

Make them executable: `chmod +x coordination/scripts/gate-status.sh coordination/scripts/approve-gate.sh coordination/scripts/block-gate.sh coordination/scripts/mark-gate-delegated.sh coordination/scripts/list-pending-gates.sh`

- [ ] **Step 4: Run the tests to verify they pass**

Run: `bash coordination/scripts/tests/test-gate-transitions.sh`
Expected: `All tests passed.`

Also run: `bash -n` on all five new scripts.
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add coordination/scripts/gate-status.sh coordination/scripts/approve-gate.sh coordination/scripts/block-gate.sh coordination/scripts/mark-gate-delegated.sh coordination/scripts/list-pending-gates.sh coordination/scripts/tests/test-gate-transitions.sh
git commit -m "coordination: add gate state-transition scripts (approve/block/mark-delegated/list)"
```

---

### Task 4: Workflow integration — `AGENTS.md` and `router-checklist.md`

**Files:**
- Modify: `AGENTS.md:51-60` (Required Workflow numbered list)
- Modify: `AGENTS.md:146-148` (insert new `## Slack Approval Gate` section between the end of Multi-Agent Coordination and `## Session Completion`)
- Modify: `coordination/router-checklist.md:51` (append new section)

**Interfaces:**
- Consumes: `create-gate.sh`, `gate-status.sh`, `approve-gate.sh`, `block-gate.sh`, `mark-gate-delegated.sh` (Tasks 2-3) — referenced by exact command line in the new docs, so their usage strings must match what those scripts actually accept.

- [ ] **Step 1: Update `AGENTS.md`'s Required Workflow**

Replace `AGENTS.md:51-60`:

```markdown
1. Read `.ai/CURRENT_TASK.md`.
2. Inspect relevant source code and tests.
3. Read applicable specification/protocol documentation.
4. Confirm acceptance criteria.
5. Write/update tests first where practical and demonstrate missing behavior.
6. Implement the smallest correct change.
7. Run relevant tests, fix failures, then run broader applicable tests.
8. Review `git diff`.
9. Update applicable `.ai/` state and `.ai/HANDOFF.md`.
10. Commit only when explicitly requested or authorized by the task.
```

with:

```markdown
1. Read `.ai/CURRENT_TASK.md`.
2. If this task has a Linear id and isn't ad hoc, create a Slack approval gate for it (if one doesn't already exist) and do not proceed past this step until it's approved — see "Slack Approval Gate" below.
3. Inspect relevant source code and tests.
4. Read applicable specification/protocol documentation.
5. Confirm acceptance criteria.
6. Write/update tests first where practical and demonstrate missing behavior.
7. Implement the smallest correct change.
8. Run relevant tests, fix failures, then run broader applicable tests.
9. Review `git diff`.
10. Update applicable `.ai/` state and `.ai/HANDOFF.md`.
11. Commit only when explicitly requested or authorized by the task.
```

- [ ] **Step 2: Add the "Slack Approval Gate" section to `AGENTS.md`**

Insert immediately after the existing Multi-Agent Coordination section's last line (currently line 146, `5. A human (or reviewer agent) merges one branch at a time and removes its worktree, same as any other task branch.`) and before `## Session Completion`:

```markdown

## Slack Approval Gate

Any session working a Linear-tracked task — interactive or autonomous, trivial or not — gates on a Slack approval before implementing. Ad hoc work with no Linear id is exempt. Full design: `docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md`.

1. Before implementing, create the gate: `coordination/scripts/create-gate.sh <linear-id> <slug> "<plan-summary>" <interactive|autonomous>`. Use `interactive` when you're in a live chat session with a human present; use `autonomous` for a scheduled/unattended session with no one to ask directly. This posts the plan to `#network-monitor` and writes `coordination/gates/<linear-id>-<slug>.md` with `status: awaiting-approval`. Then stop — do not implement anything for this task yet.
2. Approval can come from either channel:
   - **In-chat** (interactive sessions only): when the human replies with approval in the same conversation, check `coordination/scripts/gate-status.sh <linear-id> <slug>` first. If still `status=awaiting-approval`, run `coordination/scripts/approve-gate.sh <linear-id> <slug>`, decide delegation via `coordination/router-checklist.md`, run it, then `coordination/scripts/mark-gate-delegated.sh <linear-id> <slug> <in-session|codex> [agent-type]`. If the status check shows it's already `approved`, someone else (the watcher) already delegated — report that instead of delegating again.
   - **Slack reply**: picked up by the scheduled watcher agent (see below) on its next wake, which performs the same approve → delegate → mark-delegated sequence on the original session's behalf.
3. On an unclear or negative reply, do not guess: for a clear rejection run `coordination/scripts/block-gate.sh <linear-id> <slug> "<reason>"` and reply explaining why in the same thread/chat; for an ambiguous reply, ask a clarifying question and leave the gate `awaiting-approval`. Never auto-retry a rejection.

**Watcher**: a scheduled Claude Code agent (see `coordination/watcher-prompt.md` for its exact instructions) wakes every 5 minutes, lists pending gates via `coordination/scripts/list-pending-gates.sh`, checks `#network-monitor` for replies referencing each one, and performs the same approve/block/delegate sequence above on behalf of sessions that have already ended.
```

- [ ] **Step 3: Add the subagent-selection table to `router-checklist.md`**

Append to `coordination/router-checklist.md` (after its existing final line, "Default to Claude Code for the first pass on anything new or ambiguous, and move to Codex once the task has been broken down into scoped, well-specified pieces."):

```markdown

## Choosing an Agent-tool subagent (in-session delegation)

Once a gate's delegation target is `in-session` (see `docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md`), pick the subagent type with the same read as the checklist above:

| Task nature | Subagent |
|---|---|
| Cross-subsystem design, ambiguous requirements, security-sensitive architecture | `network-monitor-architect` |
| Approved, scoped implementation — bug fixes, tests, refactors, docs | `network-monitor-developer` |
| Reviewing a diff for correctness/regressions/security before merge | `network-monitor-reviewer` |
| Verifying acceptance criteria via focused unit/integration/e2e tests | `network-monitor-tester` |
```

- [ ] **Step 4: Verify the documented commands actually match script behavior**

Run this scripted dry run using the real Task 2-3 scripts — it must complete with the exact outputs named in the comments below:

```bash
SLACK_WEBHOOK_URL="" coordination/scripts/create-gate.sh ZZZ-999 doc-verify-$$ "doc verification" interactive
coordination/scripts/gate-status.sh ZZZ-999 doc-verify-$$   # expect: status=awaiting-approval delegated=false
coordination/scripts/approve-gate.sh ZZZ-999 doc-verify-$$  # expect: approved
coordination/scripts/mark-gate-delegated.sh ZZZ-999 doc-verify-$$ in-session network-monitor-developer
coordination/scripts/gate-status.sh ZZZ-999 doc-verify-$$   # expect: status=approved delegated=true
rm coordination/gates/zzz-999-doc-verify-$$.md
```

Expected: every command's output matches what's documented in the new `AGENTS.md` section; the test gate file is removed afterward.

Also run: `grep -n "TBD\|<fill in>\|TODO" AGENTS.md coordination/router-checklist.md` and confirm none of the matches fall inside the sections just added (pre-existing `<fill in>` placeholders elsewhere, e.g. in task-contract templates, are out of scope and expected to remain).

- [ ] **Step 5: Commit**

```bash
git add AGENTS.md coordination/router-checklist.md
git commit -m "docs: document the Slack approval gate workflow in AGENTS.md and router-checklist.md"
```

---

### Task 5: Watcher setup

**Files:**
- Create: `coordination/watcher-prompt.md`

**Interfaces:**
- Consumes: `list-pending-gates.sh`, `gate-status.sh`, `approve-gate.sh`, `block-gate.sh`, `mark-gate-delegated.sh` (Task 3), `router-checklist.md` (Task 4) — the watcher's instructions reference these by their real command shape.
- Produces: a running scheduled Claude Code agent, created via the `schedule` skill, whose task text is (or directly references) `coordination/watcher-prompt.md`.

- [ ] **Step 1: Write `coordination/watcher-prompt.md`**

```markdown
# Slack Approval Gate Watcher

Scheduled agent instructions — see docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md for the full design.

Each time you wake:

1. Run `coordination/scripts/list-pending-gates.sh` from the main repo root. If it prints nothing, stop — nothing to do this wake.
2. For each line (`<linear_id> <slug> <posted_at>`), read the `#network-monitor` Slack channel for messages or thread replies mentioning `<linear_id>-<slug>` posted after `<posted_at>`.
3. If there's no qualifying reply yet, move to the next gate. Do not post anything, do not change any state.
4. If there's a qualifying reply, use your own judgment to classify it:
   - **Clear approval** ("approved", "go ahead", "yes", "lgtm", etc.): run `coordination/scripts/gate-status.sh <linear_id> <slug>` first. If it still shows `status=awaiting-approval`, run `coordination/scripts/approve-gate.sh <linear_id> <slug>`. If that succeeds (prints "approved"), decide delegation via `coordination/router-checklist.md`, carry it out (spawn the right Agent-tool subagent for in-session work, or run `coordination/scripts/new-task.sh` for Codex work), then run `coordination/scripts/mark-gate-delegated.sh <linear_id> <slug> <in-session|codex> [agent-type]`. If the status check already showed `approved`, or `approve-gate.sh` exits 2, someone else (the original chat session) already handled it — do nothing further for this gate.
   - **Clear rejection**: run `coordination/scripts/block-gate.sh <linear_id> <slug> "<why, from the reply>"`, then reply in the same Slack thread acknowledging it's blocked. Do not delegate. Do not retry automatically on a later wake.
   - **Unclear / a question, not a decision**: reply in the Slack thread asking for a clear approve/reject. Leave the gate `awaiting-approval`.
5. Move to the next pending gate and repeat step 2.
```

- [x] **Steps 2-3: SUPERSEDED (ruling, 2026-09-25)** — Originally: invoke the `schedule` skill to create a recurring cloud agent (5-minute interval) running `coordination/watcher-prompt.md` as a standing scheduled process. Discovered infeasible when actually invoking the `schedule` skill: its cloud agents run on a fresh GitHub clone in an isolated sandbox with no access to local, uncommitted files — `coordination/gates/*.md` is local-only state (same as `coordination/tasks/*.md`), so a cloud watcher could never see a real gate. Per explicit user direction ("not concerned with the watcher working in cloud, only locally while chat session is active" + "check slack every 60 seconds"), this was replaced with: the gate-creating session polls Slack itself, every 60 seconds, only while it remains active — no separate scheduled/cloud agent. `coordination/watcher-prompt.md` (Step 1) was rewritten to describe this in-session polling model instead of a separate agent's wake cycle. See `docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md`'s Approaches Considered / Non-Goals amendments for the full rationale. No scheduled agent exists or is needed.

- [ ] **Step 4: Commit**

```bash
git add coordination/watcher-prompt.md
git commit -m "coordination: add the Slack approval gate watcher's scheduled-agent prompt"
```

(The scheduled agent registration itself isn't a git-tracked artifact — only its prompt file is committed here.)

---

### Task 6: End-to-end verification

No new files — this task exercises Tasks 1-5 together for real, against the live `#network-monitor` Slack channel, matching this repo's established convention of exercising `coordination/scripts/*` end-to-end rather than trusting a read-through. Clean up every test artifact (gate files, any worktrees/branches created by a real delegation) afterward, same as prior coordination-kit verification sessions.

- [ ] **Step 1: Chat-approval path**

In an interactive session: create a real gate (`create-gate.sh <a-real-or-test-linear-id> <slug> "<plan>" interactive`), confirm the post appears in `#network-monitor`, then approve in the same chat. Confirm `gate-status.sh` shows `status=approved delegated=true` afterward and that delegation actually ran (an Agent-tool subagent was spawned, or `new-task.sh` created a worktree/branch — clean up whichever it was).

- [ ] **Step 2: Slack-only path (revised — same-session polling, not a scheduled watcher, per the Task 5 ruling above)**

Create a second gate in `interactive` mode. Instead of replying in chat, reply only in the Slack thread, and have the session poll for it per `coordination/watcher-prompt.md` (every 60 seconds) rather than waiting on the next chat message. Confirm the poll picks it up: `gate-status.sh` shows `status=approved delegated=true`, and delegation happened correctly. Exercise this once with an approval that should route to an in-session Agent subagent, and once with an approval that should route to Codex via `new-task.sh` (per `router-checklist.md`'s criteria) — confirming both delegation targets work, not just one.

- [ ] **Step 3: Race case**

Create a third gate. Have a chat-session approval and a Slack-reply approval land within a few seconds of each other (approve in chat, then immediately also reply "approved" in the Slack thread, or vice versa). Confirm exactly one delegation occurred — `gate-status.sh` shows `delegated=true` exactly once, not two worktrees/subagents for the same gate.

- [ ] **Step 4: Rejection and ambiguous-reply paths**

Create a fourth gate. Reply with a clear rejection ("no, don't do this — wrong approach"). Confirm `gate-status.sh` shows `status=blocked` and that a reply was actually posted back in the thread. Create a fifth gate and reply with something ambiguous ("hmm, not sure"). Confirm the gate stays `awaiting-approval` and a clarifying question was posted, not a guess.

- [ ] **Step 5: Missing-webhook failure path**

With `SLACK_WEBHOOK_URL` unset, confirm `create-gate.sh <id> <slug> "<plan>" autonomous` refuses (matches Task 2's automated test, re-confirmed live) and `create-gate.sh <id> <slug> "<plan>" interactive` still creates a usable gate with a warning.

- [ ] **Step 6: Clean up**

Delete every test gate file under `coordination/gates/`, remove any worktrees/branches created by real delegation during this verification, and confirm `git status` is clean before finishing.

- [ ] **Step 7: Record the verification**

Update `.ai/HANDOFF.md` (or `.ai/TEST_STATUS.md`, per this repo's convention for recording verified-but-not-automated behavior) noting exactly what was exercised for real and when, matching how the original `coordination-kit` merge's end-to-end exercise was recorded.
