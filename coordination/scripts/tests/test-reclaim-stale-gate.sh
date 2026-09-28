#!/usr/bin/env bash
# Exercises reclaim-stale-gate.sh's staleness/PR/progress checks (JAM-161).
# Uses git plumbing (commit-tree/update-ref) to create test branches without
# ever touching any worktree's working directory or index — safe to run
# alongside other active sessions on this repo.
# Run: bash coordination/scripts/tests/test-reclaim-stale-gate.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/.."
# shellcheck disable=SC1091
source "$BIN/lib.sh"
FAILURES=0
TEST_LINEAR_ID="ZZZ-999"
RUN_ID="$$"

FAKE_BIN="$(mktemp -d)"
TASKS_MADE=()
BRANCHES_MADE=()
GATES_MADE=()

cleanup() {
  for f in "${GATES_MADE[@]:-}"; do rm -f "$f"; done
  for t in "${TASKS_MADE[@]:-}"; do rm -f "$t"; done
  for b in "${BRANCHES_MADE[@]:-}"; do git -C "$REPO_ROOT" branch -D "$b" >/dev/null 2>&1 || true; done
  rm -rf "$FAKE_BIN"
}
trap cleanup EXIT

# A fake `gh` that returns whatever $FAKE_GH_PR_LIST holds for any
# `pr list` invocation, regardless of arguments — no real network call.
cat > "$FAKE_BIN/gh" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "pr" && "$2" == "list" ]]; then
  printf '%s' "${FAKE_GH_PR_LIST:-[]}"
  exit 0
fi
exit 1
EOF
chmod +x "$FAKE_BIN/gh"

# Makes a throwaway branch pointing at a new commit dated $2 seconds since
# epoch (or exactly at main, with no new commit, if $2 is "same-as-main") —
# via plumbing only, so no working directory is ever touched.
make_branch() {
  local branch="$1" epoch="${2:-}"
  if [[ "$epoch" == "same-as-main" ]]; then
    git -C "$REPO_ROOT" branch "$branch" main
  else
    local tree commit
    tree="$(git -C "$REPO_ROOT" rev-parse main^{tree})"
    commit="$(GIT_AUTHOR_DATE="@${epoch}" GIT_COMMITTER_DATE="@${epoch}" \
      git -C "$REPO_ROOT" commit-tree "$tree" -p main -m "test commit for reclaim-stale-gate")"
    git -C "$REPO_ROOT" update-ref "refs/heads/${branch}" "$commit"
  fi
  BRANCHES_MADE+=("$branch")
}

# Makes a gate file already in the post-dispatch state (approved, claimed,
# delegated) that reclaim-stale-gate.sh operates on.
make_delegated_gate() {
  local slug="$1"
  local gate_file
  gate_file="$(gate_path "$TEST_LINEAR_ID" "$slug")"
  mkdir -p "$(dirname "$gate_file")"
  cat > "$gate_file" <<EOF
---
linear_id: ${TEST_LINEAR_ID}
slug: ${slug}
status: approved
delegated: true
delegation_claimed: true
posted_at: 2026-09-25T00:00:00Z
delegation_target: in-session
delegation_agent_type: claude
---

## Plan

test
EOF
  GATES_MADE+=("$gate_file")
  echo "$gate_file"
}

# Makes a task contract file with the given status/branch and mtime.
# mtime_epoch of "now" leaves it freshly touched; otherwise backdates it.
make_task_file() {
  local slug="$1" status="$2" branch="$3" mtime_epoch="${4:-now}"
  local task_file="$REPO_ROOT/coordination/tasks/${slug}.md"
  cat > "$task_file" <<EOF
---
task: ${slug}
owner: claude-code
status: ${status}
branch: ${branch}
linear_id: ${TEST_LINEAR_ID}
depends_on: []
created: 2026-09-25
slack_ts:
---

## Goal

test
EOF
  if [[ "$mtime_epoch" != "now" ]]; then
    touch -t "$(date -r "$mtime_epoch" +%Y%m%d%H%M.%S 2>/dev/null || date -d "@${mtime_epoch}" +%Y%m%d%H%M.%S)" "$task_file"
  fi
  TASKS_MADE+=("$task_file")
  echo "$task_file"
}

NOW="$(date +%s)"
TWO_HOURS_AGO=$((NOW - 7200))
THIRTY_MIN_AGO=$((NOW - 1800))

# Case A: gate isn't delegated yet — nothing to reclaim.
SLUG_A="reclaim-test-a-${RUN_ID}"
GATE_A="$(make_delegated_gate "$SLUG_A")"
gate_set_field "$GATE_A" delegated false
OUT_A="$(RECLAIM_STALE_AFTER_SECONDS=3600 PATH="$FAKE_BIN:$PATH" "$BIN/reclaim-stale-gate.sh" "$TEST_LINEAR_ID" "$SLUG_A" 2>&1)"; RC_A=$?
if [[ $RC_A -eq 2 && "$OUT_A" == "not-delegated" ]]; then
  echo "PASS: refuses when the gate isn't delegated yet"
else
  echo "FAIL: expected 'not-delegated' rc=2 — got rc=$RC_A '$OUT_A'"
  FAILURES=$((FAILURES + 1))
fi

# Case B: task file already shows real progress (status != open).
SLUG_B="reclaim-test-b-${RUN_ID}"
make_delegated_gate "$SLUG_B" >/dev/null
BRANCH_B="test-reclaim-b-${RUN_ID}"
make_branch "$BRANCH_B" same-as-main
make_task_file "$SLUG_B" "review" "$BRANCH_B" "$TWO_HOURS_AGO" >/dev/null
OUT_B="$(RECLAIM_STALE_AFTER_SECONDS=3600 PATH="$FAKE_BIN:$PATH" "$BIN/reclaim-stale-gate.sh" "$TEST_LINEAR_ID" "$SLUG_B" 2>&1)"; RC_B=$?
if [[ $RC_B -eq 2 && "$OUT_B" == "already-progressed" ]]; then
  echo "PASS: refuses when the task already recorded real progress"
else
  echo "FAIL: expected 'already-progressed' rc=2 — got rc=$RC_B '$OUT_B'"
  FAILURES=$((FAILURES + 1))
fi

# Case C: task file is fresh — not stale yet.
SLUG_C="reclaim-test-c-${RUN_ID}"
make_delegated_gate "$SLUG_C" >/dev/null
BRANCH_C="test-reclaim-c-${RUN_ID}"
make_branch "$BRANCH_C" same-as-main
make_task_file "$SLUG_C" "open" "$BRANCH_C" now >/dev/null
OUT_C="$(RECLAIM_STALE_AFTER_SECONDS=3600 PATH="$FAKE_BIN:$PATH" "$BIN/reclaim-stale-gate.sh" "$TEST_LINEAR_ID" "$SLUG_C" 2>&1)"; RC_C=$?
if [[ $RC_C -eq 2 && "$OUT_C" == "not-stale" ]]; then
  echo "PASS: refuses when not stale yet"
else
  echo "FAIL: expected 'not-stale' rc=2 — got rc=$RC_C '$OUT_C'"
  FAILURES=$((FAILURES + 1))
fi

# Case D: stale by every local signal, but a PR already exists.
SLUG_D="reclaim-test-d-${RUN_ID}"
make_delegated_gate "$SLUG_D" >/dev/null
BRANCH_D="test-reclaim-d-${RUN_ID}"
make_branch "$BRANCH_D" same-as-main
make_task_file "$SLUG_D" "open" "$BRANCH_D" "$TWO_HOURS_AGO" >/dev/null
OUT_D="$(FAKE_GH_PR_LIST='[{"number":42}]' RECLAIM_STALE_AFTER_SECONDS=3600 PATH="$FAKE_BIN:$PATH" "$BIN/reclaim-stale-gate.sh" "$TEST_LINEAR_ID" "$SLUG_D" 2>&1)"; RC_D=$?
if [[ $RC_D -eq 2 && "$OUT_D" == "pr-exists" ]]; then
  echo "PASS: refuses when a PR exists even though otherwise stale"
else
  echo "FAIL: expected 'pr-exists' rc=2 — got rc=$RC_D '$OUT_D'"
  FAILURES=$((FAILURES + 1))
fi

# Case E: genuinely stale, no PR, no unique commits — reclaims.
SLUG_E="reclaim-test-e-${RUN_ID}"
GATE_E="$(make_delegated_gate "$SLUG_E")"
BRANCH_E="test-reclaim-e-${RUN_ID}"
make_branch "$BRANCH_E" same-as-main
make_task_file "$SLUG_E" "open" "$BRANCH_E" "$TWO_HOURS_AGO" >/dev/null
OUT_E="$(FAKE_GH_PR_LIST='[]' RECLAIM_STALE_AFTER_SECONDS=3600 PATH="$FAKE_BIN:$PATH" "$BIN/reclaim-stale-gate.sh" "$TEST_LINEAR_ID" "$SLUG_E" 2>&1)"; RC_E=$?
if [[ $RC_E -eq 0 && "$OUT_E" == "reclaimed" ]]; then
  echo "PASS: reclaims a genuinely stale, PR-less, progress-less gate"
else
  echo "FAIL: expected 'reclaimed' rc=0 — got rc=$RC_E '$OUT_E'"
  FAILURES=$((FAILURES + 1))
fi
DELEGATED_AFTER="$(gate_field "$GATE_E" delegated)"
CLAIMED_AFTER="$(gate_field "$GATE_E" delegation_claimed)"
if [[ "$DELEGATED_AFTER" == "false" && "$CLAIMED_AFTER" == "false" ]]; then
  echo "PASS: reclaimed gate is fully unclaimed, ready for claim-gate-delegation.sh again"
else
  echo "FAIL: expected delegated=false delegation_claimed=false — got delegated=$DELEGATED_AFTER delegation_claimed=$CLAIMED_AFTER"
  FAILURES=$((FAILURES + 1))
fi
STATUS_AFTER="$(gate_field "$GATE_E" status)"
[[ "$STATUS_AFTER" == "approved" ]] && echo "PASS: reclaimed gate stays approved (James's original approval still stands)" \
  || { echo "FAIL: expected status to remain 'approved' — got '$STATUS_AFTER'"; FAILURES=$((FAILURES + 1)); }

# Case F: task file itself looks old, but the branch has a commit within
# the staleness window — real activity, must not reclaim.
SLUG_F="reclaim-test-f-${RUN_ID}"
make_delegated_gate "$SLUG_F" >/dev/null
BRANCH_F="test-reclaim-f-${RUN_ID}"
make_branch "$BRANCH_F" "$THIRTY_MIN_AGO"
make_task_file "$SLUG_F" "open" "$BRANCH_F" "$TWO_HOURS_AGO" >/dev/null
OUT_F="$(FAKE_GH_PR_LIST='[]' RECLAIM_STALE_AFTER_SECONDS=3600 PATH="$FAKE_BIN:$PATH" "$BIN/reclaim-stale-gate.sh" "$TEST_LINEAR_ID" "$SLUG_F" 2>&1)"; RC_F=$?
if [[ $RC_F -eq 2 && "$OUT_F" == "not-stale" ]]; then
  echo "PASS: a recent commit on the branch counts as activity even if the task file itself looks old"
else
  echo "FAIL: expected 'not-stale' rc=2 — got rc=$RC_F '$OUT_F'"
  FAILURES=$((FAILURES + 1))
fi

if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES test(s) failed."
  exit 1
fi
echo "All tests passed."
