#!/usr/bin/env bash
# Exercises reclaim-stale-gate.sh's confirmation/commit/PR/progress checks.
# Uses git plumbing (commit-tree/update-ref) to create test branches without
# ever touching any worktree's working directory or index — safe to run
# alongside other active sessions on this repo.
#
# Every invocation below explicitly sets both SLACK_WEBHOOK_URL and
# SLACK_BOT_TOKEN to "" (never leaving either unset) — reclaim now posts a
# `reclaimed` Slack status on success, and sourcing lib.sh may otherwise
# load real credentials from coordination/.env. See test-create-gate.sh's
# own comment on this for the precedent and the leak it prevents.
#
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
# `pr list` invocation (or fails with $FAKE_GH_EXIT if set nonzero),
# regardless of arguments — no real network call.
cat > "$FAKE_BIN/gh" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "pr" && "$2" == "list" ]]; then
  if [[ -n "${FAKE_GH_EXIT:-}" && "${FAKE_GH_EXIT}" != "0" ]]; then
    echo "fake gh: simulated failure" >&2
    exit "${FAKE_GH_EXIT}"
  fi
  printf '%s' "${FAKE_GH_PR_LIST:-[]}"
  exit 0
fi
exit 1
EOF
chmod +x "$FAKE_BIN/gh"

# Makes a throwaway branch pointing at a new commit (if $2 is "with-commit")
# or exactly at main with no new commit ($2 is "same-as-main" or omitted) —
# via plumbing only, so no working directory is ever touched.
make_branch() {
  local branch="$1" mode="${2:-same-as-main}"
  if [[ "$mode" == "same-as-main" ]]; then
    git -C "$REPO_ROOT" branch "$branch" main
  else
    local tree commit
    tree="$(git -C "$REPO_ROOT" rev-parse main^{tree})"
    commit="$(git -C "$REPO_ROOT" commit-tree "$tree" -p main -m "test commit for reclaim-stale-gate")"
    git -C "$REPO_ROOT" update-ref "refs/heads/${branch}" "$commit"
  fi
  BRANCHES_MADE+=("$branch")
}

# Makes a gate file already in the post-dispatch state (approved, claimed,
# delegated, with a recorded delegated_at) that reclaim-stale-gate.sh
# operates on. delegated_at defaults to "now" — staleness is no longer a
# gating condition, so tests don't need to backdate it.
make_delegated_gate() {
  local slug="$1" delegated_at_epoch="${2:-$(date +%s)}"
  local gate_file delegated_at
  gate_file="$(gate_path "$TEST_LINEAR_ID" "$slug")"
  delegated_at="$(date -u -r "$delegated_at_epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@${delegated_at_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
  mkdir -p "$(dirname "$gate_file")"
  cat > "$gate_file" <<EOF
---
linear_id: ${TEST_LINEAR_ID}
slug: ${slug}
status: approved
delegated: true
delegation_claimed: true
posted_at: 2026-09-25T00:00:00Z
delegated_at: ${delegated_at}
delegation_target: in-session
delegation_agent_type: claude
---

## Plan

test
EOF
  GATES_MADE+=("$gate_file")
  echo "$gate_file"
}

# Makes a task contract file with the given status/branch.
make_task_file() {
  local slug="$1" status="$2" branch="$3"
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
  TASKS_MADE+=("$task_file")
  echo "$task_file"
}

RECLAIM() {
  SLACK_WEBHOOK_URL="" SLACK_BOT_TOKEN="" PATH="$FAKE_BIN:$PATH" \
    "$BIN/reclaim-stale-gate.sh" "$@"
}

# Case A: missing --confirm-human-authorized-takeover — must refuse even
# though the gate is otherwise cleanly reclaimable. This is the regression
# test for "no timeout, no unattended path": nothing here should ever
# succeed without the explicit flag, regardless of how the gate looks.
SLUG_A="reclaim-test-a-${RUN_ID}"
GATE_A="$(make_delegated_gate "$SLUG_A")"
BRANCH_A="test-reclaim-a-${RUN_ID}"
make_branch "$BRANCH_A"
make_task_file "$SLUG_A" "open" "$BRANCH_A" >/dev/null
OUT_A="$(FAKE_GH_PR_LIST='[]' RECLAIM "$TEST_LINEAR_ID" "$SLUG_A" 2>/dev/null)"; RC_A=$?
if [[ $RC_A -eq 1 ]]; then
  echo "PASS: refuses without the explicit human-confirmation flag"
else
  echo "FAIL: expected exit 1 without --confirm-human-authorized-takeover — got rc=$RC_A '$OUT_A'"
  FAILURES=$((FAILURES + 1))
fi
DELEGATED_AFTER_A="$(gate_field "$GATE_A" delegated)"
if [[ "$DELEGATED_AFTER_A" == "true" ]]; then
  echo "PASS: gate is untouched when confirmation is missing"
else
  echo "FAIL: expected delegated=true (untouched) — got delegated=$DELEGATED_AFTER_A"
  FAILURES=$((FAILURES + 1))
fi

# Case B: gate isn't delegated yet — nothing to reclaim, even with confirmation.
SLUG_B="reclaim-test-b-${RUN_ID}"
GATE_B="$(make_delegated_gate "$SLUG_B")"
gate_set_field "$GATE_B" delegated false
OUT_B="$(RECLAIM "$TEST_LINEAR_ID" "$SLUG_B" --confirm-human-authorized-takeover 2>/dev/null)"; RC_B=$?
if [[ $RC_B -eq 2 && "$OUT_B" == "not-delegated" ]]; then
  echo "PASS: refuses when the gate isn't delegated yet"
else
  echo "FAIL: expected 'not-delegated' rc=2 — got rc=$RC_B '$OUT_B'"
  FAILURES=$((FAILURES + 1))
fi

# Case C: task file already shows real progress (status != open).
SLUG_C="reclaim-test-c-${RUN_ID}"
make_delegated_gate "$SLUG_C" >/dev/null
BRANCH_C="test-reclaim-c-${RUN_ID}"
make_branch "$BRANCH_C"
make_task_file "$SLUG_C" "review" "$BRANCH_C" >/dev/null
OUT_C="$(RECLAIM "$TEST_LINEAR_ID" "$SLUG_C" --confirm-human-authorized-takeover 2>/dev/null)"; RC_C=$?
if [[ $RC_C -eq 2 && "$OUT_C" == "already-progressed" ]]; then
  echo "PASS: refuses when the task already recorded real progress"
else
  echo "FAIL: expected 'already-progressed' rc=2 — got rc=$RC_C '$OUT_C'"
  FAILURES=$((FAILURES + 1))
fi

# Case D: delegated_at is this very second — reclaims anyway. There is no
# minimum wait time any more; a human's confirmation is the sole gate.
SLUG_D="reclaim-test-d-${RUN_ID}"
GATE_D="$(make_delegated_gate "$SLUG_D")"
BRANCH_D="test-reclaim-d-${RUN_ID}"
make_branch "$BRANCH_D"
make_task_file "$SLUG_D" "open" "$BRANCH_D" >/dev/null
OUT_D="$(FAKE_GH_PR_LIST='[]' RECLAIM "$TEST_LINEAR_ID" "$SLUG_D" --confirm-human-authorized-takeover 2>/dev/null)"; RC_D=$?
if [[ $RC_D -eq 0 && "$OUT_D" == "reclaimed" ]]; then
  echo "PASS: reclaims immediately with confirmation, no minimum elapsed time required"
else
  echo "FAIL: expected 'reclaimed' rc=0 — got rc=$RC_D '$OUT_D'"
  FAILURES=$((FAILURES + 1))
fi
DELEGATED_AFTER="$(gate_field "$GATE_D" delegated)"
CLAIMED_AFTER="$(gate_field "$GATE_D" delegation_claimed)"
DELEGATED_AT_AFTER="$(gate_field "$GATE_D" delegated_at)"
if [[ "$DELEGATED_AFTER" == "false" && "$CLAIMED_AFTER" == "false" && -z "$DELEGATED_AT_AFTER" ]]; then
  echo "PASS: reclaimed gate is fully unclaimed, ready for claim-gate-delegation.sh again"
else
  echo "FAIL: expected delegated=false delegation_claimed=false delegated_at=<empty> — got delegated=$DELEGATED_AFTER delegation_claimed=$CLAIMED_AFTER delegated_at=$DELEGATED_AT_AFTER"
  FAILURES=$((FAILURES + 1))
fi
STATUS_AFTER="$(gate_field "$GATE_D" status)"
[[ "$STATUS_AFTER" == "approved" ]] && echo "PASS: reclaimed gate stays approved (James's original approval still stands)" \
  || { echo "FAIL: expected status to remain 'approved' — got '$STATUS_AFTER'"; FAILURES=$((FAILURES + 1)); }

# Case E: a PR already exists — refuse even with confirmation. Real,
# externally-visible work is never silently taken over.
SLUG_E="reclaim-test-e-${RUN_ID}"
make_delegated_gate "$SLUG_E" >/dev/null
BRANCH_E="test-reclaim-e-${RUN_ID}"
make_branch "$BRANCH_E"
make_task_file "$SLUG_E" "open" "$BRANCH_E" >/dev/null
OUT_E="$(FAKE_GH_PR_LIST='[{"number":42}]' RECLAIM "$TEST_LINEAR_ID" "$SLUG_E" --confirm-human-authorized-takeover 2>/dev/null)"; RC_E=$?
if [[ $RC_E -eq 2 && "$OUT_E" == "pr-exists" ]]; then
  echo "PASS: refuses when a PR exists even with explicit confirmation"
else
  echo "FAIL: expected 'pr-exists' rc=2 — got rc=$RC_E '$OUT_E'"
  FAILURES=$((FAILURES + 1))
fi

# Case F: a commit unique to the branch exists — refuse even with
# confirmation. A real commit is real progress regardless of how much
# wall-clock time has passed since delegation.
SLUG_F="reclaim-test-f-${RUN_ID}"
make_delegated_gate "$SLUG_F" >/dev/null
BRANCH_F="test-reclaim-f-${RUN_ID}"
make_branch "$BRANCH_F" with-commit
make_task_file "$SLUG_F" "open" "$BRANCH_F" >/dev/null
OUT_F="$(FAKE_GH_PR_LIST='[]' RECLAIM "$TEST_LINEAR_ID" "$SLUG_F" --confirm-human-authorized-takeover 2>/dev/null)"; RC_F=$?
if [[ $RC_F -eq 2 && "$OUT_F" == "commit-exists" ]]; then
  echo "PASS: refuses when the branch has a unique commit, even with confirmation"
else
  echo "FAIL: expected 'commit-exists' rc=2 — got rc=$RC_F '$OUT_F'"
  FAILURES=$((FAILURES + 1))
fi

# Case G: the PR-existence check itself fails (gh unreachable/unauthenticated)
# — must fail closed (refuse to reclaim) rather than assume "no PR".
SLUG_G="reclaim-test-g-${RUN_ID}"
GATE_G="$(make_delegated_gate "$SLUG_G")"
BRANCH_G="test-reclaim-g-${RUN_ID}"
make_branch "$BRANCH_G"
make_task_file "$SLUG_G" "open" "$BRANCH_G" >/dev/null
OUT_G="$(FAKE_GH_EXIT=1 RECLAIM "$TEST_LINEAR_ID" "$SLUG_G" --confirm-human-authorized-takeover 2>/dev/null)"; RC_G=$?
if [[ $RC_G -eq 1 ]]; then
  echo "PASS: refuses (exit 1) rather than reclaim when the PR check itself fails"
else
  echo "FAIL: expected exit 1 when gh fails — got rc=$RC_G '$OUT_G'"
  FAILURES=$((FAILURES + 1))
fi
DELEGATED_AFTER_G="$(gate_field "$GATE_G" delegated)"
if [[ "$DELEGATED_AFTER_G" == "true" ]]; then
  echo "PASS: gate is untouched when the PR check fails"
else
  echo "FAIL: expected delegated=true (untouched) — got delegated=$DELEGATED_AFTER_G"
  FAILURES=$((FAILURES + 1))
fi

# Case H: a branch name shaped like a git flag (the argument-injection class
# an independent review flagged) must never be parsed as one — regression
# test for that fix, not just a functional case. If unfixed, git would
# error out on the injected "flag" but this real repro (from manual
# verification outside this suite) showed it can still create a file
# on-disk at an attacker-chosen path from BRANCH="--output=...". Here we
# just confirm reclaim behaves exactly as it would for any other no-PR,
# no-commit branch — treating the value as a plain (non-existent)
# revision — and that no stray file appears from the git invocation.
SLUG_H="reclaim-test-h-${RUN_ID}"
make_delegated_gate "$SLUG_H" >/dev/null
INJECTION_TARGET="$FAKE_BIN/pwned-${RUN_ID}.txt"
BRANCH_H="--output=${INJECTION_TARGET}"
make_task_file "$SLUG_H" "open" "$BRANCH_H" >/dev/null
OUT_H="$(FAKE_GH_PR_LIST='[]' RECLAIM "$TEST_LINEAR_ID" "$SLUG_H" --confirm-human-authorized-takeover 2>/dev/null)"; RC_H=$?
if [[ $RC_H -eq 0 && "$OUT_H" == "reclaimed" ]]; then
  echo "PASS: a flag-shaped branch name is treated as a plain revision, not injected as a git option"
else
  echo "FAIL: expected 'reclaimed' rc=0 for a flag-shaped branch — got rc=$RC_H '$OUT_H'"
  FAILURES=$((FAILURES + 1))
fi
if [[ ! -e "$INJECTION_TARGET" ]]; then
  echo "PASS: no file was created at the flag-shaped branch's implied path"
else
  echo "FAIL: injection target $INJECTION_TARGET was created — argument injection regressed"
  FAILURES=$((FAILURES + 1))
fi

if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES test(s) failed."
  exit 1
fi
echo "All tests passed."
