#!/usr/bin/env bash
# Reclaims a gate whose delegated dispatch shows no real progress: no
# commit unique to its branch, no PR (open, closed, or merged), and its
# task contract still shows status: open. This ALWAYS requires an operator
# to explicitly confirm via --confirm-human-authorized-takeover -- there is
# no automatic, timeout-based path, and an agent must never invoke this on
# its own as part of routine queue traversal. It runs only when a human, in
# a live chat session, has explicitly said to take over a specific claimed
# task.
#
# A claim an agent holds does not expire on a timer -- only on explicit
# human say-so, the same as every other gate-reset path in this file (see
# reset-gate-delegation-claim.sh's --confirm-no-active-delegation). JAM-161
# originally gave this script a 60-minute no-confirmation auto-reclaim path
# as a narrow, explicitly-approved exception; James asked in chat on
# 2026-09-28 to remove that exception -- a timeout must never be how one
# agent takes over another's claimed work, so there is no longer an
# unattended trigger here at all.
#
# Checks, all of which must pass before a human's confirmation is even
# consulted:
#   - the gate is approved and delegated (a dispatch actually completed)
#   - its task contract's status is still "open" (review/done means real
#     progress was already recorded -- never reclaim that)
#   - no commit unique to its branch (ahead of main) -- a real commit is
#     real progress regardless of how much wall-clock time has passed,
#     and is never silently overridden here even with confirmation
#   - no PR (open, closed, or merged) exists for that branch -- real,
#     externally-visible work in flight is never reclaimed regardless of
#     confirmation; and if the PR check itself can't be completed (gh
#     failure), this refuses rather than assuming "no PR"
#
# Reclaiming only resets the gate's delegation fields back to "approved,
# unclaimed" so claim-gate-delegation.sh can run again -- it does NOT touch
# the task contract, worktree, or branch, which stay exactly as they were
# in case the original agent comes back: a reclaiming agent re-enters that
# existing worktree rather than running new-task.sh again. It also posts
# `reclaimed` to Slack, since a takeover should stay visible.
#
# Usage:
#   ./reclaim-stale-gate.sh <linear-id> <slug> --confirm-human-authorized-takeover
#
# Exit 0 and prints "reclaimed" if this call reclaimed the gate. Exit 2 and
# prints why ("not-delegated", "already-progressed", "commit-exists",
# "pr-exists", or the gate's actual status if it isn't "approved" at all)
# if it refused, without changing anything. Exit 1 on a real error (missing
# confirmation flag, no such gate, no task contract for a delegated gate,
# or the PR-existence check itself failing).

set -euo pipefail

LINEAR_ID="${1:?usage: reclaim-stale-gate.sh <linear-id> <slug> --confirm-human-authorized-takeover}"
SLUG="${2:?usage: reclaim-stale-gate.sh <linear-id> <slug> --confirm-human-authorized-takeover}"
CONFIRM="${3:-}"

if [[ "$CONFIRM" != "--confirm-human-authorized-takeover" || $# -ne 3 ]]; then
  echo "refusing to reclaim without --confirm-human-authorized-takeover -- this always requires a human's explicit say-so in a live chat session, never an automatic timeout" >&2
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

LINEAR_ID_LOWER="$(echo "$LINEAR_ID" | tr '[:upper:]' '[:lower:]')"
GATE_TAG="${LINEAR_ID_LOWER}__${SLUG}"
TASK_FILE="$REPO_ROOT/coordination/tasks/${SLUG}.md"

_reclaim_locked() {
  gate_require_status "$GATE_FILE" approved || return $?

  local delegated
  delegated="$(gate_field "$GATE_FILE" delegated)"
  if [[ "$delegated" != "true" ]]; then
    echo "not-delegated"
    return 2
  fi

  if [[ ! -f "$TASK_FILE" ]]; then
    echo "no task contract for a delegated gate: $TASK_FILE" >&2
    return 1
  fi
  local task_status
  task_status="$(gate_field "$TASK_FILE" status)"
  if [[ "$task_status" != "open" ]]; then
    echo "already-progressed"
    return 2
  fi

  local branch delegated_at
  branch="$(gate_field "$TASK_FILE" branch)"
  delegated_at="$(gate_field "$GATE_FILE" delegated_at)"

  # --end-of-options keeps a branch name that happens to start with "-"
  # (e.g. "--output=/some/path") from being parsed as a git flag instead of
  # a revision -- the argument-injection gap an independent review flagged
  # against the original (age-based) version of this check.
  if git -C "$REPO_ROOT" log --format=%H -1 --end-of-options "$branch" ^main 2>/dev/null | grep -q .; then
    echo "commit-exists"
    return 2
  fi

  local pr_json pr_rc=0
  pr_json="$(cd "$REPO_ROOT" && gh pr list --head "$branch" --state all --json number 2>/dev/null)" || pr_rc=$?
  if [[ $pr_rc -ne 0 ]]; then
    echo "could not verify PR status for branch ${branch} (gh exited ${pr_rc}) -- refusing to reclaim rather than assume no PR exists" >&2
    return 1
  fi
  if [[ -n "$pr_json" && "$pr_json" != "[]" ]]; then
    echo "pr-exists"
    return 2
  fi

  local age_note=""
  if [[ -n "$delegated_at" ]]; then
    local delegated_at_epoch
    delegated_at_epoch="$(iso8601_to_epoch "$delegated_at" 2>/dev/null || true)"
    if [[ -n "$delegated_at_epoch" ]]; then
      age_note=" (delegated $(( $(date +%s) - delegated_at_epoch ))s ago)"
    fi
  fi

  gate_set_field "$GATE_FILE" delegated false || return $?
  gate_set_field "$GATE_FILE" delegation_claimed false || return $?
  gate_set_field "$GATE_FILE" delegation_target "" || return $?
  gate_set_field "$GATE_FILE" delegation_agent_type "" || return $?
  gate_set_field "$GATE_FILE" delegated_at "" || return $?
  if ! slack_post_and_record "$GATE_FILE" "reclaimed" "$GATE_TAG" "gate" "Reclaimed with explicit human confirmation in a live chat session -- no commit, no PR, task status still open${age_note} -- available for claim-gate-delegation.sh again."; then
    echo "reclaimed the gate, but the Slack post about it failed -- tell James directly" >&2
  fi
  echo "reclaimed"
}

with_gate_lock "$GATE_FILE" _reclaim_locked
