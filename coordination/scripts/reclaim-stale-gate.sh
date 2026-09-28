#!/usr/bin/env bash
# Automatically reclaims a gate whose delegated dispatch has gone stale:
# no unique commit on its branch and no PR for 60+ minutes (configurable
# via RECLAIM_STALE_AFTER_SECONDS), and its task contract still shows
# status: open (no review/done ever recorded for it). This is a
# deliberate, narrow exception to every other gate-mutating script's rule
# that a human must confirm before resetting a claim (see
# reset-gate-delegation-claim.sh's --confirm-no-active-delegation) —
# approved by James specifically for this time-boxed, PR-absence-checked
# offline-agent-recovery case (JAM-161), not a general bypass.
#
# "Stale" requires ALL of:
#   - the gate is approved and delegated (a dispatch actually completed)
#   - its task contract's status is still "open" (review/done means real
#     progress was already recorded — never reclaim that)
#   - no commit unique to its branch (ahead of main), and its task
#     contract file's own mtime, are both older than the staleness window
#     — an agent actively committing without a PR yet is not stale, even
#     if it hasn't touched the task file itself in a while
#   - no PR (open, closed, or merged) exists for that branch — real,
#     externally-visible work in flight is never reclaimed regardless of
#     how quiet the gate/task file look
#
# Reclaiming only resets the gate's delegation fields back to "approved,
# unclaimed" so claim-gate-delegation.sh can run again — it does NOT touch
# the task contract, worktree, or branch, which stay exactly as they were
# in case the original agent comes back: a reclaiming agent re-enters that
# existing worktree rather than running new-task.sh again.
#
# Usage:
#   ./reclaim-stale-gate.sh <linear-id> <slug>
#
# Exit 0 and prints "reclaimed" if this call reclaimed the gate. Exit 2 and
# prints why ("not-delegated", "already-progressed", "not-stale",
# "pr-exists") if it refused, without changing anything. Exit 1 on a real
# error (no such gate, or no task contract for it at all).

set -euo pipefail

STALE_AFTER_SECONDS="${RECLAIM_STALE_AFTER_SECONDS:-3600}"

LINEAR_ID="${1:?usage: reclaim-stale-gate.sh <linear-id> <slug>}"
SLUG="${2:?usage: reclaim-stale-gate.sh <linear-id> <slug>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$LINEAR_ID" "$SLUG")"
if [[ ! -f "$GATE_FILE" ]]; then
  echo "no such gate: $GATE_FILE" >&2
  exit 1
fi

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

  local branch task_mtime unique_commit_epoch last_activity now_epoch age
  branch="$(gate_field "$TASK_FILE" branch)"
  task_mtime="$(file_mtime_epoch "$TASK_FILE")"
  # No `set -e` trip on a branch with no unique commits (or no longer
  # present locally) — that's the common case, not an error.
  unique_commit_epoch="$(git -C "$REPO_ROOT" log "$branch" ^main --format=%ct -1 2>/dev/null || true)"
  last_activity="$task_mtime"
  if [[ -n "$unique_commit_epoch" && "$unique_commit_epoch" -gt "$last_activity" ]]; then
    last_activity="$unique_commit_epoch"
  fi
  now_epoch="$(date +%s)"
  age=$(( now_epoch - last_activity ))
  if [[ "$age" -lt "$STALE_AFTER_SECONDS" ]]; then
    echo "not-stale"
    return 2
  fi

  local pr_json
  pr_json="$(cd "$REPO_ROOT" && gh pr list --head "$branch" --state all --json number 2>/dev/null)" || pr_json="[]"
  if [[ -n "$pr_json" && "$pr_json" != "[]" ]]; then
    echo "pr-exists"
    return 2
  fi

  gate_set_field "$GATE_FILE" delegated false || return $?
  gate_set_field "$GATE_FILE" delegation_claimed false || return $?
  gate_set_field "$GATE_FILE" delegation_target "" || return $?
  gate_set_field "$GATE_FILE" delegation_agent_type "" || return $?
  echo "reclaimed"
}

with_gate_lock "$GATE_FILE" _reclaim_locked
