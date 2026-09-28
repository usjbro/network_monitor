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
#   - no commit unique to its branch (ahead of main), and the gate's own
#     delegated_at field (set once, under this same lock, by
#     mark-gate-delegated.sh — not any working-directory file's freely
#     rewritable mtime), are both older than the staleness window
#   - no PR (open, closed, or merged) exists for that branch — real,
#     externally-visible work in flight is never reclaimed regardless of
#     how quiet the gate looks; and if the PR check itself can't be
#     completed (gh failure), this refuses rather than assuming "no PR"
#
# Reclaiming only resets the gate's delegation fields back to "approved,
# unclaimed" so claim-gate-delegation.sh can run again — it does NOT touch
# the task contract, worktree, or branch, which stay exactly as they were
# in case the original agent comes back: a reclaiming agent re-enters that
# existing worktree rather than running new-task.sh again. It also posts
# `reclaimed` to Slack, since the whole reason no human confirmation is
# required here is that the action stays visible.
#
# Usage:
#   ./reclaim-stale-gate.sh <linear-id> <slug>
#
# Exit 0 and prints "reclaimed" if this call reclaimed the gate. Exit 2 and
# prints why ("not-delegated", "already-progressed", "not-stale",
# "pr-exists", or the gate's actual status if it isn't "approved" at all)
# if it refused, without changing anything. Exit 1 on a real error (no such
# gate, no task contract for a delegated gate, a delegated gate with no
# delegated_at recorded, or the PR-existence check itself failing).

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

  local branch delegated_at delegated_at_epoch unique_commit_epoch last_activity now_epoch age
  branch="$(gate_field "$TASK_FILE" branch)"
  delegated_at="$(gate_field "$GATE_FILE" delegated_at)"
  if [[ -z "$delegated_at" ]]; then
    echo "delegated gate has no delegated_at recorded: $GATE_FILE" >&2
    return 1
  fi
  delegated_at_epoch="$(iso8601_to_epoch "$delegated_at")"
  # No `set -e` trip on a branch with no unique commits (or no longer
  # present locally) — that's the common case, not an error. --end-of-options
  # keeps a branch name that happens to start with "-" (e.g.
  # "--output=/some/path") from being parsed as a git flag instead of a
  # revision — the argument-injection gap an independent review flagged.
  unique_commit_epoch="$(git -C "$REPO_ROOT" log --format=%ct -1 --end-of-options "$branch" ^main 2>/dev/null || true)"
  last_activity="$delegated_at_epoch"
  if [[ -n "$unique_commit_epoch" && "$unique_commit_epoch" -gt "$last_activity" ]]; then
    last_activity="$unique_commit_epoch"
  fi
  now_epoch="$(date +%s)"
  age=$(( now_epoch - last_activity ))
  if [[ "$age" -lt "$STALE_AFTER_SECONDS" ]]; then
    echo "not-stale"
    return 2
  fi

  local pr_json pr_rc=0
  pr_json="$(cd "$REPO_ROOT" && gh pr list --head "$branch" --state all --json number 2>/dev/null)" || pr_rc=$?
  if [[ $pr_rc -ne 0 ]]; then
    echo "could not verify PR status for branch ${branch} (gh exited ${pr_rc}) — refusing to reclaim rather than assume no PR exists" >&2
    return 1
  fi
  if [[ -n "$pr_json" && "$pr_json" != "[]" ]]; then
    echo "pr-exists"
    return 2
  fi

  gate_set_field "$GATE_FILE" delegated false || return $?
  gate_set_field "$GATE_FILE" delegation_claimed false || return $?
  gate_set_field "$GATE_FILE" delegation_target "" || return $?
  gate_set_field "$GATE_FILE" delegation_agent_type "" || return $?
  gate_set_field "$GATE_FILE" delegated_at "" || return $?
  if ! slack_post_and_record "$GATE_FILE" "reclaimed" "$GATE_TAG" "gate" "Auto-reclaimed after ${age}s with no commit, no PR, and task status still open — available for claim-gate-delegation.sh again."; then
    echo "reclaimed the gate, but the Slack post about it failed — tell James directly" >&2
  fi
  echo "reclaimed"
}

with_gate_lock "$GATE_FILE" _reclaim_locked
