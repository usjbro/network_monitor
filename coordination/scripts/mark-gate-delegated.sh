#!/usr/bin/env bash
# Records that delegation actually ran for an approved gate, so a later
# retry (after a crash between "approved" and "delegated") can tell the
# difference between "not yet delegated" and "already delegated" instead
# of re-approving or silently dropping the task.
#
# Exits 0 having recorded delegation only if the gate's status was
# "approved"; exits 2 and prints the current status (without changing
# anything) otherwise — refuses to record delegation against a gate that
# was never approved, or was blocked/still pending.
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

if [[ -n "$AGENT_TYPE" ]]; then
  validate_slug "$AGENT_TYPE" "agent-type"
fi

_mark_locked() {
  gate_require_status "$GATE_FILE" approved || return $?
  local delegated claimed
  delegated="$(gate_field "$GATE_FILE" delegated)"
  claimed="$(gate_field "$GATE_FILE" delegation_claimed)"
  if [[ "$delegated" == "true" ]]; then
    echo "already-delegated"
    return 2
  fi
  if [[ "$claimed" != "true" ]]; then
    echo "delegation-claim-required"
    return 2
  fi
  gate_set_field "$GATE_FILE" delegated true
  gate_set_field "$GATE_FILE" delegation_target "$TARGET"
  gate_set_field "$GATE_FILE" delegation_agent_type "$AGENT_TYPE"
}

with_gate_lock "$GATE_FILE" _mark_locked
echo "Gate delegated: $GATE_FILE (target=${TARGET}${AGENT_TYPE:+, agent_type=${AGENT_TYPE}})"
