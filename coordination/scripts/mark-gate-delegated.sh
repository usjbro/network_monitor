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
