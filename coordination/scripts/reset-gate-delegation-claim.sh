#!/usr/bin/env bash
# Resets an incomplete delegation claim only after an operator confirms no
# delegated work is active. Never resets a completed delegation.
#
# Usage:
#   ./reset-gate-delegation-claim.sh <linear-id> <slug> --confirm-no-active-delegation

set -euo pipefail

LINEAR_ID="${1:?usage: reset-gate-delegation-claim.sh <linear-id> <slug> --confirm-no-active-delegation}"
SLUG="${2:?usage: reset-gate-delegation-claim.sh <linear-id> <slug> --confirm-no-active-delegation}"
CONFIRM="${3:-}"

if [[ "$CONFIRM" != "--confirm-no-active-delegation" || $# -ne 3 ]]; then
  echo "refusing to reset a claim without --confirm-no-active-delegation" >&2
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

_reset_locked() {
  gate_require_status "$GATE_FILE" approved || return $?
  local delegated claimed
  delegated="$(gate_field "$GATE_FILE" delegated)"
  claimed="$(gate_field "$GATE_FILE" delegation_claimed)"
  if [[ "$delegated" == "true" ]]; then
    echo "cannot reset a completed delegation" >&2
    return 2
  fi
  if [[ "$claimed" != "true" ]]; then
    echo "there is no delegation claim to reset" >&2
    return 2
  fi
  gate_set_field "$GATE_FILE" delegation_target "" || return $?
  gate_set_field "$GATE_FILE" delegation_agent_type "" || return $?
  gate_set_field "$GATE_FILE" delegation_claimed false || return $?
  echo "delegation-claim-reset"
}

with_gate_lock "$GATE_FILE" _reset_locked
