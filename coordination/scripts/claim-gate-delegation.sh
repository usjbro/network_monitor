#!/usr/bin/env bash
# Atomically claims an approved gate for delegation. Only the session whose
# claim succeeds may launch the delegated work. A stranded claim must be
# inspected and explicitly reset before retrying (see reset-gate-delegation-claim.sh).
#
# Usage:
#   ./claim-gate-delegation.sh <linear-id> <slug>

set -euo pipefail

LINEAR_ID="${1:?usage: claim-gate-delegation.sh <linear-id> <slug>}"
SLUG="${2:?usage: claim-gate-delegation.sh <linear-id> <slug>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$LINEAR_ID" "$SLUG")"
if [[ ! -f "$GATE_FILE" ]]; then
  echo "no such gate: $GATE_FILE" >&2
  exit 1
fi

_claim_locked() {
  gate_require_status "$GATE_FILE" approved || return $?
  local delegated claimed
  delegated="$(gate_field "$GATE_FILE" delegated)"
  claimed="$(gate_field "$GATE_FILE" delegation_claimed)"
  if [[ "$delegated" == "true" ]]; then
    echo "delegated"
    return 2
  fi
  if [[ "$claimed" == "true" ]]; then
    echo "delegation-claimed"
    return 2
  fi
  gate_set_field "$GATE_FILE" delegation_claimed true || return $?
  echo "delegation-claimed"
}

with_gate_lock "$GATE_FILE" _claim_locked
