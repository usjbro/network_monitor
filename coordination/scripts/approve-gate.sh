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
