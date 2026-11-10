#!/usr/bin/env bash
# Atomically flips a gate from "awaiting-approval" to "approved". Exits 0
# and prints "approved" if this call performed the transition; exits 2 and
# prints the gate's current status if someone else already approved or
# blocked it first. Callers use that distinction to avoid double-delegating
# (see docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md,
# Error Handling: "Both channels reply close together").
#
# Usage:
#   ./approve-gate.sh <issue-key> <slug>

set -euo pipefail

ISSUE_KEY="${1:?usage: approve-gate.sh <issue-key> <slug>}"
SLUG="${2:?usage: approve-gate.sh <issue-key> <slug>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$ISSUE_KEY" "$SLUG")"

if [[ ! -f "$GATE_FILE" ]]; then
  echo "no such gate: $GATE_FILE" >&2
  exit 1
fi

_approve_locked() {
  gate_require_status "$GATE_FILE" awaiting-approval || return $?
  gate_set_field "$GATE_FILE" status approved || return $?
  echo "approved"
}

with_gate_lock "$GATE_FILE" _approve_locked
