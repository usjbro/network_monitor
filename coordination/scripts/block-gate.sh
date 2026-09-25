#!/usr/bin/env bash
# Marks a gate "blocked" (explicit rejection) and appends why. Does not
# post to Slack itself — the calling agent (which read the rejection)
# already has Slack access and replies in-thread directly; this only
# mutates state.
#
# Usage:
#   ./block-gate.sh <linear-id> <slug> "<reason>"

set -euo pipefail

LINEAR_ID="${1:?usage: block-gate.sh <linear-id> <slug> \"<reason>\"}"
SLUG="${2:?usage: block-gate.sh <linear-id> <slug> \"<reason>\"}"
REASON="${3:?usage: block-gate.sh <linear-id> <slug> \"<reason>\"}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$LINEAR_ID" "$SLUG")"

if [[ ! -f "$GATE_FILE" ]]; then
  echo "no such gate: $GATE_FILE" >&2
  exit 1
fi

_block_locked() {
  sed -i.bak "s/^status: .*/status: blocked/" "$GATE_FILE"
  rm -f "${GATE_FILE}.bak"
  {
    echo
    echo "## Blocked"
    echo
    echo "$REASON"
  } >> "$GATE_FILE"
}

with_gate_lock "$GATE_FILE" _block_locked
echo "Gate blocked: $GATE_FILE"
