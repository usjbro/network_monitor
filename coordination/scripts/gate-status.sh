#!/usr/bin/env bash
# Prints a gate's status: "status=<awaiting-approval|approved|blocked>
# delegated=<true|false>". Read-only — used by both an interactive session
# (before acting on an in-chat approval) and the watcher (before acting on
# a Slack reply) to avoid double-delegating.
#
# Usage:
#   ./gate-status.sh <linear-id> <slug>

set -euo pipefail

LINEAR_ID="${1:?usage: gate-status.sh <linear-id> <slug>}"
SLUG="${2:?usage: gate-status.sh <linear-id> <slug>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$LINEAR_ID" "$SLUG")"

if [[ ! -f "$GATE_FILE" ]]; then
  echo "no such gate: $GATE_FILE" >&2
  exit 1
fi

STATUS="$(gate_field "$GATE_FILE" status)"
DELEGATED="$(gate_field "$GATE_FILE" delegated)"
echo "status=${STATUS} delegated=${DELEGATED}"
