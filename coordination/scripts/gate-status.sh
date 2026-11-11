#!/usr/bin/env bash
# Prints a gate's status: "status=<awaiting-approval|approved|blocked>
# delegated=<true|false>". Read-only — used by both an interactive session
# (before acting on an in-chat approval) and the watcher (before acting on
# a Slack reply) to avoid double-delegating.
#
# Usage:
#   ./gate-status.sh <issue-key> <slug>

set -euo pipefail

ISSUE_KEY="${1:?usage: gate-status.sh <issue-key> <slug>}"
SLUG="${2:?usage: gate-status.sh <issue-key> <slug>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$ISSUE_KEY" "$SLUG")"

if [[ ! -f "$GATE_FILE" ]]; then
  echo "no such gate: $GATE_FILE" >&2
  exit 1
fi

STATUS="$(gate_field "$GATE_FILE" status)"
DELEGATED="$(gate_field "$GATE_FILE" delegated)"
DELEGATION_CLAIMED="$(gate_field "$GATE_FILE" delegation_claimed)"
[[ -n "$DELEGATION_CLAIMED" ]] || DELEGATION_CLAIMED=false
echo "status=${STATUS} delegated=${DELEGATED} delegation_claimed=${DELEGATION_CLAIMED}"
