#!/usr/bin/env bash
# Create a Slack approval gate for a Linear-tracked task: writes
# coordination/gates/<linear-id>-<slug>.md with status: awaiting-approval
# and posts the plan to the shared Slack channel. See
# docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md.
#
# Usage:
#   ./create-gate.sh <linear-id> <slug> "<plan-summary>" <interactive|autonomous>
#
# mode "interactive": if the Slack post fails or no webhook is configured,
#   the gate is still created (approval can still come from this chat
#   session) — a warning is printed.
# mode "autonomous": the gate can only ever be approved via Slack (there is
#   no chat session to fall back to), so a missing/failed Slack post fails
#   gate creation instead of leaving a task stuck awaiting an approval path
#   that can never arrive.

set -euo pipefail

LINEAR_ID="${1:?usage: create-gate.sh <linear-id> <slug> \"<plan-summary>\" <interactive|autonomous>}"
SLUG="${2:?usage: create-gate.sh <linear-id> <slug> \"<plan-summary>\" <interactive|autonomous>}"
PLAN_SUMMARY="${3:?usage: create-gate.sh <linear-id> <slug> \"<plan-summary>\" <interactive|autonomous>}"
MODE="${4:?usage: create-gate.sh <linear-id> <slug> \"<plan-summary>\" <interactive|autonomous>}"

if [[ "$MODE" != "interactive" && "$MODE" != "autonomous" ]]; then
  echo "mode must be 'interactive' or 'autonomous'" >&2
  exit 1
fi

# Preserve SLACK_WEBHOOK_URL from the environment before lib.sh loads .env;
# this allows tests to override it with an empty value or a test URL.
WEBHOOK_OVERRIDE="${SLACK_WEBHOOK_URL:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

# Restore the environment's SLACK_WEBHOOK_URL if it was explicitly set
if [[ -n "$WEBHOOK_OVERRIDE" ]]; then
  SLACK_WEBHOOK_URL="$WEBHOOK_OVERRIDE"
else
  unset SLACK_WEBHOOK_URL
fi

GATE_FILE="$(gate_path "$LINEAR_ID" "$SLUG")"
LINEAR_ID_LOWER="$(echo "$LINEAR_ID" | tr '[:upper:]' '[:lower:]')"
GATE_TAG="${LINEAR_ID_LOWER}-${SLUG}"

if [[ -f "$GATE_FILE" ]]; then
  echo "Gate already exists: $GATE_FILE" >&2
  exit 1
fi

if [[ -z "${SLACK_WEBHOOK_URL:-}" ]]; then
  if [[ "$MODE" == "autonomous" ]]; then
    echo "SLACK_WEBHOOK_URL not set — an autonomous gate has no other approval path, refusing to create it." >&2
    exit 1
  fi
  echo "Warning: SLACK_WEBHOOK_URL not set — this gate can only be approved in this chat session, not remotely via Slack." >&2
elif ! "$SCRIPT_DIR/slack-notify.sh" "awaiting-approval" "$GATE_TAG" "gate" "$PLAN_SUMMARY"; then
  if [[ "$MODE" == "autonomous" ]]; then
    echo "Slack post failed — an autonomous gate has no other approval path, refusing to create it." >&2
    exit 1
  fi
  echo "Warning: Slack post failed — this gate can only be approved in this chat session, not remotely via Slack." >&2
fi

mkdir -p "$REPO_ROOT/coordination/gates"

cat > "$GATE_FILE" <<EOF
---
linear_id: ${LINEAR_ID}
slug: ${SLUG}
status: awaiting-approval
delegated: false
posted_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
delegation_target:
delegation_agent_type:
---

## Plan

${PLAN_SUMMARY}
EOF

echo "Gate created: $GATE_FILE"
echo "Status: awaiting-approval"
