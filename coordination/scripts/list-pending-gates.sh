#!/usr/bin/env bash
# Lists every gate currently awaiting approval, one per line, as
# "<issue_key> <slug> <posted_at>" — used by the watcher on each scheduled
# wake to know what to check Slack for.
#
# Usage:
#   ./list-pending-gates.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATES_DIR="$REPO_ROOT/coordination/gates"

if [[ ! -d "$GATES_DIR" ]]; then
  exit 0
fi

for gate_file in "$GATES_DIR"/*.md; do
  [[ -e "$gate_file" ]] || continue
  status="$(gate_field "$gate_file" status)"
  if [[ "$status" == "awaiting-approval" ]]; then
    issue_key="$(gate_field_issue_key "$gate_file")"
    slug="$(gate_field "$gate_file" slug)"
    posted_at="$(gate_field "$gate_file" posted_at)"
    echo "${issue_key} ${slug} ${posted_at}"
  fi
done
