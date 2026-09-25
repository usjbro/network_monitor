#!/usr/bin/env bash
# Lists every gate currently awaiting approval, one per line, as
# "<linear_id> <slug> <posted_at>" — used by the watcher on each scheduled
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
  status="$(grep '^status:' "$gate_file" | cut -d' ' -f2)"
  if [[ "$status" == "awaiting-approval" ]]; then
    linear_id="$(grep '^linear_id:' "$gate_file" | cut -d' ' -f2)"
    slug="$(grep '^slug:' "$gate_file" | cut -d' ' -f2)"
    posted_at="$(grep '^posted_at:' "$gate_file" | cut -d' ' -f2)"
    echo "${linear_id} ${slug} ${posted_at}"
  fi
done
