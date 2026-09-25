#!/usr/bin/env bash
# Removes a stale or ownerless gate lock after explicit confirmation that no
# gate operation is currently active. A recorded live owner is never removed.
#
# Usage:
#   ./recover-gate-lock.sh <linear-id> <slug> --confirm-no-live-operation

set -euo pipefail

LINEAR_ID="${1:?usage: recover-gate-lock.sh <linear-id> <slug> --confirm-no-live-operation}"
SLUG="${2:?usage: recover-gate-lock.sh <linear-id> <slug> --confirm-no-live-operation}"
CONFIRM="${3:-}"

if [[ "$CONFIRM" != "--confirm-no-live-operation" || $# -ne 3 ]]; then
  echo "refusing to remove a lock without --confirm-no-live-operation" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

GATE_FILE="$(gate_path "$LINEAR_ID" "$SLUG")"
LOCK_DIR="${GATE_FILE}.lock"
if [[ -L "$LOCK_DIR" || ! -d "$LOCK_DIR" ]]; then
  echo "no recoverable lock directory: $LOCK_DIR" >&2
  exit 1
fi

OWNER_FILE="$LOCK_DIR/pid"
START_FILE="$LOCK_DIR/start"
if [[ -e "$OWNER_FILE" ]]; then
  OWNER_PID="$(cat "$OWNER_FILE")"
  if [[ ! "$OWNER_PID" =~ ^[1-9][0-9]*$ ]]; then
    echo "invalid lock owner PID in $OWNER_FILE; inspect manually" >&2
    exit 1
  fi
  if kill -0 "$OWNER_PID" 2>/dev/null; then
    RECORDED_START="$(cat "$START_FILE" 2>/dev/null || true)"
    CURRENT_START="$(LC_ALL=C ps -p "$OWNER_PID" -o lstart= 2>/dev/null || true)"
    if [[ -z "$RECORDED_START" || -z "$CURRENT_START" || "$RECORDED_START" == "$CURRENT_START" ]]; then
      echo "lock owner PID $OWNER_PID may still be running; refusing recovery" >&2
      exit 1
    fi
  fi
fi

# The owner may have died between removing pid and removing start during
# normal cleanup. Confirmation also covers that ownerless state.
rm -f "$OWNER_FILE" "$START_FILE"

if ! rmdir "$LOCK_DIR"; then
  echo "lock directory is not empty; inspect it manually: $LOCK_DIR" >&2
  exit 1
fi

echo "Recovered stale gate lock: $LOCK_DIR"
