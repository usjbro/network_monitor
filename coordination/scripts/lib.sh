#!/usr/bin/env bash
# Shared by new-task.sh, complete-task.sh, slack-notify.sh. Source, don't run.
#
# Resolves REPO_ROOT to the main repo root even when invoked from inside a
# linked worktree (--show-toplevel would return that worktree's own root
# instead, nesting new worktrees under it). --git-common-dir prints an
# absolute path to the main .git when run from a worktree, and a relative
# ".git" when already in the main checkout.
GIT_COMMON_DIR="$(git rev-parse --git-common-dir)"
case "$GIT_COMMON_DIR" in
  /*) REPO_ROOT="$(cd "$(dirname "$GIT_COMMON_DIR")" && pwd)" ;;
  *)  REPO_ROOT="$(git rev-parse --show-toplevel)" ;;
esac

# Load a locally-configured SLACK_WEBHOOK_URL if present. coordination/.env
# is gitignored (matches the repo-wide .env* pattern) — never commit a
# webhook URL. A caller-exported SLACK_WEBHOOK_URL (even if set to empty
# string) takes precedence and suppresses loading from .env — this allows
# tests and callers to override the default webhook or explicitly disable it.
if [[ -f "$REPO_ROOT/coordination/.env" && -z "${SLACK_WEBHOOK_URL+x}" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$REPO_ROOT/coordination/.env"
  set +a
fi

# Validates a value intended for use as a filesystem path component (a task
# or gate slug, or a lower-cased Linear id). Rejects anything empty, or
# containing characters other than lowercase letters, digits, and hyphens —
# in particular this rejects "/" and "..", the exact gap an open review
# finding flagged against new-task.sh's unvalidated TASK_SLUG (PR #220
# review comment, 2026-09-25): a value like "../../outside" let
# WORKTREE_DIR/TASK_FILE escape their intended directories. New path
# components built from user input must run through this first.
validate_slug() {
  local value="$1"
  local label="${2:-value}"
  if [[ -z "$value" || ! "$value" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
    echo "invalid ${label}: '${value}' (must match ^[a-z0-9][a-z0-9-]*\$)" >&2
    exit 1
  fi
}

# Computes the gate file path for a given Linear id + slug, validating both
# first. linear_id is lower-cased to match this repo's existing branch
# convention (see new-task.sh's LINEAR_ID_LOWER).
gate_path() {
  local linear_id_lower slug="$2"
  linear_id_lower="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  validate_slug "$linear_id_lower" "linear-id"
  validate_slug "$slug" "slug"
  echo "$REPO_ROOT/coordination/gates/${linear_id_lower}-${slug}.md"
}

# Runs "$@" while holding an exclusive, atomic lock on gate_file, so the two
# gate observers (a chat session's next turn, and the scheduled watcher)
# can't both act on the same gate transition. Uses mkdir as the lock
# primitive rather than flock, which isn't reliably available on macOS
# (where this repo runs); mkdir's atomicity is POSIX-guaranteed.
with_gate_lock() {
  local gate_file="$1"; shift
  local lock_dir="${gate_file}.lock"
  local attempts=0
  until mkdir "$lock_dir" 2>/dev/null; do
    attempts=$((attempts + 1))
    if [[ $attempts -ge 20 ]]; then
      echo "could not acquire lock on ${gate_file} after ${attempts} attempts (0.1s each)" >&2
      return 1
    fi
    sleep 0.1
  done
  local rc=0
  "$@" || rc=$?
  rmdir "$lock_dir"
  return $rc
}
