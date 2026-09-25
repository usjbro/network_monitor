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
# webhook URL. Falls back to an already-exported SLACK_WEBHOOK_URL if no
# file exists.
if [[ -f "$REPO_ROOT/coordination/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$REPO_ROOT/coordination/.env"
  set +a
fi
