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

# The directory lib.sh itself lives in — always the same coordination/scripts/
# as its sibling scripts (slack-notify.sh, create-gate.sh, ...) in whichever
# checkout is currently running, unlike REPO_ROOT (always the MAIN checkout,
# even from a worktree). A helper that invokes a sibling script must use
# this, not REPO_ROOT, or it would silently run the main checkout's
# possibly-stale copy instead of the currently-running branch's own.
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load locally-configured Slack credentials if present. coordination/.env
# is gitignored (matches the repo-wide .env* pattern) — never commit it.
# Applied per variable, not as an all-or-nothing block: a caller that has
# already set one of these three (even to "", e.g. a test disabling just
# one credential) keeps that exact value, while any of the other two still
# load normally from the file. An earlier version gated the whole file on a
# single combined check, which had two failure modes an independent review
# on PR #234 found: (1) explicitly exporting only SLACK_BOT_TOKEN didn't
# stop coordination/.env from being sourced anyway and silently overwriting
# it with the file's own value, and (2) explicitly exporting only
# SLACK_WEBHOOK_URL suppressed the file entirely, so a bot token/channel
# configured there was ignored even though nothing asked for that.
if [[ -f "$REPO_ROOT/coordination/.env" ]]; then
  for _slack_var in SLACK_WEBHOOK_URL SLACK_BOT_TOKEN SLACK_CHANNEL_ID; do
    if [[ -z "$(eval "echo \"\${${_slack_var}+x}\"")" ]]; then
      _slack_val="$(grep -m1 "^${_slack_var}=" "$REPO_ROOT/coordination/.env" | cut -d= -f2-)"
      [[ -n "$_slack_val" ]] && export "${_slack_var}=${_slack_val}"
    fi
  done
  unset _slack_var _slack_val
fi

# True if slack-notify.sh has any way to post — the preferred bot-token path
# (SLACK_BOT_TOKEN, can originate or reply to a thread) or the webhook
# fallback (SLACK_WEBHOOK_URL, can only reply to a thread whose ts is
# already known). Callers that gate on "is Slack configured at all" (e.g.
# create-gate.sh refusing an autonomous gate) should use this instead of
# checking SLACK_WEBHOOK_URL directly, so a bot-token-only setup still works.
slack_configured() {
  [[ -n "${SLACK_BOT_TOKEN:-}" || -n "${SLACK_WEBHOOK_URL:-}" ]]
}

# Reads a task contract's or gate's own recorded slack_ts (if any), so a
# later post about the same task/gate can thread under its parent instead of
# starting a new top-level post. Silent (prints nothing) if the file or
# field doesn't exist yet — callers treat an empty result as "post
# top-level."
lookup_slack_ts() {
  local file="$1"
  if [[ -f "$file" ]]; then
    gate_field "$file" slack_ts
  fi
  return 0
}

# Shared by new-task.sh, create-gate.sh, and complete-task.sh: posts a Slack
# status update via slack-notify.sh and, only if FILE doesn't already have a
# slack_ts, records the post's own ts into FILE's slack_ts field. Never
# overwrites an existing slack_ts — Slack's own API docs warn against using
# a reply's ts as a later thread_ts (only the root message's ts is safe to
# thread under), so once a task/gate's root post is recorded, a later
# post's ts (itself a reply, once slack_ts is set) must never replace it.
# Returns slack-notify.sh's own exit status, so callers keep their own
# success/failure policy (e.g. create-gate.sh's autonomous-mode rollback).
slack_post_and_record() {
  local file="$1" status="$2" task_slug="$3" owner="$4" message="$5"
  local ts existing
  if ! ts="$("$LIB_DIR/slack-notify.sh" "$status" "$task_slug" "$owner" "$message")"; then
    return 1
  fi
  if [[ -n "$ts" ]]; then
    existing="$(lookup_slack_ts "$file")"
    if [[ -z "$existing" ]]; then
      gate_set_field "$file" slack_ts "$ts"
    fi
  fi
  return 0
}

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
# convention (see new-task.sh's LINEAR_ID_LOWER). The double underscore is
# unambiguous because neither validated component can contain an underscore.
gate_path() {
  local linear_id_lower slug="$2"
  linear_id_lower="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  validate_slug "$linear_id_lower" "linear-id"
  validate_slug "$slug" "slug"
  echo "$REPO_ROOT/coordination/gates/${linear_id_lower}__${slug}.md"
}

# Reads a single field's value from a gate file's YAML frontmatter block
# only — the region between the first two "---" lines — never from the
# free-text Plan/Blocked body below it. A naive `grep '^field:' | cut`
# over the whole file gets confused if the body happens to contain a line
# starting with a reserved key (e.g. a plan summary or block reason
# describing this very gate mechanism, which can legitimately include a
# line like "status: awaiting-approval" as illustrative text).
gate_field() {
  local gate_file="$1" field="$2"
  awk -v field="$field" '
    /^---$/ { delim++; next }
    delim == 1 && index($0, field ":") == 1 {
      sub("^" field ":[ ]*", "")
      print
      exit
    }
  ' "$gate_file"
}

# Rewrites a single frontmatter field's value in place, scoped to the same
# block gate_field reads from, so a look-alike line in the body can never
# be mistaken for (or corrupted as) a structured field. VALUE must not
# contain a newline. Preserves gate_file's existing permission mode —
# mktemp defaults to 0600, which would otherwise silently downgrade it
# from the 0644 create-gate.sh's plain `cat >` write leaves it at.
gate_set_field() {
  local gate_file="$1" field="$2" value="$3"
  local tmp mode
  tmp="$(mktemp "${gate_file}.XXXXXX")"
  mode="$(stat -f '%Lp' "$gate_file" 2>/dev/null || stat -c '%a' "$gate_file" 2>/dev/null || true)"
  if ! awk -v field="$field" -v value="$value" '
    BEGIN { delim = 0; found = 0 }
    /^---$/ {
      delim++
      if (delim == 2 && !found) { print field ": " value; found = 1 }
      print
      next
    }
    delim == 1 && index($0, field ":") == 1 { print field ": " value; found = 1; next }
    { print }
    END { if (delim < 2) exit 1 }
  ' "$gate_file" > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if [[ -n "$mode" ]] && ! chmod "$mode" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if ! mv "$tmp" "$gate_file"; then
    rm -f "$tmp"
    return 1
  fi
}

# Reads a gate's current status and, unless it equals required_status,
# prints the current status and returns 2 without changing anything.
# Shared by every gate-mutating script's locked transition so a new
# mutator can't be added to the state machine without this precondition —
# the gap that previously let mark-gate-delegated.sh mark a still-pending
# or blocked gate as delegated with no check.
gate_require_status() {
  local gate_file="$1" required_status="$2"
  local current
  current="$(gate_field "$gate_file" status)"
  if [[ "$current" != "$required_status" ]]; then
    echo "$current"
    return 2
  fi
}

# Runs "$@" while holding an exclusive, atomic lock on gate_file. Uses
# mkdir as the lock primitive rather than flock, which isn't reliably
# available on macOS. The owner PID lets recover-gate-lock.sh distinguish
# a live operation from a stale lock after SIGKILL or a machine interruption.
with_gate_lock() {
  local gate_file="$1"; shift
  local lock_dir="${gate_file}.lock"
  local attempts=0
  until mkdir "$lock_dir" 2>/dev/null; do
    attempts=$((attempts + 1))
    if [[ $attempts -ge 20 ]]; then
      echo "could not acquire lock on ${gate_file} after ${attempts} attempts (0.1s each); inspect it with recover-gate-lock.sh" >&2
      return 1
    fi
    sleep 0.1
  done
  if ! printf '%s\n' "$$" > "$lock_dir/pid"; then
    rmdir "$lock_dir" 2>/dev/null || true
    echo "could not record lock owner for ${gate_file}" >&2
    return 1
  fi
  # A PID may later be reused. Record the process start time when ps is
  # available so recovery can distinguish a new process from this owner.
  local owner_start
  owner_start="$(LC_ALL=C ps -p "$$" -o lstart= 2>/dev/null || true)"
  if [[ -n "$owner_start" ]] && ! printf '%s\n' "$owner_start" > "$lock_dir/start"; then
    rm -f "$lock_dir/pid"
    rmdir "$lock_dir" 2>/dev/null || true
    echo "could not record lock owner start time for ${gate_file}" >&2
    return 1
  fi
  local rc=0
  "$@" || rc=$?
  rm -f "$lock_dir/pid" "$lock_dir/start"
  if ! rmdir "$lock_dir"; then
    echo "could not release lock on ${gate_file}; recover it after confirming no operation is active" >&2
    return 1
  fi
  return $rc
}
