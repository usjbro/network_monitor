#!/bin/bash
# PostToolUse hook: after a `gh pr create` Bash call, remind Claude to run
# this repo's /security-review and /code-review skills against the new PR.
#
# Claude Code hooks can't invoke slash commands directly -- only inject text
# Claude then chooses to act on (see hooks docs). This hook filters on the
# actual command string from stdin rather than relying on a matcher-level
# `if` filter, so it works regardless of that syntax's availability.
set -euo pipefail

input="$(cat)"
command="$(echo "$input" | jq -r '.tool_input.command // empty')"

if echo "$command" | grep -Eq '(^|[[:space:]&|;])gh[[:space:]]+pr[[:space:]]+create([[:space:]]|$)'; then
  cat <<'JSON'
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": "A GitHub PR was just created via `gh pr create`. Per this repo's convention, run /security-review and /code-review against it before considering the PR ready, and report the results to the user."
  }
}
JSON
fi

exit 0
