# Current Task

JAM-193: render the existing `capture_file_error` SSE event when the capture agent rejects a `start_capture_file` request.

Worktree: `.worktrees/p2-capture_file_error-sse-event-has-no-ui-handler-rejected`; branch: `jamesmbrownjr/jam-193-p2-capture_file_error-sse-event-has-no-ui-handler-rejected`.

Scope: add UI state and a dismissible rejection banner in `app/page.tsx`; add an integration regression in `lib/__tests__/page-command-bar-capture.test.tsx` that submits a capture command, emits the rejection SSE event, and verifies display/dismissal. No agent, wire, mapping, or control-route changes.

Gate approved by James in chat on 2026-10-05. PR #268 is open, rebased onto current main, all CI checks and independent code/security reviews pass. Waiting for James's real-browser check of the rejection banner before merge; the computer-use gate blocked Chrome access for this session.
