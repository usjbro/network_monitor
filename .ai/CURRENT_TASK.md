# Current Task

JAM-193: render the existing `capture_file_error` SSE event when the capture agent rejects a `start_capture_file` request.

Worktree: `.worktrees/p2-capture_file_error-sse-event-has-no-ui-handler-rejected`; branch: `jamesmbrownjr/jam-193-p2-capture_file_error-sse-event-has-no-ui-handler-rejected`.

Scope: add UI state and a dismissible rejection banner in `app/page.tsx`; add an integration regression in `lib/__tests__/page-command-bar-capture.test.tsx` that submits a capture command, emits the rejection SSE event, and verifies display/dismissal. No agent, wire, mapping, or control-route changes.

Gate approved by James in chat on 2026-10-05. Implementation and local verification are complete; awaiting independent review/publication checks.
