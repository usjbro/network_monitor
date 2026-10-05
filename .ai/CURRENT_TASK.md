# Current Task

JAM-184: authenticate the capture-agent control socket with a per-launch token. James invoked epic-task-cycle JAM-184 directly in chat on 2026-10-05, authorizing the queued scope and publication cycle.

Worktree: `.worktrees/capture-agent-control-token`; branch `jamesmbrownjr/jam-184-authenticate-the-capture-agent-control-socket-with-a-per`.

Stage: revised architectural security design approved by James directly in chat on 2026-10-05, including BOTH feed and controls. Implementation plan written and self-reviewed; awaiting James's plan review and execution-method selection under writing-plans. Existing gate approved and claimed for in-session work. No product-code edits yet.

Scope: generated token, secure local handoff, bounded handshake before feed/control access, coordinated Rust/TypeScript contract and documentation, relay reconnect behavior and live rejection tests. Keep loopback bind, TLS opt-in and dependencies unchanged. JAM-194 is merged as7cfc09d; its replay-recording review finding is separate, not part of this task.
