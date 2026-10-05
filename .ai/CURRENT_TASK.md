# Current Task

JAM-184: authenticate the capture-agent control socket with a per-launch token. James invoked epic-task-cycle JAM-184 directly in chat on 2026-10-05, authorizing the queued scope and publication cycle.

Worktree: `.worktrees/capture-agent-control-token`; branch `jamesmbrownjr/jam-184-authenticate-the-capture-agent-control-socket-with-a-per`.

Stage: architectural security design, before product-code edits. Existing gate approved and claimed for in-session work. Design spec must be reviewed before the implementation plan/code under brainstorming and CONTRIBUTING.md.

Scope: generated token, secure local handoff, bounded handshake before feed/control access, coordinated Rust/TypeScript contract and documentation, relay reconnect behavior and live rejection tests. Keep loopback bind, TLS opt-in and dependencies unchanged. JAM-194 is merged as7cfc09d; its replay-recording review finding is separate, not part of this task.
