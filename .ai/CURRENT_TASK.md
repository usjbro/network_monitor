# Current Task

## Objective

JAM-174: detect capture truncation from captured < original packet length for live capture, classic-pcap replay, and pcapng replay. Approved directly by James in this chat on 2026-10-04. Gate `jam-174__replay-capture-truncation` is approved and delegated in-session.

## State

Verified implementation is on `jamesmbrownjr/jam-174-snap-length-truncation-detector-is-dead-during-pcappcapng` in `.worktrees/replay-capture-truncation`. Source lengths propagate through `SourceFrame`; detection runs before parsing and retains the existing once-per-session warning and recent-cut reassembly attribution. Writer/wire behavior is unchanged.

Default Rust suite: 392 passed, 5 ignored; the opt-in binary replay test also passes across eight scenarios. Release build and clippy pass. Two reader fuzz smoke checks pass, including valid EPB seeds with boundary original lengths. Independent review has no remaining findings.

James approved the temporary agent stop on 2026-10-05; the prior agent had already exited, so no process was stopped or restarted. All requested validation is now complete. James invoked `epic-task-cycle JAM-174`, authorizing commit, PR, CI and merge. Linear/GitHub are authoritative for publication state.

Reader compatibility is separately tracked as JAM-194 under JAM-125. See HANDOFF and TEST_STATUS for evidence and continuation.
