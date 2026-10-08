# Current Task

JAM-173 follow-up: make the two-fragment regression exercise the actual packet event builder.

Worktree: `.worktrees/fragment-packet-event-builder-test`; branch: `jamesmbrownjr/jam-173-fragment-packet-event-builder-test`.

PR #279 merged as `00ef54f`. The follow-up extracts `PacketJson` construction into `build_packet_json` and changes the two-fragment DNS regression to assert the returned event fields and confirm reconstructed DNS fields are omitted. The focused test passed after the change; full Rust tests, Clippy, release build, PR, and CI are pending.
