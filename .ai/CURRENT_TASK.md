# Current Task

JAM-173: keep fragment-completing packet event fields consistent with the physical frame.

Worktree: `.worktrees/fragment-completing-packet-consistency`; branch: `jamesmbrownjr/jam-173-p2-fragment-completing-packet-event-shows-contradictory`.

Current phase: Root cause confirmed: `packet_osi_layer` trusted L7 info decoded from a reconstructed datagram even when the physical completing IPv4 fragment has protocol `Other` and no ports. The packet event now stays at layer 3 in that case, while TCP/UDP packets can still report layer 7. A two-fragment DNS regression was observed failing with layer 7 before the change and passes after it. Full Rust tests, warnings-denied Clippy, release build, and diff check pass; independent review and CI remain.
