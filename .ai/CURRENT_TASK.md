# Current Task

JAM-165 / JAM-192: distinguish unsupported non-IP Ethernet traffic from genuine parse failures. James approved implementation on 2026-10-10 and publication (commit/push/PR for Claude review) directly in chat on 2026-10-11. Merge is not authorized.

Worktree: `.worktrees/unparsed-frames-non-ip-and-counter`; branch: `jamesmbrownjr/jam-165-unparsed-frames-non-ip-and-counter`.

Implementation and all Claude review findings are addressed on PR #281 (CI runs the non-IP replay; PBB/E-tag/IP-over-SNAP guards; named EtherType constants). Unsupported non-IP traffic is excluded from decode-failure counts/findings without changing wire fields. See TEST_STATUS and HANDOFF.

Original live capture is unavailable. Fixture evidence does not establish its failure distribution or reassembly root cause; the counter increments before reassembly sniffing. Previous task was merged in PR #280 (`28e19db`).
