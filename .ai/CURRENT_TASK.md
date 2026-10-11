# Current Task

JAM-165 / JAM-192: distinguish unsupported non-IP Ethernet traffic from genuine parse failures. James approved implementation on 2026-10-10 and publication (commit/push/PR for Claude review) directly in chat on 2026-10-11. Merge is not authorized.

Worktree: `.worktrees/unparsed-frames-non-ip-and-counter`; branch: `jamesmbrownjr/jam-165-unparsed-frames-non-ip-and-counter`.

Implementation and Claude plan-review follow-ups are complete. The Option parser wraps the classified API; unsupported non-IP traffic is excluded from decode-failure counts/findings without changing wire fields. Docs explicitly record the absence of dedicated non-IP visibility. Decoder limits, malformed ARP sizes, and opaque MACsec remain failures. Cleartext MACsec follows its decoded inner protocol.

Final verification: 482 Rust tests (11 ignored), authenticated replay, 602 web tests, strict Clippy, lint, typecheck, Rust/web builds, Chromium smoke, Rust/npm audit gates, and 867,936 fuzz runs pass. Independent code/security re-review is clear. Publication is authorized; handoff remains In Review pending Claude's review of the actual PR. See TEST_STATUS and HANDOFF.

Original live capture is unavailable. Fixture evidence does not establish its failure distribution or reassembly root cause; the counter increments before reassembly sniffing. Previous task was merged in PR #280 (`28e19db`).
