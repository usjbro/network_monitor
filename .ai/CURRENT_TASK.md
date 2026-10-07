# Current Task

JAM-167: feed fragment-reassembled TCP through stream reassembly.

Worktree: `.worktrees/feed-fragment-reassembled-tcp`; branch: `jamesmbrownjr/jam-167-p2-feed-fragment-reassembled-tcp-through-stream-reassembly`.

Scope: route reconstructed IPv4 TCP segments into the existing TCP stream reassembly path; add a regression where an HTTP message starts in a fragment-reconstructed TCP segment and completes in a later ordinary segment. Preserve non-fragmented flow/L7 behavior. No wire changes.

Gate approved in Slack under James's standing queue instruction and explicitly authorized in chat on 2026-10-06. Gate claimed and delegated in-session; Linear JAM-167 is In Review. JAM-199 merged as PR #272 at `b4744a8`; PR #271 is being updated to the new base and requires fresh CI.
