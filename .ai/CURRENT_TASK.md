# Current Task

JAM-17 — Follow Stream implementation plan only.

James approved JAM-17's plan then JAM-261's WHOIS test investigation directly in chat on 2026-11-05 ("yes"). Gate `jam-17__follow-stream-plan` is approved and claimed for this session. Base: main e78fd32. Worktree `.worktrees/follow-stream-plan`; branch matches Linear: `jamesmbrownjr/jam-17-follow-stream-read-a-conversation-as-reassembled-text`.

Deliver `docs/superpowers/plans/2026-11-05-follow-stream.md` in its own PR against the merged revision 7 spec. Verify current source before choosing interfaces; settle PR sequence, acceptance tests, RELAY_PORT setup/mismatch semantics, fuzz CI, safe rendering, and off-by-default rollout. Claude reviews against `docs/security-plan-review-checklist.md`. No feature code; implementation requires James's plan approval. Continue Slack monitoring. After the plan PR is up, investigate JAM-261 in its own worktree. Preserve original dirty JAM-258 and PR291 test worktrees.
