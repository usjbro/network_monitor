# Current Task

JAM-261 — test-only WHOIS reset/lifecycle correction verified locally; publish PR and inspect CI/reviews.

James approved JAM-17 plan then JAM-261 directly in chat on 2026-11-05. Plan PR #295 is now up and under code/security/Claude review. This task's existing approved gate has been claimed and delegated in-session. Worktree `.worktrees/whois-test-econnreset`; branch `jamesmbrownjr/jam-261-whois-client-tests-emit-unhandled-econnreset-on-macos`, base e78fd32.

Use Linear issue acceptance criteria: instrument accepted and client sockets, reproduce before correcting, deterministic regression, unexpected errors still fail, 20 focused passes and both ordinary/single-worker full Vitest pass. Keep timeout/size/refused-connection assertions. Test-fixture scope unless production defect demonstrated. No global suppression. Preserve unrelated worktrees and main changes; monitor Slack. Original report Node 25.4.0/Vitest 5.0.1; current Node 26.12.1/Vitest 5.0.5 on macOS 26.6.2; one fresh full-suite pass does not disprove intermittent failure.

JAM-17 — Follow Stream implementation plan only.

James approved JAM-17's plan then JAM-261's WHOIS test investigation directly in chat on 2026-11-05 ("yes"). Gate `jam-17__follow-stream-plan` is approved and claimed for this session. Base: main e78fd32. Worktree `.worktrees/follow-stream-plan`; branch matches Linear: `jamesmbrownjr/jam-17-follow-stream-read-a-conversation-as-reassembled-text`.

Deliver `docs/superpowers/plans/2026-11-05-follow-stream.md` in its own PR against the merged revision 7 spec. Verify current source before choosing interfaces; settle PR sequence, acceptance tests, RELAY_PORT setup/mismatch semantics, fuzz CI, safe rendering, and off-by-default rollout. Claude reviews against `docs/security-plan-review-checklist.md`. No feature code; implementation requires James's plan approval. Continue Slack monitoring. After the plan PR is up, investigate JAM-261 in its own worktree. Preserve original dirty JAM-258 and PR291 test worktrees.
