# Current Task

JAM-261 — test-only WHOIS reset/lifecycle correction verified locally; publish PR and inspect CI/reviews.

James approved JAM-17 plan then JAM-261 directly in chat on 2026-11-05. Plan PR #295 is now up and under code/security/Claude review. This task's existing approved gate has been claimed and delegated in-session. Worktree `.worktrees/whois-test-econnreset`; branch `jamesmbrownjr/jam-261-whois-client-tests-emit-unhandled-econnreset-on-macos`, base e78fd32.

Use Linear issue acceptance criteria: instrument accepted and client sockets, reproduce before correcting, deterministic regression, unexpected errors still fail, 20 focused passes and both ordinary/single-worker full Vitest pass. Keep timeout/size/refused-connection assertions. Test-fixture scope unless production defect demonstrated. No global suppression. Preserve unrelated worktrees and main changes; monitor Slack. Original report Node 25.4.0/Vitest 5.0.1; current Node 26.12.1/Vitest 5.0.5 on macOS 26.6.2; one fresh full-suite pass does not disprove intermittent failure.
