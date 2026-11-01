# JAM-258 implementation plan

**Goal:** Report failed control requests without unhandled rejections or false success.

**Scope:** The approved assignment is documented in the [JAM-258 task thread](https://app.slack.com/archives/C0C39FJT9DX/p1791918226577999); implementation is [PR #291](https://github.com/usjbro/network_monitor/pull/291). James approved takeover and publication in this chat.

**Constraints:** Keep existing API routes, agent/wire formats, dependencies, network binds and deployment unchanged. Error text must be fixed, with HTTP status when available, never response bodies or exception details. Keep repeated enrichment disclosure and immediate CLI PID registration. JAM-261 is separate. Do not merge this branch.

- [x] Reproduce rejected/non-OK control failures through real page actions; add a shared dismissible error state and clear it on retry.
- [x] Preserve enrichment mode and lookup bookkeeping on failure; retain repeated successful-enable disclosure.
- [x] Await clipboard success; guard stale completions/timers with deferred-write regressions.
- [x] Verify intentional CLI/queue promises; contain unexpected GeoIP lookup rejection with fixed logging.
- [x] Reproduce stale header responses, then serialize pending header toggles with success/failure/retry coverage.
- [x] Assert the existing failed-registration warning in the CLI unreachable-relay test after output closes.
- [x] Run follow-up checks and independently review the delta; record passes and runtime failures in TEST_STATUS.md.
- [ ] Re-run full tests, CLI warning regression and build in a runtime allowing loopback listeners and working child-process output.
- [ ] Exercise the UI with a real capture agent when port9990 is available; retain the disclosed verification limit meanwhile.
- [x] Publish the review correction and record results in TEST_STATUS.md/HANDOFF.md.
