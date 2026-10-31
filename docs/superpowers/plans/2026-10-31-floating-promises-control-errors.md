# JAM-258 implementation plan

**Goal:** Report failed control requests without unhandled rejections or false UI success.

**Authorization:** James explicitly approved “Take over JAM-258 here” in this live chat. The original Mac checkout is inaccessible and unchanged; this checkout has its own approved/claimed gate. James subsequently authorized commit, push and PR publication in this chat. Do not merge this branch or write through the Slack connector.

**Requirements:** The complete assignment is in Slack `C0C39FJT9DX`, parent `1791918226.577999`, reply `1791918300.849799`. Use existing UI error-banner patterns. No wire, agent, API-route, dependency, network-bind or deployment changes. JAM-261 remains separate. Preserve the repeated enrichment disclosure banner and immediate PID registration.

## 1. UI control failures

Files: `app/page.tsx`, new `lib/__tests__/page-control-errors.test.tsx`.

- [x] Write tests through real command-bar/UI actions for rejected fetches and non-OK responses for pause/resume, enrichment, and GeoIP.
- [x] Assert visible fixed error messages (HTTP status allowed; response body and exception details forbidden), dismissal/retry, unchanged enrichment mode/bookkeeping on failure, and disclosure on every successful enable.
- [x] Run tests against baseline and record the expected failures before implementation.
- [x] Implement a shared dismissible control-error state consistent with existing per-feature banners. Catch errors inside handlers; mark intentional async calls explicitly where needed.
- [x] Run focused and related page tests. Preserve existing successful behavior.

## 2. Clipboard confirmation

Files: `components/InstallModal.tsx`, `lib/__tests__/install-modal.test.tsx`.

- [x] Test deferred resolution and rejection: rendered copied confirmation appears only after successful write, with no unhandled rejection.
- [x] Observe baseline failure, then await/catch clipboard writes before setting success.
- [x] Run modal tests.

## 3. Intentional background promises

Files: `bin/osi-inspect.js`, `lib/enrichment/request-queue.ts`, `lib/stream-response.ts`.

- [x] Inspect complete error paths for `sendControlMessage`, queue `drain`, and GeoIP lookup.
- [x] Add `void` and a truthful brief comment where failures are already handled. If a promise can reject, add a fixed logging catch with a behavioral regression first. Preserve ordering.
- [x] Run existing relevant CLI, queue and stream tests.

## 4. Verification and handoff

- [x] Full web649 tests, typecheck, lint, production build.
- [ ] Real-agent browser verification: attempted and blocked by occupied fixed port9990; no browser pass claimed.
- [x] Independent diff review and corrections.
- [x] Update `.ai/CURRENT_TASK.md`, `.ai/HANDOFF.md`, `.ai/TEST_STATUS.md` with actual evidence and outstanding limitations. Leave changes uncommitted.

## Environment notes

- Base `origin/main`: `f4239b6`. Worktree `/workspace/network_monitor/.worktrees/floating-promises-control-errors`; script-created branch `jamesmbrownjr/jam-258-floating-promises-control-errors`.
- Linear repeatedly requests authentication after accepting it. Do not claim a live status or generated branch was verified.
- No Slack bot/webhook is configured; repository guidance requires status in live chat instead of connector writes.
- Initial npm setup failed because `/home/agent/.npm` is not writable. Parent owns dependency setup and will retry with `/workspace/.npm-cache`. Do not independently reinstall or change dependencies.
