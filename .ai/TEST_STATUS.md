# Test Status

## Last Verified

2026-09-26 UTC, against the merged PR #225 snapshot `e42aeaf742e53a851104fae801d0e73c0761f7e6`. The current follow-up changes documentation only.

## Local Coordination Checks

Exported `coordination/` and `.gitignore` with `git archive HEAD` from the fresh worktree into a temporary directory, then ran `git init -q` there. `SLACK_WEBHOOK_URL` was set to the empty string, preventing the shared webhook configuration from loading. Tests exercised temporary local state, not the main checkout's gates.

| Command | Result |
| --- | --- |
| `bash -n <script>` for every `.sh` under `coordination/scripts/` | PASS |
| `bash coordination/scripts/tests/test-lib.sh` | PASS — 13 assertions |
| `bash coordination/scripts/tests/test-create-gate.sh` | PASS — 18 assertions |
| `bash coordination/scripts/tests/test-gate-transitions.sh` | PASS — 16 assertions |
| `bash coordination/scripts/tests/test-recovery.sh` | PASS — 18 assertions |

All four suites exited 0: 65 passing assertions, no failures. Coverage includes concurrent creation/approval, frontmatter isolation, failed writes, exclusive delegation claims, and confirmed stale-lock recovery.

## Historical PR #225 CI

Verified via `gh pr view 225 --json statusCheckRollup,commits` for final source head `f1e7a393422e4f6f11215ade4dbade9cb6c08da7`:

- [CI run 36197554609](https://github.com/usjbro/network_monitor/actions/runs/36197554609): Web (Next.js), Rust (capture-agent), E2E smoke test, and Fuzz targets jobs all SUCCESS.
- [CodeQL run 36197551011](https://github.com/usjbro/network_monitor/actions/runs/36197551011): actions, JavaScript/TypeScript, and Rust analysis all SUCCESS; the separate CodeQL aggregate check was NEUTRAL, not a failure.
- The fuzz job is path-filtered for pull requests; its successful job status alone does not prove fuzz iterations ran for this tooling change.

These are pre-merge checks of PR #225, not checks of the subsequent documentation commit. This follow-up is published as [PR #227](https://github.com/usjbro/network_monitor/pull/227). At the publication snapshot its own CI is running; consult that PR for checks of its latest commit, rather than treating this historical result as current-head evidence.

## Local Application / Live Integration Tests

TypeScript, Rust, build, Playwright, live packet capture, and a real Slack approval-to-dispatch flow were NOT RUN locally during this documentation-only follow-up. No claim is made about those local results. The GitHub CI evidence above is recorded separately.

## Known Failures / Remaining Validation

No failures in the four gate suites. Independent documentation/security review found no issues, and `git diff --check` passed. The follow-up PR's own CI/merge gates remain part of publication. Historical coordination-kit test notes are preserved at `8557704:.ai/TEST_STATUS.md`.
