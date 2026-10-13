# Current Task

JAM-257 — CI supply-chain hardening. James directly instructed claim/start in chat on 2026-10-13; existing approved gate claimed/delegated to Codex. Linear In Progress.

Worktree: `.worktrees/ci-pin-actions-and-npx`; branch: `jamesmbrownjr/jam-257-p3-ci-supply-chain-pin-github-actions-to-commit-shas-and-pin` (Linear's exact gitBranchName). Fresh base `c73a0b0dc404c1978af8150d9420d1f9b4a3ae0b`.

Scope: `.github/workflows/*.yml`, optional Dependabot github-actions configuration, task .ai state only. Pin Actions to verified full SHAs with truthful source-version/channel comments; preserve Rust stable/nightly selection via inputs. Replace on-demand CI tooling with locked local executables. Investigate explicit npm ci --ignore-scripts using source/lockfile and fresh install/type/lint/test/build evidence. Preserve every job, timeout, test/audit/live-capture check, application file and dependency version.

Prepared workflow/Dependabot changes pass local static/provenance/YAML-preservation checks, fresh script-disabled install/native smoke, typecheck/lint/build/full602-tests and unchanged audit gate. Independent review completed; generated Rust channel candidates were corrected to verified durable master SHA e2a55d2 after upstream guidance check, and narrow re-review passed. PR #283 is published; final-head CI and reviews plus post-merge Sonar-main checks are pending.

James approved commit, push and PR publication directly in chat on 2026-10-13. Publish the verified result and obtain PR CI/review evidence. Do not merge own branch. Baseline local WHOIS Vitest error is separately JAM-261; do not silently expand scope to fix it.
