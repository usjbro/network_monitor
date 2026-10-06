# Current Task

JAM-199: fix the new sharp advisory that makes the npm audit gate fail and restore CI for open PRs.

Worktree: `.worktrees/npm-audit-sharp`; branch: `jamesmbrownjr/jam-199-p1-ci-npm-audit-gate-fails-on-sharp-ghsa-wq5f-xc86-pv6w-new`.

Scope: update the vulnerable lockfile resolution for Next's optional `sharp` dependency to a patched version. Verify dependency ownership, npm audit and the repository's audit gate, lint, build, and Vitest. Record a decision on whether new advisories should receive a short grace period. Keep app/runtime code and unrelated dependencies unchanged.

Gate approved and delegated in-session on 2026-10-06. JAM-199 is a P1 blocker for JAM-167 PR #271's Web check.
