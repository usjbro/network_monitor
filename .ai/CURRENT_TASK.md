# Current Task

JAM-198: update the vulnerable `source-map-js` lockfile entry to a patched release so the npm audit CI gate passes.

Worktree: `.worktrees/npm-audit-source-map-js`; branch: `jamesmbrownjr/jam-198-p1-ci-npm-audit-gate-fails-on-source-map-js-ghsa-68fv-2mgg`.

Scope: prefer the existing semver ranges and update only `package-lock.json` for `source-map-js` 1.2.2 or later. Verify `npm audit` and `.github/scripts/check-npm-audit.mjs`, then run lint, build and Vitest. Avoid an allowlist unless no patched release can be installed.

Gate approved by James directly in chat on 2026-10-06. PR #269 (JAM-170) is blocked by this known advisory on `main`; update it after this fix merges.
