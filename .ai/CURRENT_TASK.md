# Current Task

JAM-250: add CI job timeouts, bounded apt-get retries, and an infrastructure failure policy.

Worktree: `.worktrees/ci-job-timeouts-apt-retry`; branch: `jamesmbrownjr/jam-250-p3-ci-add-job-timeouts-and-an-apt-get-retry-so-a-hung-runner`.

Current phase: Implementation and the temporary unreachable-mirror acceptance check are complete. The probe logged all three failed attempts and exited in about 24 seconds; the test-only change is now reverted. Final PR state contains only job timeouts, bounded apt retries, and the main-branch infrastructure failure policy. The probe run is expectedly red; a fresh CI run on the restored PR head must pass before merge. Historical cancelled main run 37677784244 remains out of scope because current main is green.
