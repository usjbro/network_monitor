# Current Task

JAM-250: add CI job timeouts, bounded apt-get retries, and an infrastructure failure policy.

Worktree: `.worktrees/ci-job-timeouts-apt-retry`; branch: `jamesmbrownjr/jam-250-p3-ci-add-job-timeouts-and-an-apt-get-retry-so-a-hung-runner`.

Current phase: Gate approved under James's standing queue instruction, delegation claimed and marked in-session. Issue is In Progress. Inspect all workflow job durations and apt installation sites, then add timeouts/retries and document how main-branch infrastructure failures are handled. The historical cancelled main run is out of scope because current main is green. Validate retry/fail-fast behavior with a temporary unreachable apt mirror change, then revert it before opening the final PR.
