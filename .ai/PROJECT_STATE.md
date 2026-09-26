# Network Monitor Project State

## Last Verified

2026-09-26 UTC. GitHub merge/check state, the merged coordination implementation and tests, and Linear JAM-155 were inspected. This is a scoped coordination update, not a project-wide completeness audit.

## Recent Landed Work

| PR | Verified outcome |
| --- | --- |
| #218 | Field model merged as `8ded0cac`. |
| #219 | Display filters merged as `96afc18d`. |
| #220 / #222 | Coordination scripts and shared guidance/state merged as `1f186679` / `85577046`. |
| #223 | Critical-invariants guidance merged as `b4bdc558`. |
| #224 | Shared agent coordination guidance merged as `eb37a25b`; JAM-155 is Done. |
| #225 | Slack approval gate merged as `e42aeaf7` at 2026-09-26 00:16:31 UTC. |

Evidence: GitHub merged-PR metadata and [PR #225](https://github.com/usjbro/network_monitor/pull/225). Merge status establishes integration, not feature completeness beyond the inspected implementation/tests.

## Current Work

The approved five-file `.ai/` documentation refresh is on a fresh branch from `e42aeaf7`. PR #225 has no dedicated Linear issue identified; JAM-155 is only the related, completed PR #224 issue. No next epic/task has been selected in this session.

## Verified Coordination Behavior

Local, gitignored gate state uses validated `<linear-id>__<slug>` filenames. Approval and delegation are separate transitions; an atomic claim prevents duplicate dispatch, and incomplete claims require human-confirmed recovery. Lock metadata records owner PID/start time when available; explicit recovery refuses matching live owners. Shell tests cover creation, parsing, transitions, races, and recovery (65 passing assertions).

There is no background/cloud approval resolver. A live session may poll, and a later live session with the same persistent checkout may manually pick up a gate. Historical spec diagrams/prose should be read alongside the current scripts and `coordination/watcher-prompt.md`.

## Architecture Orientation

`capture-agent/` (Rust) → `lib/agent-client.ts` relay → Next.js SSE/control routes → `app/page.tsx` and `components/`. Source/test files exist for capture, field mapping, ownership enrichment, traceroute/GeoIP, TLS visibility, and capture files. These application subsystems were not re-audited by this documentation task.

## Known Limits / Source Disagreements

- Broader project phase, roadmap completeness, and active epic statuses were not queried. Do not infer them from JAM-155 being Done.
- Historical `CONTRIBUTING.md` GitHub-tracker wording differs from the Linear workflow in `.agents/skills/epic-task-cycle/SKILL.md`; resolve per task against current tracker evidence.
- The prior September 24 source audit flagged stale host-metrics descriptions in `README.md` and `docs/architecture.md`. That finding was not re-audited here; current code/tests remain authoritative.
- `AGENTS.md` says `coordination/` is not copied into worktrees, but the tracked scripts/docs are present in this fresh worktree. Runtime gate state and webhook lookup resolve to the main repository root through `lib.sh`.
- Legacy `new-task.sh` path-component validation remains a separate follow-up; approval-gate validation does not fix that call site.

See `TEST_STATUS.md` for the precise scope of current local testing and historical CI evidence.
