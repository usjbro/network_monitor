# Linear JAM → Jira KAN migration

`jam-to-kan.tsv` maps every Linear issue `JAM-n` to the Jira issue `KAN-m` it became. Use it to resolve the `JAM-n` ids in commits, PR titles, ADRs, specs and plans. Linear itself stays as a read-only archive.

The migration fills in the ledger, one row per issue as each is created. The procedure, the field mapping and James's decisions are in `docs/superpowers/plans/2026-11-10-linear-to-jira-migration.md` and ADR-007 in `.ai/DECISIONS.md`. Until every Linear issue has a row, the migration isn't finished.

Columns:

| Column | Meaning |
|---|---|
| `jam_id` | The Linear issue, for example `JAM-21`. |
| `kan_key` | The Jira issue it became, for example `KAN-40`. |
| `kind` | `epic`, `task` or `subtask`. |
| `parent_kan` | The Jira parent's key, if any. |
| `status_set`, `links_set`, `comments_set` | `1` once that step is done, so an interrupted run can resume. |

Every migrated issue also carries the Jira label `linear-jam-<n>`, so `labels = "linear-jam-21"` finds JAM-21's issue even without this file.

The raw Linear export goes in `export/`, which is git-ignored.

## Run record (2026-11-10)

All 275 Linear issues (JAM-1 to JAM-275) have a row. KAN holds 32 Epics, 231 Tasks and 12 Subtasks, with 591 links: 459 Relates, 108 Blocks and 24 Duplicate. Checked against live Jira and Linear on 2026-11-10:

- KAN has 275 issues. Each one has exactly one `linear-jam-<n>` label and one ledger row, and no JAM or KAN id repeats.
- Every Jira status matches its `linear-status-*` label: 147 To Do, 4 In Progress, 124 Done.
- Label counts match the export: 202 `linear-priority-none`, 24 `roadmap`, 24 `duplicate`.
- For every issue:
  - its type and parent match this file;
  - its ticked and unticked checkbox counts match Linear;
  - it has a "Linear history" comment exactly when Linear had comments;
  - no signed `uploads.linear.app` URL was copied.
- Links were spot-checked on KAN-109, KAN-111, KAN-170 and KAN-278. Each link call returned success and is recorded once.

Linear changes made after this run are not included. They are synced at cutover.
