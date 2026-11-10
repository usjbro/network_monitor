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
