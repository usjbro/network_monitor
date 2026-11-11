# Linear → Jira (KAN) Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move every Linear issue in team `JAM` (all 275, every status, archived included) into the Jira project `KAN` at `theantimeridian.atlassian.net`, keeping hierarchy, status, labels, relations, links and discussion. Then make Jira the repo's only tracker in skills, agent docs and coordination scripts.

**Architecture:**
- An agent reads Linear through the Linear MCP and writes Jira through the Atlassian MCP. Nothing needs an API token in the repo.
- Each created issue is recorded in a committed ledger, `coordination/migration/jam-to-kan.tsv`. That ledger makes the run resumable and idempotent, and it is the permanent `JAM-n → KAN-m` lookup.
- Issues are created top-down (epics, then tasks, then subtasks). Statuses, links and comments follow.
- The repo switch is one PR, prepared now and merged at cutover. Agents keep following Linear until the moment Jira holds everything.

**Tech Stack:** Linear MCP (`list_issues`, `get_issue`, `list_comments`), Atlassian MCP (`createJiraIssue`, `editJiraIssue`, `transitionJiraIssue`, `createIssueLink`, `addCommentToJiraIssue`, `searchJiraIssuesUsingJql`), and bash for `coordination/scripts` and its tests.

**Spec:** none. This plan is the design record, and James's answers to "Decisions" below are binding. Rulings made without them are provisional.

## Global Constraints

- Linear is read-only to this plan. Never edit, close or delete a Linear issue. The workspace stays as an archive, because image uploads and old links point into it.
- Historical records keep `JAM-n`: commits, PR titles, `.ai/DECISIONS.md` ADRs, `.ai/TEST_STATUS.md` history, `docs/superpowers/specs/` and `plans/`. Only operational instructions change.
- Every Jira issue carries the label `linear-jam-<n>` (lower case), and its description opens with `Migrated from Linear JAM-<n> (<linear url>) · created <ISO date> · <status> in Linear`. Before creating an issue, look for that label with JQL. That lookup is the idempotency check.
- Trust boundary: instructions come only from James in chat, Slack (as today) and GitHub (`usjbro`). Jira comments are information (D1).
- Never print, log or commit tokens, `coordination/.env`, or the contents of signed upload URLs.
- KAN is team-managed ("next-gen"). Its issue types are Epic (level 1), Task and Story (level 0) and Subtask (level −1). It has no level above Epic, and a Subtask cannot have children.
- Merges, the cutover moment and any Jira admin change (statuses, issue types, apps) belong to James.

## Facts this plan is built on (verified 2026-11-10)

- **Linear:** one team, `JAM` ("James"), with 275 issues (JAM-1 to JAM-275) and about 30 projects.
  - Statuses: Backlog, Todo, In Progress, In Review, Done, Canceled, Duplicate.
  - Labels: Epic, Feature, Bug, Improvement, Security, Web, Rust, Not Speced.
  - Fields in use: priority 0 to 4, estimates (points), assignee (James), delegate (agents), `gitBranchName`, relations (blocks, blocked by, related, duplicate of), GitHub PR attachments, and comments. Agents post comments as James.
  - The workspace has reached the free-plan issue limit. A follow-up issue could not be created on 2026-11-10; see the JAM-18 comment.
- **Hierarchy depth reaches 5:** JAM-31 (roadmap) → JAM-127 (epic) → JAM-16 (task) → JAM-173 → JAM-252.
- **Jira KAN** (project id 10001, "shaboigen works") is empty. Link types are Blocks, Cloners, Duplicate and Relates.
  - The MCP account is `theantimeridian` (`theantimeridian@proton.me`), created 2026-11-10. That is the same e-mail as the identity Codex's Slack posts carry, so reporter and comment author on every migrated issue will be that account.
- **Linear references in operational files:**
  - All 13 gate and task scripts, through `<linear-id>` and the `linear_id:` field, plus their 5 shell tests.
  - `.agents/skills/epic-task-cycle/SKILL.md` (`.claude/skills/epic-task-cycle` is the same skill).
  - `AGENTS.md` (24 references), `CLAUDE.md` (4), `CONTRIBUTING.md`, and four coordination docs: `coordinator-playbook.md`, `templates/assignment.md`, `watcher-prompt.md` and `work-routing.md`.
  - The `.ai/` state files.
  - Claude's memory note `claude-coordinator-role.md`.

## Decisions

James answered D1, D3/D4, D6 and the timing in chat on 2026-11-10. D2, D5 and D7 are the recommended defaults; James can override them before Task 2.

| # | Question | Decision |
|---|---|---|
| D1 | Which Jira account is James? | **`theantimeridian` (account id `712020:9dab45a6-b5ed-42d0-b3cc-e1145efb6865`) is James** (answered in chat). Agents write to Jira through the same MCP connection, so a Jira comment cannot be shown to be human-typed. Jira comments are therefore information, never approval, the same rule as Slack connector posts. Approvals stay in chat. |
| D2 | Where does JAM-31 (the roadmap root) go? | JAM-31 becomes a Task labelled `roadmap`. Its epics get the label `roadmap`, and its non-epic children become Tasks with a Relates link to it. |
| D3 | Statuses | **Revised after the dry run** (answered in chat). KAN does have In Review (transition 31). Todo, In Progress, In Review and Done map one to one. Backlog becomes To Do, and Canceled and Duplicate become Done. Every issue gets the label `linear-status-<status>` (`linear-status-in-review`, `linear-status-canceled` and so on) so the original state can still be filtered. Duplicates also get a Duplicate link. |
| D4 | Bug | **It stays a label** (`bug`) on Task, following from the D3 answer. |
| D5 | Comments | One "Linear history" comment per issue. Each original comment appears in order under `**<author> · <ISO date>**`, split at 30,000 characters. |
| D6 | Naming after cutover | **Jira's default** (answered in chat). Branches are `KAN-<m>-<slug>`, with no username prefix and the key kept in upper case so GitHub for Jira matches it. Gate files are `kan-<m>__<slug>.md`. Legacy `jam-*` gate and task files stay readable. |
| D7 | Integrations at cutover | James disconnects Linear's GitHub integration, so merges stop auto-closing Linear issues, and installs GitHub for Jira. Slack keeps `slack-notify.sh`. |
| D8 | Timing of the repo switch | **The PR is built now and merged at cutover** (answered in chat). |

Dry-run additions (James, in chat, 2026-11-10):
- Linear "No priority" gets the label `linear-priority-none`, because Jira's default priority is Medium.
- Markdown checkboxes become ✅ (done) and ⬜ (open), because Jira shows `[x]` as plain text.
- The JAM-125 dry run became KAN-4.

## Mapping (applied by Tasks 2–4)

| Linear | Jira |
|---|---|
| Issue labelled `Epic` (other than JAM-31) | Epic |
| Child of an Epic, or a top-level issue that is not an epic | Task (Bug becomes the label `bug`, D4) |
| Child of a Task | Subtask |
| Grandchild of a Task or deeper (for example JAM-252) | Subtask under the nearest Task ancestor, plus a Relates link to its real Linear parent, noted in the description |
| Project name | label `proj-<slug>`, for example `proj-d-analysis-surfaces` |
| Labels Feature, Improvement, Bug, Security, Web, Rust, Not Speced | lower-case kebab labels (`not-speced`) |
| Priority 1 / 2 / 3 / 4 / 0 | Highest / High / Medium / Low / no change |
| Backlog, Todo / In Progress / In Review / Done, Canceled, Duplicate | To Do / In Progress / In Review / Done, plus the label `linear-status-<status>` (D3); Duplicate also gets a Duplicate link |
| Estimate | Story point estimate, if the field exists on the type; otherwise `Estimate: n pt` in the header |
| Delegate (an agent) | label `owner-codex` or `owner-claude-code` |
| Assignee James | Assignee is `theantimeridian` (D1) |
| `blocks` / `blockedBy` / `relatedTo` / `duplicateOf` | Blocks / Blocks inverse / Relates / Duplicate links |
| GitHub PR attachments | a "Linked PRs" list at the end of the description |
| Created, completed and canceled dates | the description header (the MCP cannot set Jira's own dates) |
| `JAM-n` mentions inside descriptions and comments | left as written; the ledger resolves them |

## Review Focus

1. **A run interrupted mid-way.** A rerun must not create duplicates. The label lookup in Task 2 step 2 settles this, and the Task 2 dry run tests it.
2. **A child created before its parent's key exists.** Creation goes strictly in level order, Epics → Tasks → Subtasks, and the Task 3 verification checks that every non-root issue has a Jira parent or a documented Relates fallback.
3. **Linear changing during migration.** JAM-18's cloud session or Codex may edit issues. Task 6 freezes writes and re-syncs anything with `updatedAt` after the export started.
4. **Existing gate and task files with `linear_id: JAM-n`.** After the switch, `gate-status.sh JAM-21 <slug>` must still find `jam-21__<slug>.md`. A test is added in Task 7.
5. **Markdown that doesn't survive conversion.** Tables, code fences and nested lists may not render in Jira. Task 5 compares 10 sample issues after rendering.

---

### Task 1: Prepare KAN and the ledger (James, then the agent)

**Files:** `coordination/migration/jam-to-kan.tsv` (header only) and its README already exist from the repo-switch PR. Fill in (header `jam_id	kan_key	kind	parent_kan	status_set	links_set	comments_set`) and `coordination/migration/README.md` (the mapping table above, plus the rerun procedure). Add `coordination/migration/export/` to `.gitignore`.

- [ ] **Step 1:** James confirms D2, D5 and D7, or overrides them.
- [ ] **Step 2: Verify through the MCP.** Create one throwaway issue `KAN migration probe`. `getTransitionsForJiraIssue` must reach To Do, In Progress and Done; record the transition ids in the README. `getJiraIssueTypeMetaWithFields` for Task (`requiredFieldsOnly: false`) tells you whether a story-point field exists; record its field id in the README. James deletes the probe; the MCP cannot.
- [ ] **Step 3:** Commit the ledger header and the README.

### Task 2: Export, then create Epics (dry run first)

**Interfaces:**
- Produces: ledger rows `kind=epic`, and the label-lookup routine used by Tasks 3 and 4: JQL `project = KAN AND labels = "linear-jam-<n>"`, where a hit means skip and record.

- [ ] **Step 1: Snapshot.** Write every Linear issue to `coordination/migration/export/<JAM-n>.json`, covering the fields in the mapping plus relations, attachments and comments. Record the export start time in the README. This directory is git-ignored: comments may include drafts that should not be published to the repo.
- [ ] **Step 2: Dry run.** Create the Epic for JAM-125 only. Rerun the same step and check that the lookup finds it and no second issue appears. Show James the rendered issue.
- [ ] **Step 3: Create the rest.** Create every remaining Epic (labelled `Epic`, excluding JAM-31) and add each to the ledger as it is created.
- [ ] **Step 4: Verify.** JQL `project = KAN AND issuetype = Epic` must return as many issues as the export holds `Epic` issues other than JAM-31.

### Task 3: Tasks, Bugs and Subtasks, in level order

- [ ] **Step 1:** Create JAM-31 as a Task, then every level-0 issue, each with its parent Epic key from the ledger.
- [ ] **Step 2:** Create the Subtasks. For a grandchild or deeper, apply the mapping's fallback.
- [ ] **Step 3: Verify.** The ledger has 275 rows, one per export file. `project = KAN` with `searchResultMode: count` returns 275, which holds because KAN started empty and the probe was deleted. Every row except the roots has `parent_kan` set or a fallback note.

### Task 4: Statuses, links and comments

- [ ] **Step 1:** Transition each issue to its mapped status (D3) and set `status_set=1`. The `linear-status-*` labels are set at creation.
- [ ] **Step 2:** Create the relation links. Each pair is created only once: skip the inverse side of a blocks pair. Set `links_set=1`.
- [ ] **Step 3:** Post the "Linear history" comment (D5) and set `comments_set=1`. Comment attachments become their Linear URLs, because the MCP cannot upload files.
- [ ] **Step 4: Verify.** For each Linear status, the count of `linear-status-<status>` labels matches the export, and every issue sits in its mapped Jira status. Spot-check JAM-18 (5 PR links, 1 Blocks, 4 Relates, 8 comments), JAM-252 (the depth fallback), JAM-51 (Duplicate) and JAM-1 (Canceled).

### Task 5: Fidelity review

- [ ] **Step 1:** Compare 10 issues side by side with Linear: 2 epics, 3 completed tasks with long markdown, 2 backlog items, 1 bug, 1 subtask and 1 duplicate. Check headings, tables, code fences and links.
- [ ] **Step 2:** Fix the converter and re-edit (`editJiraIssue`) any issue whose markdown came out broken. Record the fixes in the README.

### Task 6: Cutover

- [ ] **Step 1: Freeze.** Post `feedback` to Slack: "Linear is frozen; don't edit issues". Stop or park JAM-18's cloud session and Codex's queue. Check that no gate is `delegated` mid-task, or note its new key.
- [ ] **Step 2: Delta sync.** Search Linear for `updatedAt` after the export start, and re-apply status and comment changes to the mapped KAN issues.
- [ ] **Step 3:** In each open `coordination/tasks/*.md` and `coordination/gates/*.md` that has a `linear_id`, add `issue_key: KAN-m` from the ledger. `gate_field_issue_key` prefers `issue_key`, so reminders and `list-pending-gates.sh` show the KAN key. Gate files keep their `jam-n__<slug>.md` names, so commands on a gate that is still in flight keep using its legacy key, for example `gate-status.sh JAM-21 <slug>`. New gates use KAN keys.
- [ ] **Step 3b:** On the repo-switch branch, update the user-facing docs and live task state so they point at Jira. This needs KAN keys, so it can't be done earlier.
  - Replace the `linear.app` links with `theantimeridian.atlassian.net/browse/KAN-m` links looked up in the ledger: JAM-70 in `docs/analysis-guide.md:142`, `docs/troubleshooting.md:79` and `docs/usage.md:22`, and JAM-254 in `docs/wire-protocol.md:145`.
  - Point `.ai/CURRENT_TASK.md` and `.ai/HANDOFF.md` at the KAN key for whatever task is active.
  - Check that `git grep -n 'linear\.app' -- . ':!docs/superpowers'` comes back empty.
- [ ] **Step 4:** James merges the repo-switch PR (Tasks 7–8) and applies D7. Outside the repo, James also:
  - disables the `linear@claude-plugins-official` plugin in `.claude/settings.local.json` (Claude reads Linear through it until the delta sync is done);
  - gives Codex an Atlassian/Jira app. `~/.codex/config.toml` only pre-approves `linear.save_issue` and `linear.save_comment`, so it needs matching approvals for the Jira create, edit, transition and comment tools;
  - removes the Linear approvals there afterwards.
- [ ] **Step 5:** Post `done` with the ledger path. From here on, the next work item is the next KAN `To Do` issue.

### Task 7: Coordination scripts take an issue key, not a Linear id

**Files:**
- Modify: `coordination/scripts/lib.sh` (the `gate_path` and slug-validation comments)
- Modify: `create-gate.sh`, `approve-gate.sh`, `block-gate.sh`, `claim-gate-delegation.sh`, `gate-status.sh`, `mark-gate-delegated.sh`, `reclaim-stale-gate.sh`, `recover-gate-lock.sh`, `reset-gate-delegation-claim.sh`, `list-pending-gates.sh`, `new-task.sh`, `complete-task.sh`, `slack-notify.sh`
- Test: `coordination/scripts/tests/test-*.sh`

**Interfaces:**
- Produces:
  - Every script's first argument is `<issue-key>`: `KAN-m`, or a legacy `JAM-n`.
  - New gate and task files write `issue_key: <KEY>`.
  - Readers use the new `gate_field_issue_key <file>` in `lib.sh`, which returns `issue_key` or falls back to `linear_id`.
  - The reminder lines say "update <KEY>'s status in Jira".

- [ ] **Step 1: Failing tests.**
  - In `test-create-gate.sh`, a `KAN-12` gate writes `issue_key: KAN-12` to `kan-12__<slug>.md`.
  - In `test-lib.sh`, `gate_field_issue_key` returns `JAM-21` for a legacy file that has only `linear_id: JAM-21`.
  - In `test-gate-transitions.sh`, `gate-status.sh JAM-21 <slug>` still resolves a legacy file.
  - In `test-lib.sh`, `task_branch <slug> KAN-12` (and `kan-12`) gives `KAN-12-<slug>`, and with no key it gives `<prefix>/<slug>`. `task_branch` rejects a bad slug or key, and `normalize_issue_key` upper-cases the key. `new-task.sh` builds its branch and the `issue_key` it records from these helpers. There is no end-to-end `new-task.sh` test, because the script creates a real worktree and branch in the shared repository.
- [ ] **Step 2:** Run `for t in coordination/scripts/tests/test-*.sh; do bash "$t"; done`. The new assertions should fail.
- [ ] **Step 3:** Rename `LINEAR_ID` to `ISSUE_KEY` and the usage strings, write `issue_key:`, add `gate_field_issue_key`, and switch `list-pending-gates.sh` and `complete-task.sh` to it. Gate tags keep the `<key-lower>__<slug>` shape.
- [ ] **Step 4:** Run the whole suite and confirm everything passes. Then `git grep -n -i linear coordination/scripts` may only match the legacy-fallback lines and their comments.
- [ ] **Step 5:** Commit `refactor(coordination): gate and task scripts take a tracker issue key (Jira KAN)`.

### Task 8: Skills and agent docs say Jira

**Files:**
- Modify: `.agents/skills/epic-task-cycle/SKILL.md`
- Modify: `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING.md`
- Modify: `coordination/coordinator-playbook.md`, `coordination/templates/assignment.md`, `coordination/watcher-prompt.md`, `coordination/work-routing.md`
- Modify: `.ai/PROJECT_STATE.md`, and `.ai/DECISIONS.md` (a new ADR-007 only; old ADRs are not touched)

- [ ] **Step 1: Rewrite the skill.**
  - Resolve epics with JQL: `project = KAN AND issuetype = Epic AND statusCategory != Done`, then `parent = KAN-m` for its children.
  - Statuses are To Do, In Progress, In Review and Done (D3), moved with `transitionJiraIssue`; look up the transition ids with `getTransitionsForJiraIssue` and never hard-code them.
  - PRs go under the issue's "Linked PRs", or are linked automatically by GitHub for Jira (D7).
  - Remove the Linear quirks in §2 step 8, replacing them with "verify each write with a fresh `getJiraIssue`".
  - Keep JAM-125 as the worked example, noting that it is now `KAN-<m>` per the ledger.
- [ ] **Step 2: The docs.** Wherever Linear appears as the tracker, change it to Jira (KAN). In the queue rule, "the next `Todo` issue" becomes "the next `To Do` issue in KAN". Add a pointer to the ledger for old `JAM-n` references. In Sources of Truth, Linear becomes "Linear (archived, read-only; JAM-n history)".
- [ ] **Step 3: ADR-007.** "Jira KAN replaces Linear (2026-11-10)" records the reason (the Linear free-plan issue limit), the D1–D8 answers, and the ledger.
- [ ] **Step 4: Verify.**
  - Run `git grep -n -i linear -- AGENTS.md CLAUDE.md CONTRIBUTING.md coordination .agents .ai/PROJECT_STATE.md`. Only lines naming the archive or the ledger may remain.
  - Check that `.claude/skills/epic-task-cycle` resolves to the updated file.
- [ ] **Step 5:** Commit `docs: make Jira KAN the tracker in skills and agent docs`, open the PR, and post `pr-opened`. James merges at Task 6 step 4.
- [ ] **Step 6: Outside the repo.** Update Claude's memory note `claude-coordinator-role.md`, and tell Codex in Slack that its Linear connector is replaced by Jira. Codex needs its own Atlassian connector, which James sets up.
