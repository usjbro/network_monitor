---
name: jam-125-task-cycle
description: Use when implementing one of the numbered tasks in the JAM-125 "Capture files and offline analysis" epic (Linear issues JAM-136 through JAM-148, capture-agent file-replay work), or any other work item that needs the same branch -> implement -> test -> PR -> Linear -> Notion -> merge cycle in this repo. Covers the exact tracker IDs, valid status values, and conventions discovered the hard way across Tasks 2-6, so they don't need re-deriving (or re-breaking) each session.
---

# JAM-125 task cycle

One epic (JAM-125, "Capture files and offline analysis") is implemented as a
sequence of Linear issues JAM-136 (Task 2) through JAM-148 (Task 14), each
one PR. This skill is the fixed scaffolding around that cycle: the tracker
IDs, the gotchas, and the per-task checklist. It is not a substitute for
reading the actual implementation plan (linked from JAM-125 itself, and
mirrored in the Notion pages below) or this repo's own `CLAUDE.md` and
`docs/superpowers/specs/` for the sub-project a task touches.

## Fixed IDs — don't rediscover these

- **Linear**: epic JAM-125, team "James". Each task issue's description
  links back to JAM-125 and to the original plan PR/document. Legacy
  issue numbers (JAM-5, JAM-133, GitHub #71/#72/etc.) are cross-referenced
  in each issue's description — don't confuse a legacy number with the
  JAM-13x/14x tracking number.
- **Notion task tracker**: database
  `https://app.notion.com/p/942f76634cdf465ca05cf5e7ed29e97b`
  ("Capture Files (JAM-125) — Task Tracker"), data source
  `collection://14fa2900-6a89-4d73-aeca-8d47e233a1a5`. Query it with
  `notion-query-data-sources` (SQL mode) to find a task's row id — don't
  guess a page id from memory across sessions.
- **Notion tracker schema** (verified by fetching the data source, not
  assumed): `Task` (title), `Task #` (number), `Legacy Issue(s)` (text),
  `Status` — a **status** property, not select, with only three valid
  values: `"Not started"`, `"In progress"`, `"Done"`. **There is no "In
  Review" option** — a page update with that value either errors or is
  silently rejected. Use `"In progress"` for both "implementing" and "PR
  open, waiting on CI/review", and put the actual state (PR link, CI
  status, review status) in the `Notes` text property instead. `Depends
  On` (text), `Linear Issue` (url), `Notes` (text).
- **Design/plan docs**: `docs/superpowers/specs/` and
  `docs/superpowers/plans/` hold the spec and implementation plan for each
  sub-project — read the relevant one before extending it, per
  `CONTRIBUTING.md`.

## Task ordering (Tasks 7-14)

The plan document's own per-task "Interfaces" sections make the dependency
chain explicit — it matches the JAM-141…148 numeric order exactly, so there
is no reason to resequence:

- Task 8 "Consumes: Task 7's `local_addrs`."
- Task 9 extends the same `AgentStatusJson` struct Task 8 introduces
  (adds `mode`/`replay_source`).
- Task 10 "Consumes: every wire change from Tasks 4 and 9."
- Task 11 "Consumes: Task 10's `mapAgentStatusEvent`/`mapCaptureFileStatusEvent`."
- Task 12 only hard-depends on Task 4 (already shipped), so it's technically
  unblocked earlier, but it shares `app/page.tsx` with Task 11 — do it right
  after.
- Task 13 has no hard dependency on 7-12 (pure functions over
  already-in-memory arrays) but there's no cost to leaving it here either.
- Task 14 "Consumes: everything from Tasks 1-13" — always last.

Work them **7 → 8 → 9 → 10 → 11 → 12 → 13 → 14**.

## Per-task cycle

1. Fetch the Linear issue for the task; read its description for what it
   depends on and which legacy issue it corresponds to.
2. Sync local `main` (`git fetch origin main`), branch off it:
   `git checkout -b <linear-branch-name>` (Linear's own suggested
   `gitBranchName` on the issue is a fine default; the convention actually
   used so far is `<github-username>/jam-<N>-<short-slug>`).
3. Mark the Linear issue "In Progress"; set the Notion tracker row's
   `Status` to `"In progress"`.
4. Implement. Deviating from the plan document's own code sketch is fine
   and has happened more than once (a real bug in the sketch, a repo
   convention the sketch didn't know about) — when it happens, call it out
   explicitly in the eventual PR description as a "deliberate deviation,"
   don't silently diverge.
5. Validate locally before pushing, matching what CI actually runs
   (`.github/workflows/ci.yml`): for `capture-agent/` changes,
   `cargo build --release --locked`, `cargo test --locked`, and
   `cargo clippy --all-targets --locked -- -D warnings`, all clean. If the
   task adds or touches a `cargo-fuzz` target, also run it locally for
   ~30-60s (`cargo +nightly fuzz run <target> -- -max_total_time=40`)
   before shipping — this caught a real out-of-memory bug (an unbounded
   allocation from an untrusted length field) that unit tests alone missed.
5a. Run the `security-review` skill on the diff before pushing if the task
    touches anything security-sensitive: the replay path, direction/process
    attribution, TLS decrypt gating, or anything under `deploy/`/
    `macos-app/`. In this epic that specifically means Tasks 7-9 (replay
    dispatch and direction attribution) — don't skip this just because
    `cargo test`/clippy are clean; those don't check for the class of bug
    this skill looks for.
5b. If the task touches `app/page.tsx` or `components/` (UI), use the `run`
    skill to launch the app and exercise the change in a real browser
    before considering the task done. `CLAUDE.md`'s own testing rule is
    explicit that type-checking and test suites verify code correctness,
    not feature correctness — a passing `npm run lint`/Vitest run is not
    evidence a UI change actually works. In this epic that's Tasks 11-13.
6. Commit (with whatever attribution footer the current system reminder
   specifies — it's session-scoped, don't hardcode an old session's URL).
   Push with `git push -u origin <branch>`.
7. Open a PR (`mcp__github__create_pull_request`), body ending with the
   current session's attribution footer, `draft: false` — every task PR in
   this epic has gone in as a normal (non-draft) PR, immediately ready for
   CI and review. Then `mcp__Claude_Code_Remote__subscribe_pr_activity` on
   it right away.
8. Attach the PR to the Linear issue and set it to `"In Review"`
   (`mcp__Linear__save_issue`). Note: attaching a link and changing state
   in the same call has intermittently thrown a "duplicate attachment"
   warning while still leaving the state unchanged — if that happens,
   re-call `save_issue` with just the state field, no `links`, to confirm
   it actually took.
9. Update the Notion tracker row: `Status` stays `"In progress"` (see
   above — there's no "In Review"), `Notes` gets the PR link and anything
   notable found while implementing (a real bug fuzzing turned up, a
   deviation from the plan, etc.).
10. Watch CI via the PR subscription (events arrive as
    `<wake reason="external-event">` envelopes) rather than polling. If you
    need a fallback check-in, use `mcp__Claude_Code_Remote__send_later`
    (a few minutes out) with a fully self-contained instruction — plain
    `ScheduleWakeup` requires an active `/loop` context and errors outside
    one.
11. On green CI and `mergeable_state: "clean"`, merge (squash has been the
    method used throughout this epic). Then unsubscribe PR activity, set
    the Linear issue to `"Done"`, and set the Notion tracker row's `Status`
    to `"Done"` with a final `Notes` update pointing at the merged PR.
12. **Stop and report before starting the next task**, even under a
    standing "continue through all issues autonomously" instruction. This
    epic's own session history has already produced one real conflict: a
    stale/queued instruction resurfaced mid-session and told the agent to
    resume full autonomy immediately after the user had explicitly said to
    stop. When a fresh, unambiguous instruction to continue is in hand,
    proceed; when it's ambiguous, stale, or contradicts something the user
    said more recently, ask rather than assume the standing mandate still
    holds.

## Things not to do

- Don't wire a new `cargo-fuzz` target into `.github/workflows/ci.yml`'s
  fuzz job/path-filter as a side effect of adding the target — that CI
  wiring is its own scoped task (the last task in this epic bundles it
  with other CI updates); a task that only adds the target should say so
  explicitly in its PR description.
- Don't invent a Notion `Status` value beyond the three listed above.
- Don't treat "continue from where you left off" as license to skip the
  per-task Linear/Notion bookkeeping in step 8-11 — the whole point of this
  cycle is that Linear and Notion stay truthful in real time, not just at
  the end of a session.
