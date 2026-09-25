---
name: epic-task-cycle
description: Use when handling a Linear epic in this repo across branching, implementation, validation, PR, tracker updates, and merge. Resolve the epic ID and follow repo-specific tracker, CI, and close-out conventions.
---

# Epic task cycle

The repo's branch → implement → validate → PR → Linear → optional Notion →
merge workflow for an epic. Invoke it as `$epic-task-cycle JAM-127` or load
it before starting the cycle; §0 covers what to do when no epic is given.

## Scope and authorization

Follow the user's requested scope. Loading this skill or identifying an
epic does not authorize external changes. Update Linear/Notion, push, open
or subscribe to a PR, send notifications, or merge only when the user has
authorized that stage. A request for read-only triage ends before changing
branches, files, tracker state, or GitHub state. Passing CI gates is not
permission to merge.

Every rule below was found by hitting it during **JAM-125 ("Capture files
and offline analysis")**, which shipped 14/14 tasks — none of it was
anticipated in the abstract. JAM-125 stays throughout as the worked example,
and the appendix records what it cost.

This is scaffolding, not a substitute for reading the actual spec and plan
for whatever you're touching (`docs/superpowers/specs/`,
`docs/superpowers/plans/`) or this repo's own `AGENTS.md`.

## 0. Resolve the epic

Do this before touching a branch. §2 assumes you already know which item
you're on, and guessing is how the wrong task gets built.

1. **Get the epic id** from this skill's arguments. If none was given, don't
   guess: `list_issues` with `parentId: JAM-31` (the roadmap issue the
   phase-2 epics hang off) and ask which one. An epic already `In Progress`
   is the likeliest intent, but say so rather than assuming it.
2. **Fetch the epic** (`get_issue`), then its children
   (`list_issues parentId: <epic>`). The children are the task issues; the
   epic itself is never implemented directly.
3. **Find the spec and plan.** Both live under `docs/superpowers/`, but
   **neither filename contains the epic id** — specs are
   `YYYY-MM-DD-<slug>-design.md`, plans are `YYYY-MM-DD-<slug>.md`. Don't
   guess the slug. Each task description names the plan PR *and* the doc
   path verbatim, e.g. JAM-135: "Part of the JAM-125 implementation plan
   (PR usjbro/network_monitor#193,
   `docs/superpowers/plans/2026-09-19-capture-files.md`, Task 1)". Read the
   spec before extending anything it covers.
4. **Pick the next item**: the lowest-numbered `Todo` child whose stated
   dependencies are all `Done`. Dependencies are **prose in the task
   description** ("Depends on Task 3 (the Writer type), not on the
   reader/replay tasks — can proceed in parallel with Tasks 6-8"), not
   Linear relation fields. A `blockedBy` query comes back empty and tells
   you nothing.
5. **Locate the epic's Notion tracker, if it has one** (§1). Many epics
   won't have one. That's normal — don't create one to fill the gap unless
   asked.

## 1. Tracker conventions

### Linear

Team **"James"**. A task issue's description links back to its parent epic
and to the original plan PR/document, and cross-references the **legacy
issue** it discharges (e.g. JAM-5, JAM-133, GitHub #71/#72). Don't confuse a
legacy number with the tracking one — and don't discard it either, §3 needs
it.

### Notion

An epic *may* have its own Notion task-tracker database. JAM-125's was
`https://app.notion.com/p/942f76634cdf465ca05cf5e7ed29e97b` ("Capture Files
(JAM-125) — Task Tracker"), data source
`collection://14fa2900-6a89-4d73-aeca-8d47e233a1a5` — now fully `Done`, and
kept here only as the shape to expect. **Another epic's tracker is a
different database with different ids and possibly a different schema.**

To use one: find its data source, `fetch` it to read the **live** schema,
then query with `notion-query-data-sources` (SQL mode) to get a row id.
Don't carry a page id across sessions from memory.

The schema pattern JAM-125 used — worth re-verifying against whatever
tracker an epic actually has, since this shape isn't guaranteed elsewhere:
`Task` (title), `Task #` (number), `Legacy Issue(s)` (text), `Notes` (text),
and `Status`.

**`Status` is a status property, not a select**, and its option set is
fixed. JAM-125's had exactly three values: `"Not started"`, `"In progress"`,
`"Done"` — **no "In Review"**. A write with an unsupported value errors or
is silently rejected, so check the schema before assuming a value exists.
Where there's no "In Review", use `"In progress"` for both "implementing"
and "PR open, waiting on CI/review", and put the actual state (PR link, CI
status, review status) in `Notes` instead.

## 2. Per-item cycle

1. Fetch the task issue; read its description for dependencies and the
   legacy cross-reference.
2. Inspect `git status` and the current branch before syncing local `main`
   (`git fetch origin main`). Follow a designated branch in the current
   session instructions, or use the issue's `gitBranchName` after checking
   it is safe. Never reset/recreate a branch or discard local/unmerged work
   unless explicitly directed and the worktree/history is confirmed safe.
3. Mark the task issue "In Progress"; same for a Notion row if one exists.
4. Implement. **Expect the plan document's own code sketch to contain a real
   bug** — this isn't a hedge, it's the observed rate: in JAM-125's final
   three tasks, every single one had at least one verified error in its
   sketch (a control-route allowlist the sketch assumed already existed and
   didn't; a byte-offset claim about a binary format that was simply wrong;
   an exclusion test that asserted `[] === []` and tested nothing; a
   resource-limit claim — "a ring overwrites its oldest file" — that was the
   opposite of what the code does). Read the sketch as a draft to verify
   against the actual code, not a spec to transcribe. When you deviate, say
   so explicitly in the PR description as a "deliberate deviation" with the
   concrete evidence (the line of code, the failing assertion) — don't
   silently diverge, and don't silently agree either.
5. Validate locally before pushing, matching what CI actually runs
   (`.github/workflows/ci.yml`) — for `capture-agent/` changes:
   `cargo build --release --locked`, `cargo test --locked`, and
   `cargo clippy --all-targets --locked -- -D warnings`, all clean.
   - If the change adds or touches a `cargo-fuzz` target, run it locally for
     ~30-60s (`cargo +nightly fuzz run <target> -- -max_total_time=40`)
     before shipping — this caught a real out-of-memory bug (an unbounded
     allocation from an untrusted length field) that unit tests missed.
   - If the change touches an `#[ignore]`d integration test (e.g. anything
     needing `CAP_NET_RAW`/`CAP_NET_ADMIN` for a real capture), **actually
     run it**, not just confirm it compiles: `setcap
     cap_net_raw,cap_net_admin=eip target/debug/<bin>` then `cargo test
     --locked --test <name> -- --ignored --test-threads=1`. A test that
     never executes proves nothing — this is also the right moment for the
     "break it on purpose" check (temporarily corrupt the thing the test is
     supposed to catch, confirm it fails on exactly that, revert) rather
     than trusting a green run you haven't seen go red.
5a. For security-sensitive changes (auth/origin checks, replay, attribution,
    TLS gating, `deploy/`, or `macos-app/`), run an available security-review
    workflow before pushing. If none is available, perform and report a
    focused security review; clean tests do not replace it. JAM-125's review
    of two control messages found a CSRF gap tests had missed.
5b. For UI changes in `app/page.tsx` or `components/`, exercise the change
    in a browser against a real capture agent where the environment supports
    it. Lint/Vitest alone missed UI defects during JAM-125. Replay settings
    (`REPLAY_FILE`, `REPLAY_SPEED=realtime`, `MAX_FLOWS`) can provide a
    deterministic session. If browser/agent verification is unavailable,
    report that limitation.
6. Commit only when authorized, using any attribution required by current
   session instructions; never copy a stale footer. Push only when
   authorized, with `git push -u origin <branch>`. If the branch's remote history
   is entirely already-merged commits (check with `git diff --stat
   origin/main <remote-branch-sha>` — empty means fully merged), a rejected
   non-fast-forward push there is expected and `--force-with-lease` against
   that known sha is safe; never force past unmerged work.
7. If authorized to open a PR, check which GitHub integration or CLI is
   actually available; do not assume `gh` or any MCP server is installed.
   Use the current session's attribution footer only if required by its
   instructions. Subscribe to PR activity only if supported and authorized.
8. Attach the PR to the task issue and set it to `"In Review"`. Two distinct
   Linear quirks, both hit for real:
   - Passing `links` and `state` in the same `save_issue` call can silently
     drop the state change (sometimes with a "duplicate attachment" warning,
     sometimes with none at all) — set them in **separate calls**, state
     last.
   - **The very next read can lie.** `save_issue`'s own response, and even a
     subsequent `get_issue`, can echo the *old* state for a few seconds
     after a write that actually succeeded (observed: four consecutive reads
     all showing "In Review" for an issue that had flipped to "Done" a
     minute earlier, per its own `stateHistory`). If a state change looks
     like it didn't take, don't loop retrying `save_issue` — check
     `stateHistory` on a fresh `get_issue`, or cross-check with
     `list_issues`, before concluding the write failed.
9. Update the Notion tracker row if one exists: `Status` to `"In progress"`
   (there may be no "In Review" — see §1), `Notes` gets the PR link and
   anything notable found while implementing.
10. Watch CI through PR activity subscriptions when available; otherwise
    inspect workflow runs/jobs using the connected GitHub integration or
    CLI. Do not assume a subscription, CLI, or MCP server exists.
    - **This repo's legacy commit-status API is always empty** —
      `pull_request_read`'s `get_status` reliably returns `total_count: 0`.
      Use `actions_list` (`list_workflow_runs` / `list_workflow_jobs`) for
      the real check runs instead; trusting `get_status`'s emptiness as "no
      CI yet" is a repeated false read.
    - CodeQL runs as its own workflow (shows up named `PR #<N>`,
      `dynamic/github-code-scanning/codeql`) and holds `mergeable_state` at
      `"unstable"` for several minutes *after* the main CI workflow has gone
      green — don't merge on CI-green alone; wait for
      `mergeable_state: "clean"`.
    - If the session cannot remain active until CI completes, record the
      current PR/check-run and next action in `.ai/HANDOFF.md`; do not assume
      a background scheduler or notification tool is available.
11. Merge with squash only when all of these gates pass:
    - CI is green, including separate workflows such as CodeQL.
    - A security review has passed (for security-sensitive work, use §2.5a).
    - Code review has passed; an absent or pending review is not a pass.
    - GitHub reports `mergeable_state: "clean"`.

    The user has authorized merging once these gates pass. Do not ask for
    another merge confirmation between tasks. If any gate fails or is still
    pending, leave the PR open and report what remains. After a successful
    merge, unsubscribe from PR activity if applicable, set the task issue to
    `"Done"`, and update the Notion row (if any) with the merged PR.
12. After closing out an item, continue automatically to the next eligible
    child task; do not stop for a progress report or ask for a new go-ahead
    between tasks when the user has requested the epic cycle. Re-read the
    latest user instructions before each item. Pause and report only when a
    task is blocked, requirements or dependencies are materially ambiguous,
    a security or scope issue needs a decision, the user changes or cancels
    direction, or a required external action is not authorized by the user or
    this skill. At the end of the epic, complete §3 and report the outcome.

## 3. Closing the epic

When the last child merges, the epic's *work* is done but its paperwork
isn't. §2 steps 8–11 keep the tracker truthful during the work; this keeps
it truthful afterwards.

1. **Confirm every child is closed.** `list_issues parentId: <epic>` and
   check them all, rather than trusting a memory of the last one merging.
2. **Sweep the legacy issues.** Each task description names the legacy issue
   it discharges ("Corresponds to legacy issue JAM-7 / GitHub #74"). Those
   legacy issues do **not** close themselves when the implementing task
   merges. Collect them across every task in the epic, then close each with
   a comment naming the task issue and the merged PR that discharged it — a
   bare status flip loses the trail for whoever reads the issue later.
   - A legacy issue split across several tasks (JAM-133 took Tasks 6–8)
     closes once, citing all of them.
   - Record anything that would otherwise die with the issue. JAM-133's
     closing comment had to carry the "replay resolves once at startup,
     never runtime-switchable" design decision, because that constraint
     lived nowhere its readers would look.
   - Where the shipped work is *stronger* than the issue's acceptance
     criteria, say so: JAM-7 asked for a test that decrypted content can't
     be exported, and what shipped made it structurally unreachable.
3. **Watch for legacy issues parented elsewhere.** JAM-8 was discharged by
   JAM-125's Task 1 but sits under JAM-130, the *continuous* security/CI
   epic. Closing it narrows a different epic's scope, so surface it and ask
   rather than closing it reflexively.
4. **Then** close the epic itself.

**The failure this prevents:** JAM-125 was marked `Done` while five legacy
issues it had fully discharged (JAM-5, JAM-6, JAM-7, JAM-132, JAM-133) sat
in `Todo` — four of them its own direct children. The epic advertised
completion while carrying open children for days, and the roadmap read as
having more work left than it did. Do step 2 before step 4, not after.

## Environment gotchas (this repo, this kind of session)

- Fresh container setup for `capture-agent/`: `apt-get install -y
  libpcap-dev` (cargo can't link without it) before any cargo command that
  touches the crate, plus `npm install` at the repo root for the web side.
- Playwright: this environment pre-installs a Chromium build at a different
  revision than `@playwright/test`'s own pinned one.
  `playwright.config.ts` already handles this for `npx playwright test`;
  driving the app with a standalone script needs the same treatment —
  `chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome',
  args: ['--no-sandbox'] })` — and the driver script needs to live inside
  the repo (or be run from it) so `require('playwright')` resolves at all.
- **Never `pkill` to stop a dev server or agent process spawned for
  verification** — it can kill the session's own process tree. Use
  `lsof -ti:<port> -sTCP:LISTEN | xargs -r kill` instead, scoped to the
  actual port.
- `git checkout next-env.d.ts` before every commit if `npm run dev` ran this
  session — it rewrites that file as a side effect (a `.next/` vs.
  `.next/dev/` path difference) that has nothing to do with your change and
  shouldn't be committed.

## Things not to do

- Don't invent a tracker `Status` value beyond what the schema actually
  supports — check it, don't assume "In Review" exists just because it would
  be convenient.
- Don't treat "continue from where you left off" as license to skip the
  per-item bookkeeping in §2 steps 8–11, or the close-out in §3 — the whole
  point of this cycle is that the tracker stays truthful in real time, not
  just at the end of a session.
- Don't widen or narrow an item's scope as a silent side effect of something
  else you're doing (e.g. wiring new CI automation while fixing an unrelated
  bug) — if a task's own plan explicitly scopes something out for a later
  item, respect that and say so in the PR description rather than bundling
  it in "since you're already there."
- Don't close a legacy issue on a title that merely looks similar. Close it
  on the task description that names it, and cite that task and its PR.

## Appendix: JAM-125, for the record

The worked example the rules above came from. 14/14 tasks shipped
(JAM-135–148), epic `Done`.

Three collateral defects were found while implementing the later tasks and —
deliberately — filed and fixed as their own separate items rather than
folded silently into whatever task surfaced them: JAM-150 (a wire-format
mismatch that left a shipped UI banner permanently dead against a real
agent), JAM-151 (a missing cross-site check on a control endpoint, escalated
by a later task into an arbitrary-path file write), and JAM-152 (a flaky
test intermittently reddening `main`). That pattern — fix the item you're
on, file the collateral finding as its own tracked thing instead of
scope-creeping it in — is worth repeating on any epic.

Its five legacy issues (JAM-5, JAM-6, JAM-7, JAM-132, JAM-133) were closed
retroactively, well after the epic was marked `Done`. §3 exists so the next
epic doesn't repeat that.

Two follow-ups from that work remain intentionally unfiled (flagged, not
forgotten): widening `capture-agent/src/wire.rs`'s `line.contains(...)` test
assertions into full-shape checks, and tightening
`validate_capture_file_path` to an allowlisted capture directory rather than
"anywhere outside the agent's own working directory."
