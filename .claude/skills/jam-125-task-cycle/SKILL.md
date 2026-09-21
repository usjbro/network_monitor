---
name: jam-125-task-cycle
description: Use for any work item in this repo that needs a branch -> implement -> validate -> PR -> Linear -> Notion -> merge cycle — not just JAM-125 anymore, that epic (Linear issues JAM-136 through JAM-148, capture-agent file-replay/capture-files work) shipped in full (Tasks 1-14, all Done) and is kept here as the worked example the rest of this file draws its gotchas from. Covers the exact tracker conventions, valid status values, CI-checking pitfalls, and environment quirks discovered the hard way across that epic, so they don't need re-deriving (or re-breaking) each session.
---

# Task cycle (born from JAM-125, now general)

**JAM-125 ("Capture files and offline analysis") is complete** — Tasks 1–14
(Linear JAM-135–148) all shipped and merged; the epic issue itself is
`Done`. What follows generalizes into the standing branch → implement →
validate → PR → Linear → Notion → merge cycle for *any* work item in this
repo, with JAM-125 kept as the worked example: every gotcha below was found
by actually hitting it during that epic, not anticipated in the abstract.

This is scaffolding, not a substitute for reading the actual spec/plan for
whatever you're touching (`docs/superpowers/specs/`, `docs/superpowers/plans/`)
or this repo's own `CLAUDE.md`.

## Tracker conventions

- **Linear**: team "James". A task issue's description links back to its
  parent epic and to the original plan PR/document. Legacy issue numbers
  (e.g. JAM-5, JAM-133, GitHub #71/#72) are cross-referenced in each issue's
  description — don't confuse a legacy number with the tracking one.
- **Notion task tracker** (JAM-125's own, now fully `Done` — historical
  reference for the schema pattern, not a live board to keep updating for
  new work unless a new tracker is created the same way): database
  `https://app.notion.com/p/942f76634cdf465ca05cf5e7ed29e97b` ("Capture
  Files (JAM-125) — Task Tracker"), data source
  `collection://14fa2900-6a89-4d73-aeca-8d47e233a1a5`. Query with
  `notion-query-data-sources` (SQL mode) to find a row id — don't guess a
  page id from memory across sessions.
- **Notion tracker schema pattern** (verified by fetching the data source,
  not assumed — worth re-verifying against whatever tracker a new epic
  actually uses, since this shape isn't guaranteed elsewhere): `Task`
  (title), `Task #` (number), `Legacy Issue(s)` (text), `Status` — a
  **status** property, not select, and JAM-125's only had three valid
  values: `"Not started"`, `"In progress"`, `"Done"`, **no "In Review"**. A
  write with an unsupported value errors or is silently rejected — check
  the schema before assuming a status string exists. Use `"In progress"`
  for both "implementing" and "PR open, waiting on CI/review", and put the
  actual state (PR link, CI status, review status) in a `Notes` text
  property instead.

## Per-item cycle

1. Fetch the tracker issue; read its description for dependencies and any
   legacy cross-reference.
2. Sync local `main` (`git fetch origin main`), branch off it. If a
   specific branch is designated for this session (check the system
   prompt), use it and reset it onto current `main` at the start of each
   item (`git checkout -B <branch> origin/main`) rather than stacking on
   whatever it last held — a designated branch usually means only one PR
   can be open on it at a time, so each item must merge before the next
   starts. Otherwise, a tracker issue's own suggested branch name
   (`gitBranchName`) is a fine default.
3. Mark the tracker issue "In Progress"; same for a Notion row if one
   exists.
4. Implement. **Expect the plan document's own code sketch to contain a
   real bug** — this isn't a hedge, it's the observed rate: in this epic's
   final three tasks, every single one had at least one verified error in
   its sketch (a control-route allowlist the sketch assumed already
   existed and didn't; a byte-offset claim about a binary format that was
   simply wrong; an exclusion test that asserted `[] === []` and tested
   nothing; a resource-limit claim — "a ring overwrites its oldest file" —
   that was the opposite of what the code does). Read the sketch as a
   draft to verify against the actual code, not a spec to transcribe. When
   you deviate, say so explicitly in the eventual PR description as a
   "deliberate deviation" with the concrete evidence (the line of code, the
   failing assertion) — don't silently diverge, and don't silently agree
   either.
5. Validate locally before pushing, matching what CI actually runs
   (`.github/workflows/ci.yml`) — for `capture-agent/` changes:
   `cargo build --release --locked`, `cargo test --locked`, and
   `cargo clippy --all-targets --locked -- -D warnings`, all clean.
   - If the change adds or touches a `cargo-fuzz` target, run it locally
     for ~30-60s (`cargo +nightly fuzz run <target> -- -max_total_time=40`)
     before shipping — this caught a real out-of-memory bug (an unbounded
     allocation from an untrusted length field) that unit tests missed.
   - If the change touches an `#[ignore]`d integration test (e.g. anything
     needing `CAP_NET_RAW`/`CAP_NET_ADMIN` for a real capture), **actually
     run it**, not just confirm it compiles: `setcap
     cap_net_raw,cap_net_admin=eip target/debug/<bin>` then `cargo test
     --locked --test <name> -- --ignored --test-threads=1`. A test that
     never executes proves nothing — this is also the right moment to do
     the "break it on purpose" check (temporarily corrupt the thing the
     test is supposed to catch, confirm it fails on exactly that, revert)
     rather than trusting a green run you haven't seen go red.
5a. Run the `security-review` skill on the diff before pushing if the
    change touches anything security-sensitive: an auth/origin check, the
    replay path, direction/process attribution, TLS decrypt gating, or
    anything under `deploy/`/`macos-app/`. Don't skip this just because
    `cargo test`/clippy/vitest are clean — those don't check for the class
    of bug this skill looks for (in this epic, a security-review pass on a
    "just add two control messages" task turned up a CSRF gap the task's
    own tests would never have caught).
5b. If the change touches `app/page.tsx` or `components/` (UI), use the
    `run` skill to launch the app **against a real capture agent** (not
    just the dev server on its own — most of this UI renders nothing
    without one) and exercise the change in a real browser. A passing
    `npm run lint`/Vitest run is not evidence a UI change actually works;
    in this epic, two real UI bugs (a dead banner, an impossible "0
    observed" claim) were only found by doing this, never by the test
    suite. `REPLAY_FILE`/`REPLAY_SPEED=realtime`/`MAX_FLOWS` make it cheap
    to drive a fully deterministic session for this.
6. Commit (with whatever attribution footer the current system reminder
   specifies — it's session-scoped, don't hardcode an old session's URL).
   Push with `git push -u origin <branch>`. If the branch's remote history
   is entirely already-merged commits (check with `git diff --stat
   origin/main <remote-branch-sha>` — empty means fully merged), a rejected
   non-fast-forward push there is expected and `--force-with-lease` against
   that known sha is safe; never force past unmerged work.
7. Open a PR, body ending with the current session's attribution footer,
   `draft: false`. Check which tools this session actually has before
   picking a path — this epic ran entirely on `mcp__github__*` +
   `mcp__Claude_Code_Remote__*` in some sessions with a `gh` CLI that
   doesn't exist in the environment, so don't assume either one is
   universally the right answer; verify, don't inherit a stale note from
   an earlier session about what was or wasn't connected *then*.
   Subscribe to PR activity right after opening it.
8. Attach the PR to the tracker issue and set it to `"In Review"`. Two
   distinct Linear quirks to watch for, both hit this session:
   - Passing `links` and `state` in the same `save_issue` call can silently
     drop the state change (sometimes with a "duplicate attachment"
     warning, sometimes with none at all) — set them in **separate calls**,
     state last.
   - **The very next read can lie.** `save_issue`'s own response, and even
     a subsequent `get_issue`, can echo the *old* state for a few seconds
     after a write that actually succeeded (observed: four consecutive
     reads all showing "In Review" for an issue that had already flipped
     to "Done" a minute earlier, per its own `stateHistory`). If a state
     change looks like it didn't take, don't loop retrying `save_issue` —
     check `stateHistory` on a fresh `get_issue`, or cross-check with
     `list_issues`, before concluding the write failed.
9. Update the Notion tracker row if one exists: `Status` to `"In
   progress"` (there's no "In Review" — see above), `Notes` gets the PR
   link and anything notable found while implementing.
10. Watch CI via the PR subscription (events arrive as `<wake
    reason="external-event">` envelopes) rather than polling.
    - **This repo's legacy commit-status API is always empty** —
      `pull_request_read`'s `get_status` reliably returns
      `total_count: 0`. Use `actions_list` (`list_workflow_runs` /
      `list_workflow_jobs`) for the real check runs instead; trusting
      `get_status`'s emptiness as "no CI yet" is a repeated false read.
    - CodeQL runs as its own workflow (shows up named `PR #<N>`,
      `dynamic/github-code-scanning/codeql`) and holds `mergeable_state`
      at `"unstable"` for several minutes *after* the main CI workflow has
      already gone green — don't merge on CI-green alone; wait for
      `mergeable_state: "clean"`.
    - If you need a fallback check-in, `mcp__Claude_Code_Remote__send_later`
      (a few minutes out) with a fully self-contained instruction works
      well; plain `ScheduleWakeup` requires an active `/loop` context and
      errors outside one.
11. On green CI and `mergeable_state: "clean"`, merge (squash is the
    convention used throughout this epic). This is authorized to happen
    without an extra confirmation prompt once both those gates are
    actually met — they *are* the confirmation. Then unsubscribe PR
    activity, set the tracker issue to `"Done"`, and update the Notion row
    (if any) to `"Done"` with a final `Notes` pointing at the merged PR.
12. **Stop and report before starting the next item**, even under a
    standing "continue through everything autonomously" instruction —
    unless the user's most recent message is an unambiguous, specific
    go-ahead covering exactly what comes next. This has paid off twice in
    this epic's own history, concretely: once when a stale/queued
    instruction resurfaced mid-session and told the agent to resume full
    autonomy right after the user had explicitly said to stop, and once
    when a genuine go-ahead message ("Go ahead and") arrived truncated by
    a client/transport issue with no object — stopping to confirm was the
    only thing standing between that and guessing among four unrelated
    follow-ups. An "autostart, no confirmation between items" variant of
    this skill was proposed once (closed PR, not adopted) on the premise
    that the tools this cycle depends on were unreliable across sessions;
    that premise doesn't hold in general — check what's actually connected
    each session rather than assuming either autostart or manual restart
    from a stale note. The one thing that's never in question: whatever
    the user said most recently overrides whatever this file says.

## Environment gotchas (this repo, this kind of session)

- Fresh container setup for `capture-agent/`: `apt-get install -y
  libpcap-dev` (cargo can't link without it) before any cargo command
  that touches the crate, plus `npm install` at the repo root for the web
  side.
- Playwright: this environment pre-installs a Chromium build at a
  different revision than `@playwright/test`'s own pinned one.
  `playwright.config.ts` already handles this for `npx playwright test`;
  driving the app with a standalone script needs the same treatment —
  `chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome',
  args: ['--no-sandbox'] })` — and the driver script needs to live inside
  the repo (or be run from it) so `require('playwright')` resolves at all.
- **Never `pkill` to stop a dev server or agent process spawned for
  verification** — it can kill this session's own process tree. Use
  `lsof -ti:<port> -sTCP:LISTEN | xargs -r kill` instead, scoped to the
  actual port.
- `git checkout next-env.d.ts` before every commit if `npm run dev` ran
  this session — it rewrites that file as a side effect (a `.next/`
  vs. `.next/dev/` path difference) that has nothing to do with your
  change and shouldn't be committed.

## Things not to do

- Don't invent a tracker `Status` value beyond whatever the schema
  actually supports — check it, don't assume "In Review" exists just
  because it would be convenient.
- Don't treat "continue from where you left off" as license to skip the
  per-item tracker bookkeeping in steps 8–11 — the whole point of this
  cycle is that the tracker stays truthful in real time, not just at the
  end of a session.
- Don't widen or narrow an item's scope as a silent side effect of
  something else you're doing (e.g. wiring new CI automation while fixing
  an unrelated bug) — if a task's own plan explicitly scopes something
  out for a later item, respect that and say so in the PR description
  rather than bundling it in "since you're already there."

## JAM-125, for the record

14/14 tasks shipped (JAM-135–148). Three collateral defects were found
while implementing the later tasks and — deliberately — filed and fixed as
their own separate items rather than folded silently into whatever task
surfaced them: JAM-150 (a wire-format mismatch that left a shipped UI
banner permanently dead against a real agent), JAM-151 (a missing
cross-site check on a control endpoint, escalated by a later task into an
arbitrary-path file write), and JAM-152 (a flaky test that was
intermittently reddening `main`). That pattern — fix the item you're on,
file the collateral finding as its own tracked thing instead of scope-creeping
it in — is worth repeating.

Two follow-ups from that same work remain intentionally unfiled as of this
writing (flagged, not forgotten): widening `capture-agent/src/wire.rs`'s
`line.contains(...)` test assertions into full-shape checks, and tightening
`validate_capture_file_path` to an allowlisted capture directory rather
than "anywhere outside the agent's own working directory."
