# PR #225 Review Follow-ups Implementation Plan

> **For agentic workers:** Use the executing-plans skill to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Let a later session safely recover an approved gate whose delegation was interrupted, and recover an abandoned filesystem lock without disturbing an active operation.

**Architecture:** Keep the existing local Markdown gate format and `mkdir` lock. Record an atomic delegation claim before dispatch; expose an explicit reset that requires confirmation after checking no delegation is active. Record the lock owner PID and process start time when available, and provide an explicit recovery command that refuses a matching live owner. Update the agent instructions to distinguish pending, claimed, and completed delegation.

**Tech Stack:** Bash, awk, POSIX filesystem operations, shell regression tests.

**Spec:** Existing `docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md`; this plan resolves post-open review findings without changing the approval policy.

## Global Constraints

- Keep gate paths validated through `gate_path` and `validate_slug`.
- Only `status=approved` gates may be claimed, reset, or marked delegated.
- Never dispatch twice while a delegation claim exists.
- Never remove a lock whose recorded owner process is alive.
- Preserve existing gate file permission modes and cross-platform macOS/Linux support.

## Review Focus

- An approval followed by interruption before dispatch remains recoverable without another approval.
- An interruption after claiming delegation cannot silently cause a duplicate dispatch; recovery requires explicit confirmation.
- Lock recovery refuses a live owner and removes only a stale or ownerless lock after explicit confirmation.
- Normal command failures release their lock and preserve their original exit status.
- Existing approval, rejection, frontmatter-scoping, and concurrent-transition behavior remains unchanged.

---

### Task 1: Recover abandoned gate locks

**Files:** Modify `coordination/scripts/lib.sh`; create `coordination/scripts/recover-gate-lock.sh`; test `coordination/scripts/tests/test-lib.sh`.

- [x] Write tests proving that a live owner is refused, a stale owner can be recovered only with `--confirm-no-live-operation`, and an ownerless lock also requires confirmation.
- [x] Run `bash coordination/scripts/tests/test-lib.sh` and confirm the new cases fail because recovery is unavailable.
- [x] Record the current PID inside each acquired lock; remove the owner file and lock directory on normal completion, while retaining the command's exit status.
- [x] Add a validated recovery command that refuses live owner PIDs and requires explicit confirmation before removing stale or ownerless locks.
- [x] Run the focused test and confirm all lock cases pass.

### Task 2: Recover approved, undispatched tasks

**Files:** Modify `coordination/scripts/create-gate.sh`, `gate-status.sh`, and `mark-gate-delegated.sh`; create `claim-gate-delegation.sh` and `reset-gate-delegation-claim.sh`; test `coordination/scripts/tests/test-gate-transitions.sh`; update `AGENTS.md` and `coordination/watcher-prompt.md`.

- [x] Write tests proving only the first session can claim an approved gate, a claimed gate cannot be claimed twice, a completed delegation cannot be reset, and an explicitly confirmed orphaned claim can be reset and reclaimed.
- [x] Run `bash coordination/scripts/tests/test-gate-transitions.sh` and confirm the new cases fail before implementation.
- [x] Add a `delegation_claimed` frontmatter field initialized to `false`; expose it in gate status.
- [x] Atomically claim only an approved, unclaimed, not-yet-delegated gate. Require a claim before `mark-gate-delegated.sh` records completion.
- [x] Add an explicit reset requiring `--confirm-no-active-delegation`; refuse reset for completed delegations.
- [x] Update chat and Slack watcher instructions to resume an approved unclaimed gate, and to ask for confirmation before resetting an incomplete claim.
- [x] Run transition and lock tests, `bash -n` on all coordination scripts, and `git diff --check`.
