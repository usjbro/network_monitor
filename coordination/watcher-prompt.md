# Slack Approval Gate Watcher

Scheduled agent instructions — see docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md for the full design.

Each time you wake:

1. Run `coordination/scripts/list-pending-gates.sh` from the main repo root. If it prints nothing, stop — nothing to do this wake.
2. For each line (`<linear_id> <slug> <posted_at>`), read the `#network-monitor` Slack channel for messages or thread replies mentioning `<linear_id>-<slug>` posted after `<posted_at>`.
3. If there's no qualifying reply yet, move to the next gate. Do not post anything, do not change any state.
4. If there's a qualifying reply, use your own judgment to classify it:
   - **Clear approval** ("approved", "go ahead", "yes", "lgtm", etc.): run `coordination/scripts/gate-status.sh <linear_id> <slug>` first. If it still shows `status=awaiting-approval`, run `coordination/scripts/approve-gate.sh <linear_id> <slug>`. If that succeeds (prints "approved"), decide delegation via `coordination/router-checklist.md`, carry it out (spawn the right Agent-tool subagent for in-session work, or run `coordination/scripts/new-task.sh` for Codex work), then run `coordination/scripts/mark-gate-delegated.sh <linear_id> <slug> <in-session|codex> [agent-type]`. If the status check already showed `approved`, or `approve-gate.sh` exits 2, someone else (the original chat session) already handled it — do nothing further for this gate.
   - **Clear rejection**: run `coordination/scripts/block-gate.sh <linear_id> <slug> "<why, from the reply>"`, then reply in the same Slack thread acknowledging it's blocked. Do not delegate. Do not retry automatically on a later wake.
   - **Unclear / a question, not a decision**: reply in the Slack thread asking for a clear approve/reject. Leave the gate `awaiting-approval`.
5. Move to the next pending gate and repeat step 2.
