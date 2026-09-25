# Slack Approval Gate Watcher

In-session polling instructions — see docs/superpowers/specs/2026-09-25-slack-approval-gate-design.md for the full design. Not a separate scheduled agent: this runs inside the same interactive Claude Code session that created the gate, only while that session remains active. There is no cloud/scheduled-agent watcher — cloud agents can't see local, uncommitted gate state, and a real gate creator's session can just poll directly instead.

After creating a gate and telling the user it's posted, if you want to actively watch for a Slack reply rather than only waiting for the user's next chat message, poll `#network-monitor` every 60 seconds (tracking the last-read message, not the last-sent one, per this repo's existing Slack-monitoring convention) until the gate is resolved or the session ends:

1. Run `coordination/scripts/gate-status.sh <linear_id> <slug>` for the gate you created. If it's no longer `awaiting-approval` (someone approved it via chat in the meantime), stop polling — nothing left to do.
2. Read the `#network-monitor` Slack channel for messages or thread replies mentioning `<linear_id>-<slug>` posted after the gate's `posted_at`.
3. If there's no qualifying reply yet, wait 60 seconds and repeat from step 1.
4. If there's a qualifying reply, use your own judgment to classify it:
   - **Clear approval** ("approved", "go ahead", "yes", "lgtm", etc.): run `coordination/scripts/gate-status.sh <linear_id> <slug>` first. If it still shows `status=awaiting-approval`, run `coordination/scripts/approve-gate.sh <linear_id> <slug>`. If that succeeds (prints "approved"), decide delegation via `coordination/router-checklist.md`, carry it out (spawn the right Agent-tool subagent for in-session work, or run `coordination/scripts/new-task.sh` for Codex work), then run `coordination/scripts/mark-gate-delegated.sh <linear_id> <slug> <in-session|codex> [agent-type]`. If the status check already showed `approved`, or `approve-gate.sh` exits 2, the user already approved it in this same chat — do nothing further.
   - **Clear rejection**: run `coordination/scripts/block-gate.sh <linear_id> <slug> "<why, from the reply>"`, then reply in the same Slack thread acknowledging it's blocked. Do not delegate. Do not retry.
   - **Unclear / a question, not a decision**: reply in the Slack thread asking for a clear approve/reject. Keep polling — the gate stays `awaiting-approval`.
5. If the session ends before the gate is resolved, polling simply stops — the gate stays `awaiting-approval` and either a future session's own poll (if one is later started against the same task) or a direct in-chat approval next time this task is revisited can still resolve it.
