# Current Task

## Objective

Complete JAM-164: make live packet stream OSI layers truthful and ensure the layer filter buttons match the layers this capture path can report.

## Baseline

- Issue: [JAM-164](https://linear.app/shmishmorshin/issue/JAM-164/live-pcap-per-packet-layer-field-is-hardcoded-to-4-breaking-the)
- Branch: `jamesmbrownjr/jam-164-live-pcap-per-packet-layer-field-is-hardcoded-to-4-breaking`
- Worktree: `.worktrees/live-pcap-per-packet-layer-field-is-hardcoded-to-4-breaking`
- Pull request: [#240](https://github.com/usjbro/network_monitor/pull/240)

## Acceptance Criteria

- [x] TCP/UDP without recognized application data is tagged L4; ICMP and other unparsed transports are tagged L3.
- [x] Recognized HTTP, HTTP response, DNS, and TLS ClientHello packets are tagged L7.
- [x] Live packet layer filters show only supported L3, L4, and L7 controls.
- [x] Rust classification tests cover the transport, network, and application cases.
- [x] Component test proves L3/L4/L7 filters narrow a mixed packet feed and unsupported layer buttons are absent.

## Status

Implementation and validation are complete. PR #240 is open, attached to JAM-164, and Linear is In Review. CI is green and GitHub reports a clean mergeable state. Codex's independent code review found no actionable issues; Claude Code cross-review was requested in the task's Slack thread and is still pending. Before merge, recheck that PR #239's stream-reassembly changes do not require syncing this branch. See `HANDOFF.md` and `TEST_STATUS.md` for evidence.
