# Current Task

JAM-168: keep reassembled L7 field offsets tied to bytes present in the emitted packet event.

Worktree: `.worktrees/p2-keep-reassembled-l7-field-offsets-tied-to-packet-bytes`; branch: `jamesmbrownjr/jam-168-p2-keep-reassembled-l7-field-offsets-tied-to-packet-bytes`.

Current phase: PR #277 is open and attached to JAM-168, which is In Review. Packet field construction omits application fields when `SniffOutcome.status` shows L7 info came through reassembly, while preserving packet header fields and direct, unsplit L7 offsets. Split and unsplit ClientHello regressions pass. Full Rust tests, strict Clippy, release build, `git diff --check`, and two independent reviews pass. GitHub CI is pending; merge only after clean checks and reviewer approval.
