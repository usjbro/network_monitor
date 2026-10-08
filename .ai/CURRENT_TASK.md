# Current Task

JAM-168: keep reassembled L7 field offsets tied to bytes present in the emitted packet event.

Worktree: `.worktrees/p2-keep-reassembled-l7-field-offsets-tied-to-packet-bytes`; branch: `jamesmbrownjr/jam-168-p2-keep-reassembled-l7-field-offsets-tied-to-packet-bytes`.

Current phase: Implemented and locally verified. Packet field construction now omits application fields when `SniffOutcome.status` shows L7 info came through reassembly, while preserving packet header fields and direct, unsplit L7 offsets. Split and unsplit ClientHello regressions pass. Full Rust tests, strict Clippy, release build, `git diff --check`, and independent Codex review pass. Formatting check remains noisy due to existing unrelated files. Preparing the PR.
