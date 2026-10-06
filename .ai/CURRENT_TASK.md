# Current Task

JAM-170: account for the IPv4-fragment and TCP-stream coverage buffers and allocated vector capacities in the reassembly memory budgets.

Worktree: `.worktrees/reassembly-coverage-memory-accounting`; branch: `jamesmbrownjr/jam-170-p2-account-for-reassembly-coverage-storage-in-memory-limits`.

Scope: `capture-agent/src/reassembly.rs` and `capture-agent/fuzz/fuzz_targets/stream_reassembly.rs`; update the stream-reassembly design spec and `.ai/` verification state. Count `data` and byte-backed `filled` vector capacities against the existing 4 MiB total fragment and TCP ceilings. Add tests that fill each budget and verify accounting/eviction, and ensure fuzz checks use the full accounting. No wire/API or unrelated reassembly behavior changes.

Gate approved by James directly in chat on 2026-10-06. The gate is claimed and delegated in-session; Linear JAM-170 is In Progress. Full local validation and review remain.
