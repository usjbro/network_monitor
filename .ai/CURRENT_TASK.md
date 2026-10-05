# Current Task

JAM-194: third-party pcapng replay compatibility. Approved directly in chat on 2026-10-05.

Worktree: `.worktrees/third-party-pcapng-replay`; branch `jamesmbrownjr/jam-194-p2-pcapng-replay-rejects-valid-third-party-blocks-sections`.

Scope: section byte order/version, concatenated sections, section-local interfaces, per-packet framing/timestamp metadata, validated unknown-block skipping, explicit replay errors and unsupported packet-block diagnostics, classic-pcap RAW mapping. Preserve JAM-174 length attribution and existing resource limits. Offset/FCS/address metadata, writer and TLS ingestion remain follow-ups.

Validation: reader/unit regressions, independent multi-interface/mixed-endian fixtures, actual binary replay, malformed inputs, Rust tests/release/clippy, reader fuzz, independent code/security review and CI before merge.
