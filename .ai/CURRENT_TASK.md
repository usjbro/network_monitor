# Current Task

JAM-204: reassemble TLS 1.3 records across TCP segments, track per-direction sequence numbers, and select the correct traffic secret.

Worktree: `.worktrees/tls-decrypt-record-layer`; branch: `jamesmbrownjr/jam-204-tls-decrypt-record-layer`.

Current phase: Review fixes are implemented and locally verified; PR #276 is open and needs a refreshed CI and independent review before merge. Review fixes address sequence advancement after zeroization, replaying records after late key arrival before expiry, counting retained plaintext-ring allocations in the aggregate TLS budget, avoiding non-zeroizing header formatting temporaries, bounding key-log polling/incomplete lines, and limiting/compacting handshake parsing. Earlier review findings on capture-truncation propagation, strict key-wait/gap expiry, cleartext Finished, released-byte retransmissions, HPACK zeroization/accounting, terminal parser budget cleanup, and malformed decode temporary cleanup remain addressed. Preserve per-process opt-in decryption, in-memory-only plaintext/key handling, redaction, the rendering gate, and no-disk-write invariant.
