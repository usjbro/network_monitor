# Current Task

JAM-204: reassemble TLS 1.3 records across TCP segments, track per-direction sequence numbers, and select the correct traffic secret.

Worktree: `.worktrees/tls-decrypt-record-layer`; branch: `jamesmbrownjr/jam-204-tls-decrypt-record-layer`.

Current phase: Implementation and local verification are complete. Review findings on capture-truncation propagation, strict key-wait/gap expiry, cleartext Finished, released-byte retransmissions, HPACK zeroization/accounting, terminal parser budget cleanup, and malformed decode temporary cleanup have been addressed. Final independent re-review is in progress. Preserve per-process opt-in decryption, in-memory-only plaintext/key handling, redaction, the rendering gate, and no-disk-write invariant.
