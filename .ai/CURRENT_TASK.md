# Current Task

JAM-204: reassemble TLS 1.3 records across TCP segments, track per-direction sequence numbers, and select the correct traffic secret.

Worktree: `.worktrees/tls-decrypt-record-layer`; branch: `jamesmbrownjr/jam-204-tls-decrypt-record-layer`.

Current phase: Implementation and local verification are complete. PR #276 is open. The first CI run caught three existing decrypted-payload test fixtures missing the newly required `direction`; commit `07ac312` fixes them, and local TypeScript type-check plus focused tests pass. Refreshed CI and latest-head code/security review are pending. Review findings on capture-truncation propagation, strict key-wait/gap expiry, cleartext Finished, released-byte retransmissions, HPACK zeroization/accounting, terminal parser budget cleanup, and malformed decode temporary cleanup have been addressed. Preserve per-process opt-in decryption, in-memory-only plaintext/key handling, redaction, the rendering gate, and no-disk-write invariant.
