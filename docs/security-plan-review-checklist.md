# Security plan-review checklist

For reviewing a design (or the PR that implements it) for anything that parses attacker-controlled bytes or handles key material: protocol decoders, reassembly, TLS or other decryption, authentication, capture-file readers, and log/status/event output near them. Distilled from the JAM-204 TLS record-layer plan review (2026-10-07); see [`security.md`](security.md) for the project's overall posture.

Use it twice: once on the plan (before code), once on the diff. Mark each item pass, fail or not applicable, and say what you did not verify.

## 1. Inputs and bounds

- [ ] Every length taken from the wire is checked against a documented maximum **before** any allocation or reservation. The maximum is the protocol's real limit (for example a TLS 1.3 record body is at most 16,640 bytes, 16,645 with its header), not a convenient constant that happens to be nearby.
- [ ] Every buffer is bounded per stream, per owner (process) and globally, with the bound counted in capacity, not just length. Pressure behaviour is defined: what is evicted, and what the evicted stream reports.
- [ ] Reordering and overlap policy is stated: how much out-of-order data is held, which copy wins on overlap, and what a conflict does.
- [ ] Parsers cannot loop or recurse without a bound, and arithmetic on sequence numbers handles wraparound.

## 2. State and failure semantics

- [ ] Each failure is classified terminal or recoverable, with what recovers it and a deadline. A recoverable state that needs buffered data says where the data is held and counts it in the budget.
- [ ] A failure never produces output derived from unauthenticated or incomplete data. Fail closed, and say so.
- [ ] Per-direction (or per-stream) state is separate where the protocol's state is separate; one shared decoder for both directions is a bug.
- [ ] An on-path attacker's best move (injecting, dropping, reordering) is named and its effect stated, and whether it is a confidentiality issue or only denial of service.

## 3. Cryptography

- [ ] Algorithm and suite are identified from the protocol, not guessed from key length, and unsupported suites report "unavailable", not an authentication failure.
- [ ] Nonce and sequence construction follow the RFC. A sequence number advances only after successful authentication, and a failed trial never advances it.
- [ ] Key derivation and update steps are specified, including which side switches when.
- [ ] Constant-time comparison is used where secrets or tags are compared, if the library does not already do it.

## 4. Secrets and sensitive data

- [ ] Secrets are owned by exactly one scope (for example process + session), dropped as soon as consumed, and removed on every cleanup path (flow close, process unregister, eviction, shutdown).
- [ ] Types holding secrets implement zeroize and a redacting `Debug` (no derived `Debug`). No secret or plaintext appears in a log, panic message, status event or error string.
- [ ] Zeroization is exercised by a test through a seam, not assumed. Library types that cannot be zeroized are named, and the limit is documented in `security.md`.
- [ ] Decrypted data stays in memory only, in the existing capped, locked, zero-on-evict store, redacted before emission and rendered only through the existing gate. The no-disk-write test covers the new paths.
- [ ] Stored secrets have a retention cap and a time limit, so an unused secret cannot accumulate.

## 5. Time

- [ ] Timeouts use the replay-aware clock the rest of the pipeline uses, not wall time, so offline replay behaves the same at any speed.

## 6. Interfaces

- [ ] A wire change updates Rust (`wire.rs`), `docs/wire-protocol.md`, `lib/types.ts` and `lib/agent-mapping.ts` together. Unknown enum values on the receiving side do not throw.
- [ ] A new status or event is one-shot per (connection, direction, reason) where flooding is possible, and says whether it is subject to the content-rendering gate and why.

## 7. Tests and tooling

- [ ] Tests are written first and shown failing. They cover the boundary values (limit, limit + 1, zero), the failure classes above, ordering (in order, out of order, gap, overlap), and cleanup.
- [ ] A fuzz target covers the new parser or reassembler in the same PR, including declared lengths and sequence wraparound, and CI runs it.
- [ ] The reviewer states what was read and what was run. "I did not run the tests" is a valid statement; leaving it out is not.
