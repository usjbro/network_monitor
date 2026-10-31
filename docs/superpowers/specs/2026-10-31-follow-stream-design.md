# Follow Stream: Reassembled Conversation View — Design Spec

**Issue:** JAM-17 — "Follow Stream: read a conversation as reassembled text" (GitHub #84)
**Epic:** JAM-127 (analysis surfaces)
**Depends on:** JAM-16 stream reassembly (shipped; `2026-09-28-stream-reassembly-design.md`, "Deferred, explicitly").
**Status:** DRAFT for James's review. No wire, agent or UI code until this is approved.

Written spec-first at James's direction (chat, 2026-10-11) because the 2026-10-11 spec-readiness review found seven undecided points. This document decides each one and marks the ones that are James's call. Where a number is a judgment, it says why, so the reviewer can change it without archaeology.

## Problem

Packets are viewable one at a time. Nothing joins a conversation's bytes. JAM-16's reassemblers cannot be reused as the store: `StreamReassembler` holds 16 KiB per direction (`MAX_TCP_STREAM_BYTES`) and **releases a direction's buffer the moment an L7 detector decides**. It is an L7-decision buffer, not a conversation store, and its own spec says Follow Stream "will want its own bounded store".

## The privacy fact that shapes everything

Holding conversation bytes means holding the cleartext payload of real traffic in agent memory for longer than anything does today. Today the agent keeps payload only transiently for an L7 decision, and emits a sampled, rate-limited `hexDump` per packet (100 events/s). A conversation store is a different class of retention. So retention is **opt-in**, consistent with the repo's other opt-in features (TLS decryption, ownership and GeoIP enrichment, capture-to-file). Nothing is retained, and the control message returns "not enabled", unless the operator turned it on.

## Decisions

### D1. Retention is opt-in at agent startup — **James to confirm**

`FOLLOW_STREAM=1` (agent environment, read once at startup, like the other opt-ins). When off: no store is allocated, `get_stream` answers `enabled: false`, and the UI button explains how to enable it. When on: the agent retains the **head** of each TCP flow (below), cleartext flows only.

Alternatives considered:
- **Per-flow "arm" at click time.** Smaller retention footprint, but not retroactive: the operator clicks a flow that is already mid-conversation and sees only what follows, so the headline case ("read that HTTP request I just saw") fails. Rejected as the default; it could be added later as a narrower mode.
- **Always on.** Rejected: it silently changes what the agent holds in memory for everyone.

### D2. The store: head-keeping, per direction, with explicit gaps

New module `capture-agent/src/follow.rs` (`FollowStore`). Separate from `StreamReassembler`; shares the flow identity (`FlowTable::key_for`, so the two can never disagree about flow or direction) and, where clean, the sequence-delta arithmetic and first-seen-bytes-win overlap policy (JAM-16 rationale: the monitor's view of already-reported bytes must be immutable; conflicting overlaps are counted).

Per flow, per direction:
- **Contiguous stored bytes** from the stream start, plus an ordered list of **gaps**. A gap is `{ at: stored offset, missing: u32, reason }` and records an exact sequence-space hole size (known from the sequence delta), never a guess.
- **Out-of-order window:** bytes ahead of the contiguous edge are held for at most 64 KiB and 2 s of *capture time*. After that the hole is declared a gap and the stream continues past it. This is what makes the reader see "N bytes missing" instead of either stalling forever or splicing across the hole.
- **Gap reason**, with JAM-16's precedence: `snaplen` (the IP header's declared length exceeded the captured bytes; actionable: raise the snap length) wins over `missing` (frames never captured).
- **Head-keeping caps, never a rolling window.** When a direction reaches its cap the store stops appending, keeps counting `seen_bytes`, and reports `storeTruncated`. A rolling window would silently discard the start of the conversation, which is the part readers want, and would make the view change under them.
- **Turns:** an ordered list of `{ dir, start, len, firstSeenMs }`, coalescing consecutive same-direction runs. This is how the two directions are interleaved in reading order. Capped (4 096 per flow); beyond it, turns coalesce further and the response says `turnsCoalesced`.

| Cap | Value | Why |
|---|---|---|
| Per direction | 256 KiB | A full HTTP exchange with a modest body; 16× the L7 buffer. Past this the view is a head, labelled as one. |
| Per flow | 512 KiB | Two directions. |
| Retained flows | 256 | A reader follows a handful of flows; far below `DEFAULT_MAX_FLOWS` (10 000). |
| Global | 16 MiB | **Counted in reserved capacity** (data, gap lists, turn lists, coverage maps), not length, per the security checklist §1. 256 × 512 KiB would be 128 MiB, so the global cap binds first and is the real limit. |
| Out-of-order window | 64 KiB / 2 s capture time | Bounds a hostile sender that never fills a hole. |

**Eviction:** tied to flow lifetime. A flow's entry is dropped when `FlowTable` evicts it (idle or capacity) and, under global-cap pressure, oldest-closed-first then oldest-idle. An evicted flow answers `found: false`, which is not the same as "empty". Timeouts run on the replay-aware clock (`ReplayClock`), never wall time (checklist §5). An interface switch clears the store (JAM-183 precedent) and a pause stops feeding it without clearing.

**Fragment-reassembled TCP** feeds the store through the same path JAM-167 already routes it through, so a segment that arrived in IP fragments is not a spurious gap.

**Flow start not captured:** if the first segment seen has neither SYN nor a known start, `flowStartCaptured: false` and the view says so. It never presents a mid-stream start as a beginning.

### D3. Encrypted flows are detected and not stored

A flow whose first client bytes are a TLS record (the existing ClientHello structural probe) is marked `encrypted`; **its bytes are discarded, not stored**, and only `seenBytes` is kept. The view says "this is TLS — content is encrypted" and names `bin/osi-inspect.js` as the only supported way to see inside. We therefore never hold or display ciphertext as if it were content, and no memory is spent on it. QUIC and any UDP are out of scope (D8).

`decrypted_payload` and its `DecryptedStore` stay entirely separate. Follow Stream **never reads from them and never merges with them**; a flow that has decryption active still shows the "encrypted" explanation here, plus a pointer to where decrypted segments already render (`PacketStreamView`). `lib/decrypted-payload-gate.ts` is not modified, and the existing `decrypted-export-exclusion` test must keep passing untouched.

### D4. Wire: request/response over a relay HTTP route, not SSE broadcast — **wire change, ask-first under AGENTS.md**

Stream content must not be pushed onto the SSE feed. Every connected browser tab receives that feed; broadcasting a conversation to all of them turns "one operator looked at one flow" into a fan-out. Instead:

- **Browser → relay:** `POST /api/follow-stream` with `{ connectionId, c2s: { offset }, s2c: { offset } }`. The route applies `rejectIfCrossSite` first (as `/api/control` and `/api/enrichment/lookup` do), validates field types and bounds, then the content gate (D6).
- **Relay → agent:** a new control message `get_stream` with a `requestId` the relay generates, plus the same fields. `ControlMessage` gains `GetStream` (Rust `wire.rs`), and `app/api/control/route.ts`'s allowlist is **not** extended: this message is only ever sent by the new route, never accepted from the browser.
- **Agent → relay:** a new event `stream_data` carrying the same `requestId`. The agent-client correlates it to the pending request (5 s timeout) and `lib/stream-response.ts` (where `decrypted_payload` is already gated per event, line ~122) **drops it from the SSE feed**, so it is never delivered to browsers except as the HTTP response.

Response shape (all sizes bounded; the relay also re-validates):

```json
{
  "type": "stream_data",
  "requestId": "r-7f3a",
  "connectionId": "Tcp-192.168.1.10:51000-93.184.216.34:80",
  "enabled": true,
  "found": true,
  "encrypted": false,
  "flowStartCaptured": true,
  "closed": false,
  "turnsCoalesced": false,
  "directions": {
    "clientToServer": {
      "offset": 0, "storedBytes": 412, "seenBytes": 412, "storeTruncated": false,
      "gaps": [], "conflictingOverlapBytes": 0,
      "redactedRanges": [{"start": 187, "len": 22}],
      "dataBase64": "R0VUIC8..."
    },
    "serverToClient": { "offset": 0, "storedBytes": 1530, "seenBytes": 1530, "storeTruncated": false,
      "gaps": [{"at": 900, "missing": 1460, "reason": "missing"}],
      "conflictingOverlapBytes": 0, "redactedRanges": [], "dataBase64": "SFRUUC8x..." }
  },
  "turns": [{"dir": "c2s", "start": 0, "len": 412, "firstSeenMs": 120}, {"dir": "s2c", "start": 0, "len": 900, "firstSeenMs": 160}]
}
```

- **Paging:** each response carries at most 32 KiB of stored bytes per direction (64 KiB total), starting at the requested offsets; the client keeps requesting from `offset + returned` until it has all `storedBytes`. This keeps every NDJSON line far below any line cap and bounds relay memory per request. Checked in `lib/agent-client.ts`: only the 256-byte authentication line is size-capped; an event line is buffered until its newline with no cap. The 64 KiB bound therefore has to be enforced by the agent when it builds the response, and the implementation plan should add a relay-side cap on a `stream_data` line (rejecting an oversized one) rather than rely on the agent alone.
- **Extending, not breaking:** unknown fields and enum values are ignored by the mapper, and `reason` / `dir` unknown values map to a visible "unknown" rather than throwing (checklist §6).
- **Rate:** one outstanding request per connection id per tab; the agent answers from memory and does no per-request allocation larger than the response bound.
- Updated together, per the repo's wire rule: `capture-agent/src/wire.rs`, `lib/types.ts`, `lib/agent-mapping.ts`, `docs/wire-protocol.md`, tests on both sides.

### D5. Live and replay

Works on any flow the store retains, live **and** replay (`REPLAY_FILE`), since the store is fed from the packet path both share. That also makes the feature deterministic to test end to end. It does **not** read capture files by itself; reading a recorded file's streams on demand is the JAM-255 query-service question (D9).

### D6. Gating and the cleartext content boundary

The relay applies a gate to `/api/follow-stream` that is **the same predicate** as `isDecryptedPayloadAllowed` (direct loopback, or a verified mTLS header via Caddy), implemented as a new function `isStreamContentAllowed` in its own module so a test can prove parity and so decrypted content and cleartext stream content cannot silently become one switch. It does not modify `lib/decrypted-payload-gate.ts`.

Honest limit, stated rather than hidden: JAM-255's review notes that an absent mTLS header on the local path is not caller authentication, and JAM-196 (authenticated callers) is open. Follow Stream inherits that limit exactly as `decrypted_payload` and the packet `hexDump` do. It makes it no worse for the per-packet case, but a full conversation is more content than a sampled packet, so **D1's opt-in is the real control and JAM-196 is a recommended prerequisite for enabling this on a LAN**. Say so in `docs/security.md`.

### D7. Redaction: same-length masking at emission — **James to confirm**

`redact.rs` today masks parsed HTTP/2 header values on the decrypted path and leaves bodies untouched ("named limitation, not a bug"). The issue says redaction applies here. For cleartext HTTP/1.x the agent applies the same name list and bearer-token shape (`is_sensitive_header_name`, bearer prefix test) to **header lines in the bytes it is about to emit** and overwrites the value bytes with `*` **at the same length**. Same length means offsets, gaps and the hex view stay consistent, and the response lists `redactedRanges` so masked text is visibly masked rather than looking like real content.

- Redaction runs on emission; the in-memory store keeps the original bytes (checklist §4 "redacted before emission"). It is a new byte-range helper in `redact.rs` (which needs `looks_like_bearer_token`, currently private, widened to `pub(crate)`), with its own tests (names case-insensitive, folded headers, bearer under an unlisted name, a header that straddles a gap is left alone because it cannot be parsed safely).
- **Named limitations, unchanged in kind:** bodies are never redacted; non-HTTP protocols are not parsed, so a password in a Telnet or FTP stream is visible. The UI banner for non-HTTP text says "content is shown as captured; only HTTP/1.x credential headers are masked".
- Escaping is not redaction and does not replace it.
- Raw save and hex mode emit the masked bytes too. There is no "reveal" in v1.

### D8. Scope: TCP only

UDP and QUIC are out of scope for v1. The issue's title names UDP, but its acceptance criteria and every dependency are TCP/HTTP, and UDP has no stream identity or ordering to follow. Recorded as a deliberate non-goal, not a gap. IPv6 TCP is in scope to the extent the flow table keys it.

### D9. Live vs recorded — relationship to JAM-255 — **James to confirm**

This spec delivers **live-and-replay** Follow Stream only. JAM-255's proposal (a separate unprivileged query service over finalized captures) would add recorded Follow Stream and notes that it needs "a separate, bounded reassembly contract preserving direction, gaps, conflicts and truncation". The `stream_data` shape above (per-direction bytes, gaps with reasons, conflicts, truncation, turns) is deliberately source-agnostic so a recorded source could later fill the same contract. Nothing here depends on JAM-255 being adopted, and nothing here pre-empts its decisions.

### D10. Rendering safety (the browser side)

New pure module `lib/stream-render.ts` (no React), unit-tested with a hostile fixture before any component exists. Rules:

- Bytes are never interpreted as markup. The component renders text through React text nodes only; `dangerouslySetInnerHTML` is forbidden for this view, and a test greps for it.
- **Text mode** decodes as UTF-8 with invalid sequences shown as `\xNN`, then escapes: C0 controls other than `\n` and `\t` (including ESC, so ANSI/CSI/OSC sequences are inert), DEL, C1 controls, and the Unicode characters that can change what the reader sees: bidirectional overrides and isolates (U+202A–U+202E, U+2066–U+2069), zero-width and invisible formatting characters (U+200B–U+200F, U+2028, U+2029, U+FEFF). `\r` is shown visibly so a carriage return cannot overwrite an earlier line in the display.
- **Hex mode:** offset, hex bytes, and an ASCII column where every non-printable byte is `.`.
- **Render cap:** at most the 256 KiB per-direction store cap is ever rendered; a "load more" appends pages. Long unbroken lines wrap (`overflow-wrap: anywhere`) instead of widening the page.
- **Gaps and truncation are first-class rows**, never elided: `── 1460 bytes not captured (frames missing) ──`, `── 380 bytes not captured (snap length too small — raise it with snaplen) ──`, `── stored head only: 256 KiB of 1.4 MiB seen ──`.
- `lib/osi-mon-client.ts` (JAM-185) already has a control/escape/bidi-safe text escaper for terminal output. The implementer should reuse or share that logic rather than write a second, different escape set.
- **Raw save** downloads the already-fetched, masked bytes as a `Blob` from the browser, with a fixed filename (`stream-<n>.bin`), `application/octet-stream`, never derived from captured content. The agent writes no file and the relay serves none.

### D11. UI

A "Follow Stream" button in `ConnectionsView`'s selected-connection panel, next to "Trace Route" (same affordance, same on-demand rule: never automatic). The view is direction-coloured (client and server distinct, with a non-colour cue such as a `→` / `←` prefix so it does not depend on colour alone), has Text / Hex / Save, and a header banner with exactly these states (wording lives in one place, in the spirit of `ReassemblyStatus::label()`): `complete so far`, `gaps: frames missing`, `gaps: snap length too small`, `head only: store cap reached`, `flow start not captured`, `encrypted`, `not enabled`, `no longer retained`. Not changing `app/page.tsx` ownership of main state beyond one handler.

## Acceptance criteria → how each is met and tested

| Criterion | Mechanism | Test |
|---|---|---|
| Cleartext HTTP readable end to end, directions distinguished | D2 store, D10 text mode, D11 colour + glyph | Rust: request/response across segments in and out of order; TS: render fixture; real-browser run against replay of an HTTP pcap |
| Gaps and truncation never silently elided | D2 gaps with reasons, D10 gap rows | Rust: hole, snaplen-truncated frame, cap hit, out-of-order timeout; TS: every gap kind renders a row |
| Control chars and escape sequences cannot affect the page | D10 | Hostile fixture: ESC `[2J`, OSC 8 link, CR overwrite, NUL, bidi override, `<script>`, `</div>`, very long line; assert escaped output and zero DOM elements created from payload |
| Encrypted flows explain themselves | D3 | ClientHello flow stores nothing and the banner shows; ciphertext never reaches the response |
| Decrypted content stays gated, existing tests pass | D3, D6 | `decrypted-payload-gate` and `decrypted-export-exclusion` tests run unmodified; new parity test for `isStreamContentAllowed`; a test that the follow path has no import from the decrypted store |

## Security-plan review (checklist `docs/security-plan-review-checklist.md`)

Marked from this design; the implementing PR must re-mark them against the diff. What I did not verify: no code has run; the numeric caps are reasoned, not measured. Verified by reading source: `key_for`, `ReplayClock`, `rejectIfCrossSite` on the existing on-demand routes, the `decrypted_payload` filter in `lib/stream-response.ts`, the private `looks_like_bearer_token`, and the absence of an event-line cap in `lib/agent-client.ts`.

| § | Item | Status |
|---|---|---|
| 1 | Wire lengths checked before allocation; capacity-counted, per-stream/flow/global bounds; stated overlap policy; wraparound | Pass (design): D2 caps, window, first-seen-wins, `i32` sequence delta. Request `offset` and `connectionId` length are validated at relay and agent. |
| 1 | No unbounded parse loops | Pass (design): redaction scans only emitted header lines, bounded by the chunk size. |
| 2 | Failure terminal vs recoverable, fail closed, per-direction state | Pass (design): a gap is terminal for those bytes and shown; per-direction stores. An on-path attacker's best moves (injected overlapping data, a never-filled hole, a flood of flows) are bounded: first-seen-wins, window timeout, global cap. These are denial of service or a skewed view, not disclosure. |
| 3 | Cryptography | Not applicable: no decryption, no keys. |
| 4 | Secrets and sensitive data | Pass (design) with a limit: cleartext payload is held in memory, opt-in (D1), masked on emission (D7); never written to disk; not logged. Bodies and non-HTTP credentials are not redacted (named). The store should zeroize its buffers on eviction. Whether to do so for cleartext is an open question for the implementer to answer in the plan. |
| 5 | Time | Pass (design): replay-aware clock. |
| 6 | Interfaces | Pass (design): Rust, docs, `lib/types.ts` and `lib/agent-mapping.ts` change together; unknown values do not throw; `stream_data` is request-scoped, so flooding is bounded by the one-request-per-connection rule. It is subject to the content gate (D6). |
| 7 | Tests and tooling | Required by this spec: tests first and shown failing; boundary cases (cap, cap+1, zero); a `cargo-fuzz` target `follow_store` that asserts the byte caps hold under arbitrary segments, wired into CI's hand-listed fuzz steps and path filter; the hostile TS fixture; `security-review` before push. |

## Non-goals

No verdicts about whether traffic is normal or malicious (epic non-goal). No search, no export beyond Raw save, no HTTP body parsing or decompression, no object extraction (that is JAM-209), no UDP/QUIC, no recorded-file source (JAM-255), no persistence of any kind.

## Open questions for James

1. **D1:** is opt-in at agent startup (`FOLLOW_STREAM=1`) the right retention control?
2. **D7:** is same-length masking of HTTP/1.x credential headers the right reading of "redaction applies", given that bodies and non-HTTP credentials stay visible?
3. **D9:** live-and-replay now, with recorded Follow Stream left to the JAM-255 decision?
4. **Caps (D2):** are 256 KiB per direction and 16 MiB global acceptable, or should the global cap be smaller on a small host?
5. **Prerequisite:** should JAM-196 (authenticated callers) block enabling this off loopback, or is documenting the limit enough?

## Next

On approval: an implementation plan under `docs/superpowers/plans/`, then the work in this order: `follow.rs` and its fuzz target (agent-only, no wire), then the wire change, then the relay route, then `lib/stream-render.ts`, then the UI. Each step test-first.
