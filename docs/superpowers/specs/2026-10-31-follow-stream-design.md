# Follow Stream: Reassembled Conversation View — Design Spec

**Issue:** JAM-17 — "Follow Stream: read a conversation as reassembled text" (GitHub #84)
**Epic:** JAM-127 (analysis surfaces)
**Depends on:** JAM-16 stream reassembly (shipped; `2026-09-28-stream-reassembly-design.md`, "Deferred, explicitly"). JAM-184 agent socket authentication (shipped).
**Status:** DRAFT, revision 6. James's product decisions are recorded (2026-11-01, chat); awaiting spec approval. No wire, agent or UI code until the spec is approved.

Written spec-first at James's direction (chat, 2026-10-11). Revisions 2–5 address the review threads on PR #290 (Codex reviews of `35b2f22`, `ebd62fc`, `6039379`, `2fe7629` and `ee6c125`, and the `usjbro` review). Each decision says which finding it answers. Where a number is a judgment, it says why, so the reviewer can change it without archaeology.

## Problem

Packets are viewable one at a time. Nothing joins a conversation's bytes. JAM-16's reassemblers cannot be reused as the store: `StreamReassembler` holds 16 KiB per direction (`MAX_TCP_STREAM_BYTES`) and **releases a direction's buffer the moment an L7 detector decides**. It is an L7-decision buffer, not a conversation store, and its own spec says Follow Stream "will want its own bounded store".

## The privacy fact that shapes everything

Holding conversation bytes means holding the cleartext payload of real traffic in agent memory for longer than anything does today. Today the agent keeps payload only transiently for an L7 decision, and emits a sampled, rate-limited `hexDump` per packet (100 events/s). A conversation store is a different class of retention. So retention is **opt-in**, consistent with the repo's other opt-in features (TLS decryption, ownership and GeoIP enrichment, capture-to-file). Nothing is retained, and the request answers "not enabled", unless the operator turned it on.

## What this spec does and does not promise

Stated up front because two review findings were about promises the first draft could not keep.

- **Promised:** stored and displayed bytes are exactly what was captured, minus what this spec masks or withholds; gaps, truncation, store caps and classification uncertainty are always shown, never elided; content is delivered only to the requester, only through the gated relay route; the store is bounded in memory and zeroized on every release path.
- **Not promised:** that every encrypted stream is recognized. TLS is recognized structurally and best-effort (D3). Other encryption (SSH after its banner, custom protocols) is shown as bytes, escaped. The view never describes content as "readable" or "decrypted"; it says "bytes as captured".
- **Not promised:** that every credential is masked. Only HTTP/1.x-style credential header lines are masked (D7), conservatively. Bodies and non-HTTP credentials (FTP `PASS`, SMTP `AUTH`, Telnet) are visible. This is a named limitation.

## Decisions

### D1. Retention is opt-in at agent startup — **decided (James, 2026-11-01)**

`FOLLOW_STREAM=1` (agent environment, read once at startup, like the other opt-ins). When off: no store is allocated, `get_stream` answers `enabled: false`, and the UI button explains how to enable it. When on: the agent retains the **head** of each TCP flow that is not classified as TLS (D2, D3).

Alternatives considered:
- **Per-flow "arm" at click time.** Smaller retention footprint, but not retroactive: the operator clicks a flow that is already mid-conversation and sees only what follows, so the headline case ("read that HTTP request I just saw") fails. Rejected as the default; it could be added later as a narrower mode.
- **Always on.** Rejected: it silently changes what the agent holds in memory for everyone.

### D2. The store: head-keeping, per direction, with explicit gaps

New module `capture-agent/src/follow.rs` (`FollowStore`). Separate from `StreamReassembler`; shares the flow identity (`FlowTable::key_for`, so the two can never disagree about flow or direction) and, where clean, the sequence-delta arithmetic and first-seen-bytes-win overlap policy (JAM-16 rationale: the monitor's view of already-reported bytes must be immutable; conflicting overlaps are counted).

Per retained flow, per direction:
- **Contiguous stored bytes** from the stream start, plus an ordered list of **gaps**. A gap is `{ at: stored offset, missing: u32, reason }` and records an exact sequence-space hole size (known from the sequence delta), never a guess.
- **Out-of-order window:** bytes ahead of the contiguous edge are held for at most 64 KiB and 2 s of *capture time*. After that the hole is declared a gap and the stream continues past it.
- **Gap reason** (answers the snaplen-attribution finding): the production signal is the pre-parse one. `main.rs::note_capture_truncation` already compares captured with original frame length before `parse_packet` and calls `StreamReassembler::note_frame_cut_at_snaplen`. It calls the same notifier on `FollowStore`, which keeps its own `last_frame_cut_at_ms` with the same `CUT_ATTRIBUTION_WINDOW_MS`. A gap declared while that window is open gets reason `snaplen_likely`, otherwise `missing`. "Likely" is deliberate: a frame cut short enough to fail parsing never reaches the store, so the cut cannot be tied to this flow; the attribution is capture-wide and time-based, exactly as JAM-16's is. The IP declared-length check from revision 1 is dropped as the primary signal because such frames are discarded before reassembly.
- **Head-keeping caps, never a rolling window.** When a direction reaches a cap the store stops appending, keeps counting `seen_bytes`, and reports why (`store_cap`, `gap_limit`, `turn_limit`, `redaction_limit`). A rolling window would silently discard the start of the conversation and make the view change under the reader.
- **Turns:** an ordered list of `{ dir, start, len, firstSeenMs }` per flow, coalescing consecutive same-direction runs. Capped; at the cap the store stops appending for both directions (`turn_limit`) rather than coalescing further, because coalescing would misstate the interleave.
- **Generation** (answers the stale-continuation finding): each retained entry gets `generation = (store_epoch, counter)`. `store_epoch` is 64 random bits drawn once at agent start (`ring::rand::SystemRandom`, already a dependency); `counter` is a `u64` incremented for every new entry, including a new flow that reuses an evicted flow's tuple and every entry created after an interface reset. `FlowKey::connection_id()` is protocol plus endpoints only, so it cannot tell a replacement flow from the original; the generation can.

| Cap | Value | Why |
|---|---|---|
| Per direction, data | 256 KiB | A full HTTP exchange with a modest body; 16× the L7 buffer. Past this the view is a head, labelled as one. |
| Per direction, gaps | 1 024 entries | A conversation with more holes than this is not readable anyway; stops a one-byte-gap flood from growing metadata. |
| Per direction, redacted ranges | 1 024 entries | Bounds D7's metadata. At the cap the store stops appending (`redaction_limit`) rather than storing unmasked bytes. |
| Per flow, turns | 4 096 entries | Same reasoning as gaps. |
| Retained flows | 256 | A reader follows a handful of flows; far below `DEFAULT_MAX_FLOWS` (10 000). |
| Global | 16 MiB | **Counted in reserved capacity** (data chunks, gap, turn and range vectors, coverage maps), not length, per checklist §1. The global cap binds first and is the real limit. |
| Out-of-order window | 64 KiB / 2 s capture time | Bounds a hostile sender that never fills a hole. |

**Storage layout.** Data is stored in fixed 16 KiB chunks allocated on demand, never in one growing `Vec`, so growth never reallocates and copies sensitive bytes into memory that is then freed unzeroized (D7a). Metadata vectors are allocated at their cap's size on first use for the same reason.

**Eviction:** tied to flow lifetime. A flow's entry is dropped when `FlowTable` evicts it (idle or capacity) and, under global-cap pressure, oldest-closed-first then oldest-idle. An evicted flow answers `found: false`, which is not the same as "empty". Timeouts run on the replay-aware clock (`ReplayClock`), never wall time (checklist §5). An interface switch clears the store (JAM-183 precedent); a pause stops feeding it without clearing. Every release path zeroizes (D7a).

**Fragment-reassembled TCP** feeds the store through the same path JAM-167 already routes it through, so a segment that arrived in IP fragments is not a spurious gap.

**Flow start not captured:** if the first segment seen has neither SYN nor a known start, `flowStartCaptured: false` and the view says so. It never presents a mid-stream start as a beginning.

### D3. TLS classification, and what is withheld while it is uncertain

Answers the two TLS findings (midstream application data, SNI-less ClientHello, STARTTLS/CONNECT upgrades). Revision 1's rule ("first client bytes are a ClientHello") is replaced.

**Classifier.** A new structural probe in `follow.rs`, independent of `l7.rs::sniff_tls_client_hello` (which requires a ClientHello and returns `None` without SNI, so it is unsuitable here). A *valid TLS record header* is: content type in {0x14, 0x15, 0x16, 0x17}, legacy version `0x03 0x01`–`0x03 0x04`, and length ≤ 18 432 (2^14 + 2048, RFC 8446 §5.2's maximum ciphertext record). A direction is classified **TLS** when either:
1. its stream starts with a valid header of type 0x16 whose first handshake byte is 0x01 (ClientHello) or 0x02 (ServerHello), with or without SNI; or
2. a **chain** is found: two consecutive valid record headers where the second starts exactly at `first_offset + 5 + first_length`. Candidate first headers are tried at every offset in the first 20 KiB of the direction's bytes (or of the bytes after an upgrade point), so a capture that begins in the middle of a record resynchronises on the next record boundary, which must occur within 18 437 bytes. Confirming the chain can need one more full record, so the classifier looks at up to **40 KiB**. Split headers are handled because the probe runs over the reassembled contiguous bytes, never one segment.

A flow is TLS when either direction is.

**States per direction:** `pending` → `cleartext` or `tls`.
- **`pending`:** the first bytes are stored but **not emitted**. The response reports `classification: "pending"` and returns no data for that direction. A direction leaves `pending` when it is classified TLS, or when 40 KiB have been seen, 2 s of capture time have passed or the direction has closed with no chain found (→ `cleartext`). The UI shows "classifying…", never bytes.
- **`tls`:** every stored byte of the flow is zeroized and released, nothing more is stored, `seenBytes` keeps counting, and the response says `classification: "tls"` with no data. The view says "this is TLS — content is encrypted" and names `bin/osi-inspect.js` as the only supported way to see inside.
- **`cleartext`, then an upgrade:** after a direction is `cleartext`, every newly contiguous offset is still checked for a valid record header (a constant-time 5-byte test; in text, bytes 0x14–0x17 followed by `0x03 0x01`–`0x03 0x04` are rare, so false suspicion is uncommon and only delays emission). A valid header makes the bytes from that offset **suspect**: they are stored but withheld from emission until the chain is confirmed (→ upgrade) or refuted (the bytes after the claimed record length do not chain, or 2 s of capture time pass). On confirmation at offset *k*: bytes before *k* stay as cleartext; bytes from *k* on are zeroized and dropped; the direction records `tlsFrom: k`; nothing further is stored for the flow; and the view shows `── switched to TLS at byte k (STARTTLS / CONNECT / upgrade) — later content is encrypted ──`. Because suspect bytes are withheld until decided, ciphertext after an upgrade is not emitted before detection.
- **Partial header holdback:** a record header can be split across arrivals, so up to the last 4 bytes at the contiguous edge are withheld whenever they could still be the start of a valid header (first byte in 0x14–0x17; then `0x03`; then `0x01`–`0x04`; then a length high byte ≤ 0x48, since 18 432 = 0x4800). They are released only when later bytes refute the prefix, or when the direction closes; if the prefix completes into a valid header, the suspect rule above takes over. A browser request arriving between the two halves of a header therefore never receives its first bytes.

**Residual risk, stated:** an encrypted protocol that is not TLS, TLS whose record boundaries are never seen within the window, or a TLS direction that sends a single record while the other direction is never seen, is classified `cleartext` and shown as escaped bytes. This is why the promise in "What this spec does and does not promise" is narrowed.

`decrypted_payload` and its `DecryptedStore` stay entirely separate. Follow Stream **never reads from them and never merges with them**; a flow that has decryption active still shows the "encrypted" explanation here, plus a pointer to where decrypted segments already render (`PacketStreamView`). `lib/decrypted-payload-gate.ts` is not modified, and the existing `decrypted-export-exclusion` test must keep passing untouched.

### D4. Wire: request/response over a relay HTTP route, never the SSE feed — **wire change, ask-first under AGENTS.md**

Stream content must not be pushed onto the SSE feed. Every connected browser tab receives that feed; broadcasting a conversation to all of them turns "one operator looked at one flow" into a fan-out.

**New relay machinery, stated plainly.** Today `AgentClient.sendControl` (`lib/agent-client.ts`) is fire-and-forget: it returns `void`, writes straight to the socket, and has no request/response correlation and no backpressure. Follow Stream needs both, so this is new design, not a filter on existing plumbing.

- **Browser → relay:** `POST /api/follow-stream` with `{ connectionId, generation?, c2s: { offset }, s2c: { offset }, turnsFrom }`. The route applies `rejectIfCrossSite` first (as `/api/control` and `/api/enrichment/lookup` do), validates types and bounds (`connectionId` ≤ 128 chars; offsets non-negative integers ≤ the per-direction data cap; `turnsFrom` a non-negative integer ≤ the per-flow turn cap, default 0), applies the content gate (D6), then admission control (D4a).
- **Relay → agent:** a new control message `get_stream` with a relay-generated `requestId` (128-bit random, hex) plus the same fields. `ControlMessage` gains `GetStream` (Rust `wire.rs`). `app/api/control/route.ts`'s allowlist is **not** extended: this message is only ever sent by the new route.
- **Agent → relay:** a new event `stream_data` carrying the same `requestId`. A new `AgentClient.request()` path keeps a pending map keyed by `requestId`, and the line reader **intercepts `stream_data` before `emit('event')`**, so it never reaches any SSE listener. `lib/stream-response.ts` also drops `stream_data` defensively, so a future refactor of the interception cannot leak it. A `stream_data` whose `requestId` is unknown (late, cancelled or forged) is dropped and counted, never forwarded.

**Generation handling.** The first request omits `generation`. Every response carries `generation` (`"<epoch hex>:<counter>"`). Continuation requests must send it back. If it does not match the entry currently held for that `connectionId`, the agent answers `stale: true` with no data, and the client discards everything it accumulated and restarts from offset 0 without `generation`. Raw save is only offered for an accumulation that is entirely from one generation.

**Response shape and encoded bound** (answers the metadata-size finding). The agent builds each response against a hard ceiling on the **whole encoded line**: `MAX_STREAM_DATA_LINE = 192 KiB`, including base64 and every metadata array. Per response, per direction: at most 32 KiB of stored bytes (≈ 43.7 KiB base64), at most 128 gap entries and 128 redacted-range entries; per response at most 256 turns. Worst case ≈ 85.3 KiB data (2 × 43 692 B) + 15.0 KiB gaps (2 × 128 × ~60 B) + 10.0 KiB ranges (2 × 128 × ~40 B) + 17.5 KiB turns (256 × ~70 B) ≈ 128 KiB, under the ceiling with margin; the per-entry sizes are estimates and the agent's pre-write assertion, not this arithmetic, is the guarantee. **Metadata is never dropped to fit**: if a direction's window would contain more gaps or ranges than the per-response limit, the data window is shortened to end at the last offset whose metadata fits, and `nextOffset` says where to continue. Turns page separately: both requests (browser → relay and `get_stream`) carry `turnsFrom`, the response returns at most 256 turns starting there plus `turnsNext` (the next index, or `null` when none remain), and the client keeps requesting until `turnsNext` is `null`. Data and turn paging are independent, so a client can finish one before the other.
- **The final turn is mutable.** During live capture, more same-direction bytes extend the last turn's `len` without changing its index. So every response also carries `lastTurn` (`{ index, dir, start, len, firstSeenMs }`, the current final turn, regardless of `turnsFrom`), and the client replaces its stored turn at that index on every response. A turn is immutable only once a later turn exists **and** the client has fetched it after that point; the turn the client last held as final may have grown before being superseded. So whenever `lastTurn.index` is beyond the last index the client holds, the client resumes turn paging from **its last held index** (count − 1), not from its count, replacing that turn with the returned version, and continues until `turnsNext` is `null`. Together this keeps the accumulated turns covering every byte the client has fetched. Tests: append same-direction bytes between data page requests after turn paging has finished; and grow the client's last held turn, then add a turn in the other direction, before the next request (direction change between requests); each asserts the client's turns cover all fetched bytes with correct lengths. The agent asserts the encoded length before writing; the relay rejects a `stream_data` line over the ceiling (fails the request with 502) instead of buffering it further.

```json
{
  "type": "stream_data",
  "requestId": "9f2c…",
  "connectionId": "Tcp-192.168.1.10:51000-93.184.216.34:80",
  "enabled": true, "found": true, "stale": false,
  "generation": "4be1a07c9d22f310:17",
  "flowStartCaptured": true, "closed": false,
  "directions": {
    "clientToServer": {
      "classification": "cleartext", "tlsFrom": null,
      "offset": 0, "nextOffset": 412, "storedBytes": 412, "seenBytes": 412, "stoppedReason": null,
      "gaps": [], "conflictingOverlapBytes": 0,
      "redactedRanges": [{"start": 187, "len": 22, "reason": "credential"}],
      "dataBase64": "R0VUIC8..."
    },
    "serverToClient": {
      "classification": "cleartext", "tlsFrom": null,
      "offset": 0, "nextOffset": 900, "storedBytes": 1530, "seenBytes": 2990, "stoppedReason": null,
      "gaps": [{"at": 900, "missing": 1460, "reason": "missing"}],
      "conflictingOverlapBytes": 0, "redactedRanges": [], "dataBase64": "SFRUUC8x..."
    }
  },
  "turnsFrom": 0, "turnsNext": null,
  "lastTurn": {"index": 1, "dir": "s2c", "start": 0, "len": 900, "firstSeenMs": 160},
  "turns": [{"dir": "c2s", "start": 0, "len": 412, "firstSeenMs": 120}, {"dir": "s2c", "start": 0, "len": 900, "firstSeenMs": 160}]
}
```

- **Extending, not breaking:** unknown fields and enum values are ignored by the mapper; unknown `reason` / `dir` / `classification` values map to a visible "unknown" rather than throwing (checklist §6).
- Updated together, per the repo's wire rule: `capture-agent/src/wire.rs`, `lib/types.ts`, `lib/agent-mapping.ts`, `docs/wire-protocol.md`, tests on both sides.

### D4a. Admission control and backpressure

Answers the aggregate-pending-work finding. A per-tab rule cannot bound a server: the request carries no tab identity, and other tabs or direct HTTP callers do not follow UI conventions. So limits are enforced in the relay and the agent, and the per-tab "one request at a time" rule remains only as UI behaviour.

**Relay** (`AgentClient` plus the route):
- At most **4** `get_stream` requests in flight relay-wide, and at most **1** per `connectionId`. Beyond either, the route answers **429** immediately and allocates no pending state.
- Before writing a request, the relay checks the agent socket's `writableLength`; above 64 KiB it answers **503** instead of queueing. `request()` honours `socket.write()`'s return value and never queues more than one unsent `get_stream`.
- Each pending entry is removed on exactly one of: the matching response; a **5 s** timeout (504); agent disconnect or re-authentication (all pending fail with 503); or the HTTP request's `AbortSignal` (client gone, entry removed, a late response is dropped as unknown). Pending state is therefore bounded by 4 entries plus at most 4 × 192 KiB of response being parsed.

**Agent:**
- `get_stream` is answered synchronously from memory with bounded work (one response ≤ 192 KiB, built into one reusable buffer). The agent tracks unflushed `stream_data` bytes on the relay connection; if they exceed 512 KiB, or 4 responses are still unflushed, it answers `{"busy": true}` (relay → 503) instead of building another.
- `stream_data` is never subject to the packet-event rate limiter (that would drop responses), and it does not count against the 100/s discrete-event budget.

**Tests that ignore the UI convention:** 20 concurrent `fetch`es to the route with a fake agent (≤ 4 forwarded, the rest 429, one per `connectionId`); timeout cleanup; abort cleanup with a late response; disconnect failing all pending; a slow-reading fake agent driving the 503 path; agent-side `busy` when unflushed bytes exceed the threshold.

### D5. Live and replay

Works on any flow the store retains, live **and** replay (`REPLAY_FILE`), since the store is fed from the packet path both share. That also makes the feature deterministic to test end to end. It does **not** read capture files by itself; reading a recorded file's streams on demand is the JAM-255 query-service question (D9).

### D6. Gating and the cleartext content boundary

The relay applies a gate to `/api/follow-stream` that is **the same predicate** as `isDecryptedPayloadAllowed` (direct loopback, or a verified mTLS header via Caddy), implemented as a new function `isStreamContentAllowed` in its own module so a test can prove parity and so decrypted content and cleartext stream content cannot silently become one switch. It does not modify `lib/decrypted-payload-gate.ts`.

Honest limit: JAM-255's review notes that an absent mTLS header on the local path is not caller authentication, and JAM-196 (authenticated callers) is open. Follow Stream inherits that limit as `decrypted_payload` and the packet `hexDump` do. A full conversation is more content than a sampled packet, so **D1's opt-in is the real control, and JAM-196 is a recommended prerequisite for enabling this on a LAN**. Say so in `docs/security.md`.

### D6a. Recapture of the relay's own responses — **decided: option A (James, 2026-11-01)**

Answers the recapture finding. When the capture interface is loopback, the relay's HTTP response to `/api/follow-stream` (and the Caddy → relay hop on a LAN deployment, which is loopback plaintext) crosses the captured interface. Today `exclude_live_control_capture` (`main.rs`) excludes only `127.0.0.1:9990`, so those response bytes would re-enter the pipeline: sampled `packet` events carry payload in `hexDump`, which `lib/stream-response.ts` forwards to every SSE viewer without the content gate, and `FollowStore` would ingest them as a new conversation. The SSE feed itself is already recaptured this way today, which is pre-existing and harmless-looking, but conversation content is not.

Delivering content only through the HTTP route does **not** fix this by itself: the route's response is the recaptured traffic. One of these is needed:

- **Option A (recommended): exclude the relay transport at the same point as port 9990.** The agent reads `RELAY_PORT` (default 3000, the port `next dev` / `next start` use unless `PORT` is set; it must be configured identically in both processes, the same rule JAM-184 applies to `AGENT_TOKEN_FILE`). `exclude_live_control_capture` also matches TCP between loopback addresses where either port is `RELAY_PORT`. It runs where the existing exclusion runs: "before reassembly, flow/payload events and raw recording" (`main.rs`, the comment at the call site), in live mode, so the bytes never reach packet events, `FollowStore` or a capture file. Cost: on a loopback capture the UI's own traffic stops appearing as flows (it is noise to the operator anyway).
- **Option B: disable Follow Stream on loopback captures.** While the active interface is loopback, `get_stream` answers `unavailable: "loopback capture"` and the store is not fed. Simpler and needs no port configuration, but it removes the feature from the most convenient local test setup, and it does not cover a LAN deployment that captures loopback.

Either way, an end-to-end test captures loopback with the relay running, requests a stream containing a sentinel string, and asserts that no `packet` event, no `FollowStore` entry and no capture file contains the sentinel.

### D7. Redaction: stream-relative, conservative, same-length — **decided (James, 2026-11-01)**

Answers the redaction-before-slicing and fail-closed-on-gaps findings. Revision 1 scanned only the bytes about to be emitted, which leaks when a page or request offset starts inside a header line. Revision 2 computes masks over the **stored stream at ingest**, records them as stream-relative ranges, and intersects them with each page at emission.

**Scanner.** A per-direction line scanner runs incrementally over newly contiguous cleartext bytes (it never runs on `pending`, `tls` or suspect bytes). It is line-based over the whole stream rather than header-block-aware, so it needs no HTTP message framing: over-masking a body line that looks like a header is accepted as the safe direction.

A *header-candidate line* is a line whose bytes so far are HTTP token characters followed by `:`. It stops being a candidate as soon as a non-token character appears before `:` (so a JSON body starting `{` is visible immediately).
- **Masked value:** for a complete header line whose name matches `is_sensitive_header_name`, or whose value matches the bearer-token shape (`looks_like_bearer_token`, widened to `pub(crate)`), the value bytes (after `:` and optional whitespace, up to but not including CR/LF) are recorded as a range with reason `credential`.
- **Folded (obs-fold) headers are masked conservatively.** A line starting with SP or HTAB directly after a header-candidate line is a continuation of that header (RFC 9112 §5.2). Because the credential can sit entirely in the continuation (`X-Custom-Auth:` then ` Bearer secret`), whenever a continuation follows, the **whole logical value is masked**: the value part of the first line and every continuation line, with reason `credential`, regardless of name or shape. obs-fold is obsolete and rare, so over-masking is the cheap direction. To make this decidable, a header-candidate line's value is withheld at emission until the first byte of the following line is seen (or the direction closes), because only then is it known whether a continuation follows. This works across segments because the scanner runs over contiguous stored bytes and carries its state.
- **Fail closed on gaps:** any line that touches a gap, on either side of it, is masked entirely with reason `uncertain`. After a gap, bytes up to the next LF are masked because the line's start, and therefore its name, is unknown. The same applies at a `store_cap` or `turn_limit` edge and at an upgrade point (D3).
- **Fail closed at an uncaptured start:** a direction whose beginning was not captured (`flowStartCaptured: false`, D2) is treated as if there were a gap at stored offset 0: the scanner starts in the `uncertain` state and masks up to the first LF, so a capture that begins inside `Authorization: Bearer secret` cannot show `rer secret`. Only a direction whose first stored byte is the first data byte after its SYN starts in the normal state.
- **Uncertainty carries through continuations.** An `uncertain` line (after a gap, at an uncaptured start, at a cap edge or upgrade point) may be the first line of a folded header, so the mask does not end at its LF: every immediately following line that starts with SP or HTAB is masked too (`uncertain`), and uncertainty ends only at a line whose first byte is neither. As with header lines, an uncertain line is not released until the first byte of the next line is seen (or the direction closes), because only then is it known whether a continuation follows. Each line keeps the 16 KiB bound.
- **Unfinished lines:** a header-candidate line that has no terminator yet is withheld at emission until it ends, and is then classified. A post-gap or candidate line longer than 16 KiB without a terminator stays masked to its end (headers are limited to 8 KiB by common servers; 16 KiB leaves margin). A gap-uncertain mask that runs past 16 KiB without LF ends there, so a binary or newline-free body after a gap is not hidden entirely; this is a stated trade-off, not an oversight.
- **Bounded:** at most 1 024 ranges per direction, adjacent ranges coalesced. At the cap the store stops appending (`redaction_limit`) rather than store bytes it cannot mask.

**Emission.** For each page the agent copies the stored bytes, overwrites every byte inside an intersecting range with `*` at the same length, and returns the intersecting ranges (clipped to the page) in `redactedRanges`. Same length keeps offsets, gaps and hex views consistent. The store keeps the original bytes; masking happens on the copy (checklist §4, "redacted before emission").

**Tests:** credential header split across two pages at every byte offset; a request whose `offset` lands inside a credential value; folded continuations, including `X-Custom-Auth:` with an empty first line and ` Bearer secret` as the continuation, delivered in separate segments with a fetch between them; a capture starting at every offset inside a header name and inside a value (`flowStartCaptured: false`); an uncaptured start and a gap each followed by folded continuation lines carrying the credential (`abc\r\n secret\r\n`); a gap through the name, through the value, and just before the line; bearer under an unlisted name; a JSON body that must stay visible; a header-like body line that is (acceptably) masked; the 16 KiB unterminated cases; range-cap behaviour.

**Named limitations, unchanged in kind:** bodies are never redacted; non-HTTP credentials are visible. The UI shows "content is shown as captured; only credential header lines are masked" on every cleartext view. Escaping is not redaction. Raw save and hex mode emit the masked bytes. There is no "reveal" in v1.

### D7a. Zeroization — mandatory

Answers the zeroization finding. The store deliberately keeps original credential bytes (D7), so every path that releases them zeroizes first:
- capacity eviction, idle eviction, eviction tied to `FlowTable` eviction, global-cap pressure;
- interface reset, TLS classification or upgrade (D3), and `FOLLOW_STREAM` store teardown on shutdown (`Drop` zeroizes every chunk);
- the per-response emission buffer (raw copy, masked copy and base64 string) after the line is written.

Data chunks and emission buffers use `zeroize::Zeroizing` (the crate is already a dependency). Fixed-size chunks (D2) mean growth never leaves an unzeroized copy behind. `FollowStore` and its entry types implement a **redacting `Debug`** (no derived `Debug`); no stored byte appears in a log line, panic message, status event or error string.

**Test seam:** a `#[cfg(test)]` release hook receives each chunk just before deallocation; tests assert it is all zeros for every path above. Documented limit, added to `docs/security.md`: the relay is JavaScript, and the response bytes it parses and forwards live in V8 strings and buffers that cannot be reliably zeroized; they are short-lived and never stored.

### D8. Scope: TCP only

UDP and QUIC are out of scope for v1. The issue's title names UDP, but its acceptance criteria and every dependency are TCP/HTTP, and UDP has no stream identity or ordering to follow. IPv6 TCP is in scope to the extent the flow table keys it.

### D9. Live vs recorded — relationship to JAM-255 — **decided (James, 2026-11-01)**

This spec delivers **live-and-replay** Follow Stream only. JAM-255's proposal would add recorded Follow Stream and notes that it needs "a separate, bounded reassembly contract preserving direction, gaps, conflicts and truncation". The `stream_data` contract above (per-direction bytes, gaps with reasons, conflicts, truncation, classification, generations) is deliberately source-agnostic so a recorded source could fill the same contract later. Nothing here depends on JAM-255 being adopted.

### D10. Rendering safety (the browser side)

New pure module `lib/stream-render.ts` (no React), unit-tested with a hostile fixture before any component exists.

- Bytes are never interpreted as markup. The component renders text through React text nodes only; `dangerouslySetInnerHTML` is forbidden for this view, and a test greps for it.
- **Text mode** decodes as UTF-8; each invalid sequence is shown as `\xNN`. Then it applies one **character policy**, defined by Unicode general category rather than an enumerated list (answers the missing-characters finding): every code point in `Cc` (controls) except LF and TAB, `Cf` (format), `Zl`, `Zp`, `Co` (private use), `Cs` (surrogates, only reachable through bad input) and `Cn` (unassigned), plus variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF), is shown as a visible escape (`\u{061C}` style) instead of being rendered. `Cf` covers U+00AD SOFT HYPHEN, U+061C ARABIC LETTER MARK, U+200B–U+200F, U+202A–U+202E, U+2060–U+2064, U+2066–U+2069, U+FEFF and the tag characters U+E0000–U+E007F. CR is shown visibly. ESC is in `Cc`, so ANSI/CSI/OSC sequences are inert. Implemented with Unicode property escapes (`/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}\p{Cn}]/u` minus LF/TAB, plus the variation-selector ranges).
- **One policy, shared:** `lib/osi-mon-client.ts`'s `safe()` covers less than this. The implementation moves the policy into a shared module used by both. That also overlaps JAM-260 item 3 (rewriting `safe()`'s class with `\u` escapes); whichever lands second rebases onto the shared module.
- **Hex mode:** offset, hex bytes, and an ASCII column where every byte outside 0x20–0x7E is `.`.
- **Render cap:** at most the 256 KiB per-direction store cap is ever rendered; "load more" appends pages. Long unbroken lines wrap (`overflow-wrap: anywhere`).
- **Gaps, masks and states are first-class rows**, never elided: `── 1460 bytes not captured (frames missing) ──`, `── 380 bytes not captured (snap length likely too small — raise it with snaplen) ──`, `── stored head only: 256 KiB of 1.4 MiB seen ──`, `── switched to TLS at byte 812 — later content is encrypted ──`. Masked bytes render as `*` with a distinct style and a tooltip giving the reason (`credential` or `uncertain`).
- **Raw save** downloads the already-fetched, masked bytes as a `Blob` from the browser, only for a single-generation accumulation, with a fixed filename (`stream-<n>.bin`) and `application/octet-stream`, never derived from captured content. The agent writes no file and the relay serves none.

**Fixtures:** ESC `[2J`, OSC 8 hyperlink, CR overwrite, NUL, each bidi control including U+061C, U+00AD, U+2060, U+200B, U+FEFF, a tag sequence, a variation selector, private use, invalid UTF-8, `<script>`, `</div>`, and a very long line; each asserts the escaped output and that no DOM element is created from payload.

### D11. UI

A "Follow Stream" button in `ConnectionsView`'s selected-connection panel, next to "Trace Route" (same affordance, same on-demand rule: never automatic). The view is direction-coloured (client and server distinct, with a `→` / `←` prefix so it does not depend on colour alone), has Text / Hex / Save, and a header banner with exactly these states (wording lives in one place, in the spirit of `ReassemblyStatus::label()`): `complete so far`, `gaps: frames missing`, `gaps: snap length likely too small`, `head only` (with the stop reason), `flow start not captured`, `classifying…`, `encrypted (TLS)`, `switched to TLS`, `not enabled`, `no longer retained`, `restarted: flow was replaced` (stale generation), `busy, try again`. `app/page.tsx` gains one handler; it does not take over state ownership.

## Acceptance criteria → how each is met and tested

| Criterion | Mechanism | Test |
|---|---|---|
| Cleartext HTTP readable end to end, directions distinguished | D2 store, D10 text mode, D11 colour + glyph | Rust: request/response across segments in and out of order; TS: render fixture; real-browser run against a replay of an HTTP pcap |
| Gaps and truncation never silently elided | D2 gaps with reasons and stop reasons, D10 rows | Rust: hole, snaplen-cut frame within and outside the window, each cap and cap + 1, out-of-order timeout; TS: every row kind renders |
| Control chars and escape sequences cannot affect the page | D10 | Fixtures listed in D10 |
| Encrypted flows explain themselves | D3 | Rust: ClientHello with and without SNI; capture starting at a 0x17 record; capture starting mid-record; TLS header split across segments; SMTP STARTTLS; HTTP CONNECT then TLS, with the first TLS header split at each of positions 1–4 and a fetch between the halves; a cleartext stream that must not be misclassified. Each asserts no TLS byte is ever emitted and stored TLS bytes are zeroized |
| Decrypted content stays gated, existing tests pass | D3, D6 | `decrypted-payload-gate` and `decrypted-export-exclusion` tests run unmodified; new parity test for `isStreamContentAllowed`; a test that the follow path has no import from the decrypted store |
| (added) Content never reaches other viewers | D4, D6a | `stream_data` never emitted to SSE listeners; recapture sentinel test (D6a) |
| (added) Server work is bounded | D4, D4a | Encoded-line ceiling test with maximal metadata; the concurrency tests in D4a |
| (added) All metadata is retrievable | D4 paging | End-to-end retrieval of a flow with more than 256 turns and more than 128 gaps per direction, asserting every turn and gap arrives exactly once |
| (added) Continuations cannot mix flows | D2 generation, D4 | Evict and replace a flow with the same tuple between pages; interface reset between pages; both answer `stale` and the client restarts |

## Security-plan review (checklist `docs/security-plan-review-checklist.md`)

Marked from this design; the implementing PR must re-mark them against the diff. Not verified: no code has run; the caps and the 192 KiB ceiling arithmetic are reasoned, not measured. Verified by reading source at `f4239b6`: `key_for`, `ReplayClock`, `note_capture_truncation` and `note_frame_cut_at_snaplen`, the call site and comment of `exclude_live_control_capture` (9990 only, before reassembly, events and recording, live only), `rejectIfCrossSite` on the existing on-demand routes, the `decrypted_payload` filter in `lib/stream-response.ts`, `AgentClient.sendControl` (fire-and-forget, no correlation, no backpressure), the absence of an event-line cap in `lib/agent-client.ts`, `sniff_tls_client_hello`'s ClientHello-and-SNI requirement, `FlowKey::connection_id()`'s tuple-only format, and the private `looks_like_bearer_token`.

| § | Item | Status |
|---|---|---|
| 1 | Lengths checked before allocation; capacity-counted per-stream, per-flow and global bounds; overlap policy; wraparound | Pass (design): D2 caps including metadata caps, fixed chunks, first-seen-wins, `i32` sequence delta; TLS record length ≤ 18 432 checked before any use; request fields bounded at relay and agent. |
| 1 | No unbounded loops | Pass (design): classifier search bounded to 20 KiB of candidate offsets and 40 KiB of lookahead per direction or upgrade point; scanner line limits of 16 KiB; response building bounded by the encoded ceiling. |
| 2 | Failure classes, fail closed, per-direction state | Pass (design): gaps, caps and limits are terminal for those bytes and shown; `pending` and suspect bytes are withheld; gap-adjacent lines are masked (`uncertain`); classification and redaction state are per direction. On-path attacker: injected overlap (first-seen-wins), never-filled holes (window), flow floods (global cap), fragment-heavy streams (gap cap), many credential lines (range cap), crafted TLS-looking bytes (worst case: a cleartext flow is dropped as TLS — loss of visibility, not disclosure). |
| 3 | Cryptography | Not applicable: no decryption, no keys. |
| 4 | Secrets and sensitive data | Pass (design): opt-in (D1); masked on emission from stream-relative ranges (D7); zeroized on every release path with a test seam and redacting `Debug` (D7a); never written to disk; never logged. Limits named: bodies and non-HTTP credentials visible; JS-side buffers not zeroizable. |
| 5 | Time | Pass (design): replay-aware clock for the window, classification timeout, suspect timeout and snaplen attribution; relay request timeout is wall time, which is correct for an HTTP request. |
| 6 | Interfaces | Pass (design): Rust, docs, `lib/types.ts` and `lib/agent-mapping.ts` change together; unknown values do not throw; `stream_data` is request-scoped, intercepted before the SSE emitter, size-capped and admission-controlled (D4a); content is gated (D6) and excluded from recapture (D6a). |
| 7 | Tests and tooling | Required: tests first and shown failing; boundaries (cap, cap + 1, zero) for every cap; the fixtures in D3, D7, D10; the concurrency tests in D4a; a `cargo-fuzz` target `follow_store` that feeds arbitrary segments, gaps and TLS-like bytes and asserts the byte and metadata caps, the encoded ceiling and that no `tls`/`pending` byte is ever emitted, wired into CI's hand-listed fuzz steps and path filter; `security-review` before push. |

## Non-goals

No verdicts about whether traffic is normal or malicious (epic non-goal). No search, no export beyond Raw save, no HTTP body parsing or decompression, no object extraction (JAM-209), no UDP/QUIC, no recorded-file source (JAM-255), no persistence of any kind, no detection of non-TLS encryption.

## Decisions recorded

James agreed with every recommendation in chat on 2026-11-01. Recorded here so the implementation plan does not reopen them:

1. **D1 retention:** opt-in at agent startup with `FOLLOW_STREAM=1`. No per-flow arm mode and no always-on mode in v1.
2. **D7 redaction:** conservative same-length masking of credential header lines as specified. Bodies and non-HTTP credentials (FTP `PASS`, SMTP `AUTH`, Telnet) stay visible and are labelled as such; masking for those protocols is a possible follow-up, not v1.
3. **D9 scope:** live and replay now. Recorded-file Follow Stream is left to the JAM-255 decision.
4. **D2 caps:** 256 KiB per direction, 256 retained flows, 16 MiB global, as constants that can be tuned later.
5. **D6 / JAM-196:** document the caller-authentication limit now (in `docs/security.md`), and do not enable Follow Stream on a LAN deployment until JAM-196 (authenticated relay callers) is done. Local loopback use relies on the D1 opt-in.
6. **D6a recapture:** option A. The agent excludes loopback TCP on `RELAY_PORT` (default 3000) at the same point it excludes port 9990. Option B is not adopted.

## Revision log

- **Revision 6** (this): James's decisions on the six open questions recorded (2026-11-01); D6a set to option A; D6 records the LAN policy pending JAM-196. No design change.
- **Revision 5** (`1100291`): from the Codex review of `ee6c125`: turn paging resumes from the client's last held index, so a final turn that grew before being superseded is refreshed (D4).
- **Revision 4** (`ee6c125`): from the Codex review of `2fe7629`: `uncertain` masking carries through folded continuation lines after gaps, uncaptured starts and other uncertain points (D7); the mutable final turn is returned as `lastTurn` on every response and replaced by the client (D4).
- **Revision 3** (`2fe7629`): from the Codex review of `6039379`: `turnsFrom` added to both request contracts with an end-to-end >256-turn test (D4); trailing partial-header holdback on the upgrade path (D3); obs-fold continuations mask the whole logical value, with the header line's value withheld until the next line starts (D7); a direction whose start was not captured begins in the `uncertain` state (D7).
- **Revision 2** (`6039379`): D2 snaplen attribution from the pre-parse signal, metadata caps, fixed-size chunks, generations; D3 replaced (structural TLS classifier, `pending` withholding, upgrade detection, narrowed promise); D4 request/response machinery stated as new, interception before the SSE emitter, generation handling, whole-line encoded ceiling with metadata paging; new D4a admission control and backpressure; new D6a recapture exclusion with options; D7 stream-relative ranges computed at ingest, fail-closed rules; new D7a mandatory zeroization; D10 category-based character policy shared with `osi-mon`; acceptance table, checklist and questions updated.
- **Revision 1:** initial draft (`35b2f22`).

## Next

On approval: an implementation plan under `docs/superpowers/plans/`, then the work in this order: `follow.rs` with the classifier, scanner, zeroization and its fuzz target (agent-only, no wire); the recapture exclusion (D6a); the wire change and agent response builder; the relay request path with admission control; `lib/stream-render.ts` and the shared character policy; the UI. Each step test-first.
