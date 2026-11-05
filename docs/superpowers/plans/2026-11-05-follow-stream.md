# Follow Stream Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Do not implement before James approves this plan and the proposed contract corrections below. Create each implementation task's approval gate and worktree before editing; commit/push only with task authorization.

**Goal:** Let an operator explicitly fetch a bounded, direction-distinguished TCP conversation, with honest gaps, masking and encryption explanations, without publishing its content to other viewers.

**Architecture:** A separate opt-in Rust store receives the logical TCP packets already resolved by JAM-167. Authenticated request/reply messages carry masked pages to one HTTP requester through bounded agent/relay queues; a pure renderer and component own the browser accumulation. The existing decrypted store and its gate remain separate.

**Tech Stack:** Existing Rust/Tokio/serde/ring/zeroize/base64; Next.js Node runtime, TypeScript, React, Vitest and Playwright. No new dependency.

**Spec:** [Approved revision 7](../specs/2026-10-31-follow-stream-design.md). Base inspected: `e78fd324b5a379cdc278153cb7ed7086e6de06be` (main, including #290 and #291). This document is a plan, not implementation evidence.

## Global Constraints

- Startup `FOLLOW_STREAM=1` only. Unset, empty or any other value means disabled; no store allocation and `enabled:false`. Never enable by default in scripts, CI's ordinary smoke, or deployment. Test fixtures explicitly opt in.
- TCP, IPv4/IPv6, live and replay only; no recorded-file query, UDP/QUIC, HTTP object extraction, decompression, search or reveal mode.
- Keep Next.js and agent on `127.0.0.1`; preserve Webpack/watch behavior and package.json's `--webpack` flags. No Caddy changes. LAN enablement waits for JAM-196; an mTLS content predicate is not caller authentication.
- Follow data never enters broadcast/SSE, logs, errors, agent files or decrypted-payload storage. Raw save contains already-fetched masked bytes only. Existing decrypted gate/export tests remain unchanged.
- Head retention: 256 KiB/direction; 1,024 gaps and 1,024 redacted ranges/direction; 4,096 turns/flow; 256 retained flows; global 16 MiB counted by reserved capacity, including out-of-order bytes, coverage and metadata. Fixed 16 KiB zeroizing data chunks; allocate bounded metadata once, without reallocating secret storage.
- Reordering: 64 KiB/direction, 2,000 ms capture time; first-seen bytes win; signed wrapping sequence deltas; exact hole size. Snaplen attribution uses the pre-parse notifier and existing `CUT_ATTRIBUTION_WINDOW_MS` (import/share its actual value, never duplicate a guessed duration).
- TLS: record types 0x14–0x17, legacy versions 0x0301–0x0304, length at most 18,432; candidate offsets in first 20 KiB, lookahead 40 KiB, 2,000 ms capture-time pending/suspect deadline, trailing partial-header holdback of up to four bytes. No decryption here.
- Scanner: at most 16 KiB per undecided line, conservative obs-fold and uncertainty propagation, stream-relative same-length masking on copies before paging. Original bytes remain private in zeroizing store chunks.
- Response: whole NDJSON line at most 192 KiB including LF; at most 32 KiB data and 128 gaps/ranges per direction, 256 turns/response. Metadata is paged, never silently discarded.
- Relay: four slots total, one/connectionId, 192 KiB reservation/slot through HTTP finish/abort (768 KiB logical output reservations); agent writableLength above 64 KiB rejects 503; at most one write awaiting drain; 5,000 ms correlation timeout; 10,000 ms HTTP write deadline after agent response. Fixed error bodies at most 256 bytes.
- Agent: at most four unflushed responses and at most 512 KiB unflushed stream bytes per authenticated connection; do not build a response that cannot fit the remaining budget. Busy responses contain no content and use bounded/coalesced output. No response uses the discrete packet-event rate budget.

## Review Focus

These inputs need explicit tests in the tasks below, beyond the acceptance-table headline cases:

1. A live final turn grows and is superseded between page requests: replace the client's old final turn rather than skipping its growth (Task 6).
2. A UTF-8 code point or credential value straddles a page, gap, direction change or withheld emission boundary: never invent characters or expose a suffix (Tasks 1, 3, 5, 6).
3. A fast agent responds while HTTP readers stop draining: slots remain occupied after correlation removal and release once on finish, abort or deadline (Task 4).
4. A live loopback relay response or IP fragment contains the sentinel: exclude before store, events and recording, including non-default port and IPv6 (Tasks 2, 6).
5. Flow replacement, interface reset or an old HTTP completion races a new selection: generations and client request epochs prevent mixed exports or stale UI (Tasks 1, 3, 6).

## Decisions requiring review before implementation

The approved retention, masking, LAN and live/replay choices are unchanged. Two implementation gaps need explicit resolution in this plan's review, with James's approval before coding:

**P1 — observe real HTTP egress.** Use `pages/api/follow-stream.ts` for the same `POST /api/follow-stream` URL, backed by `lib/follow-stream-response.ts`. Node's `ServerResponse` exposes `finish`, `close`, `error`, `write()` and `drain`. An App Router `ReadableStream`'s producer `close()` is not HTTP finish: inspected Next 16.4.1 `dist/server/pipe-readable.js` writes through a separate sink, waits for drain, and waits for `finish` only in that sink's close. Releasing from a producer close would violate revision 7. Do not use private Next APIs, modify Next's installed files or add a custom server. A Node Pages API handler is a narrow transport adaptation; it must pass the existing request gates through a tested `NextRequest` adapter and be covered in dev and production builds. Do not also create an App Router route at this URL.

**P2 — detect port mismatch before disclosing data.** Add required `relayPort: u16` to `get_stream` and optional response `unavailable:"relay_port_mismatch"`. The relay reports `req.socket.localPort`, validated as 1..=65535, not an environment copy of the intended port; no startup wrapper is needed. The agent compares the supplied port with its startup `RELAY_PORT` before snapshotting, masking or serializing content. Missing/invalid/mismatched values return a correlated, content-free unavailable response; the relay maps it to fixed 503. No `stream_data` content is returned before this check. This is an explicit additive amendment to D4's request fields, not a claim the spec already provides detection. Without it, independently configured ports cannot be compared: the current authentication ACK contains no configuration and D4 has no port field. A typo or default-port auto-increment in next dev could therefore recapture HTTP content into ungated packet events. Apply the check before content generation in live and replay, independent of the current interface (set_interface may move to loopback). This is a misconfiguration guard self-reported by an authenticated relay, not caller authentication. Keep this correction in the wire contract PR, with Rust/TS/docs/tests together.

If either proposal is rejected, revise this plan before implementation; do not substitute producer-close admission release or silently accept a port mismatch. These proposals were raised separately in the task Slack thread with source evidence.

## Source map and PR sequence

| PR / task | Responsibility | Files to create or modify | Depends on |
|---|---|---|---|
| 1 | Bounded store, classifier, scanner, zeroization; fuzz | Create `capture-agent/src/follow.rs`, `capture-agent/fuzz/fuzz_targets/follow_store.rs`; modify `src/lib.rs`, `src/redact.rs`, `fuzz/Cargo.toml`, `.github/workflows/ci.yml` | Plan approval |
| 2 | Live relay-transport exclusion and startup config | Create `capture-agent/src/follow_config.rs`; modify `src/lib.rs`, `src/main.rs`; add config tests, README/getting-started instructions | 1; review P2 |
| 3 | Shared wire contract, bounded response builder and packet integration | Create `capture-agent/src/follow_response.rs`, `capture-agent/tests/follow_replay.rs`, `lib/__tests__/follow-stream-mapping.test.ts`; modify `src/wire.rs`, `src/main.rs`, `src/flow.rs`, `lib/types.ts`, `lib/agent-mapping.ts`, `docs/wire-protocol.md`, fuzz harness | 1, 2 |
| 4 | Relay admission, correlation, egress and gates | Create `pages/api/follow-stream.ts`, `lib/follow-stream-response.ts`, `lib/follow-stream-admission.ts`, `lib/stream-content-gate.ts`; modify `lib/agent-client.ts`, `lib/stream-response.ts`; add focused tests | 3; approval P1/P2 |
| 5 | Pure byte renderer and shared terminal character policy | Create `lib/safe-characters.ts`, `lib/stream-render.ts`; modify `lib/osi-mon-client.ts`; add renderer/policy/client-source tests | 3 contract; can review separately |
| 6 | Browser accumulation, UI, raw save and end-to-end evidence | Create `lib/follow-stream-client.ts`, `components/FollowStreamView.tsx`, component/client tests, `e2e/follow-stream.spec.ts`, `capture-agent/tests/follow_loopback.rs`; modify `ConnectionsView.tsx`, `app/page.tsx`, e2e config/helper and CI integration steps | 4, 5 |
| 7 | Operator/security docs and final opt-in acceptance | Modify `docs/security.md`, `docs/usage.md`, `docs/getting-started.md`, `capture-agent/README.md`, `CONTRIBUTING.md` and task evidence | All previous PRs |

Keep PRs serial while changing the same core files. Task 1's fuzz target and CI wiring ship together; Task 3 extends that target with encoded-response invariants. No early PR exports content to browsers. Every implementation PR documents what was read/run and re-marks the security checklist against the actual diff. Do not mark JAM-17 Done when the plan merges.

## Shared types and ownership

Use `capture-agent/src/follow.rs` for store constants and internal state. `follow_response.rs` owns wire-page constants and serialization; `follow-stream-admission.ts` owns relay limits. Keep tests for Rust/TS limit parity; avoid unrelated global constants refactoring.

```rust
// follow.rs — new API, signatures to implement, not existing functionality.
pub struct FollowStore { /* private bounded state; redacting Debug */ }
pub struct Generation { pub epoch: u64, pub counter: u64 }
pub enum Direction { C2s, S2c }
pub enum StopReason { StoreCap, GapLimit, TurnLimit, RedactionLimit }
pub enum Classification { Pending, Cleartext, Tls }
pub enum GapReason { Missing, SnaplenLikely }
pub enum MaskReason { Credential, Uncertain }
pub struct Gap { pub at: u32, pub missing: u32, pub reason: GapReason }
pub struct MaskRange { pub start: u32, pub len: u32, pub reason: MaskReason }
pub struct Turn { pub dir: Direction, pub start: u32, pub len: u32, pub first_seen_ms: u64 }
pub struct FollowSegment<'a> {
    pub seq: u32, pub syn: bool, pub ack: bool, pub fin: bool, pub rst: bool,
    pub payload: &'a [u8], pub now_ms: u64,
}
impl FollowStore {
    pub fn new(epoch: u64) -> Self;
    pub fn ingest(&mut self, key: &FlowKey, outbound: bool, segment: FollowSegment<'_>);
    pub fn note_frame_cut_at_snaplen(&mut self, now_ms: u64);
    pub fn tick(&mut self, now_ms: u64);
    pub fn drop_flow(&mut self, key: &FlowKey);
    pub fn reset(&mut self); // clear entries, retain epoch and monotonic counter
    pub fn reserved_bytes(&self) -> usize;
}
```

Generate epoch with existing `ring::rand::SystemRandom` once at startup; fail startup on RNG failure. Increment counter for every new/replacement entry; on overflow refuse new retention (never reuse a generation). No wall clock in FollowStore. Entry keys reuse `FlowTable::key_for`; do not parse `connection_id()` to reconstruct a key. Maintain a bounded ID lookup inside the store, count its allocation, and remove it on eviction.

Direction decision: a SYN without ACK identifies the client; a first SYN+ACK identifies the opposite endpoint as client. Freeze orientation for the generation. If capture starts midstream with no role evidence, use local-outbound as the stable first direction and label endpoints local/remote in the UI, with `flow start not captured`; do not claim the local endpoint was proven to be the initiator. A later SYN establishes a new generation rather than relabeling previously exposed bytes. This is a planning call requiring reviewer confirmation against D2's direction wording.

Data offsets count stored bytes, not missing TCP sequence space. `seenBytes:u64` counts observed TCP payload bytes with saturating arithmetic, including retransmissions; it is not an unbounded historical unique-byte count. Label that counter accordingly in the head-only explanation. All out-of-order storage and coverage is bounded and charged. Under a stopped direction, keep counting observed payload lengths without retaining new data; overlap counts remain truthful for retained coverage only (do not allocate an unbounded history to deduplicate forever). `storedBytes` counts retained bytes, while page output stops at the safe emission horizon. A mask/partial-header holdback must not move that horizon backward after bytes have been exposed.

```ts
// lib/types.ts — canonical decoded contract (wire input is unknown until validated)
type FollowDirection = 'c2s' | 's2c' | 'unknown';
type FollowClassification = 'pending' | 'cleartext' | 'tls' | 'unknown';
interface FollowRequest {
  connectionId: string; generation?: string;
  c2s: { offset: number }; s2c: { offset: number }; turnsFrom?: number;
}
interface FollowGap { at: number; missing: number; reason: 'missing' | 'snaplen_likely' | 'unknown' }
interface FollowMask { start: number; len: number; reason: 'credential' | 'uncertain' | 'unknown' }
interface FollowTurn { dir: FollowDirection; start: number; len: number; firstSeenMs: number }
interface FollowDirectionPage {
  classification: FollowClassification; tlsFrom: number | null;
  offset: number; nextOffset: number; storedBytes: number; seenBytes: number;
  stoppedReason: 'store_cap' | 'gap_limit' | 'turn_limit' | 'redaction_limit' | 'unknown' | null;
  gaps: FollowGap[]; conflictingOverlapBytes: number; redactedRanges: FollowMask[]; dataBase64: string;
}
interface FollowAccumulation {
  connectionId: string; generation: string;
  clientToServer: Uint8Array; serverToClient: Uint8Array;
  metadata: FollowResponse; turns: FollowTurn[];
  gaps: { clientToServer: FollowGap[]; serverToClient: FollowGap[] };
  masks: { clientToServer: FollowMask[]; serverToClient: FollowMask[] };
}
interface FollowResponse {
  type: 'stream_data'; requestId: string; connectionId: string;
  enabled: boolean; found: boolean; stale: boolean; generation: string | null;
  flowStartCaptured: boolean; closed: boolean;
  directions: { clientToServer: FollowDirectionPage; serverToClient: FollowDirectionPage };
  turnsFrom: number; turnsNext: number | null;
  lastTurn: (FollowTurn & { index: number }) | null; turns: FollowTurn[];
  busy?: boolean; unavailable?: 'relay_port_mismatch' | 'unknown';
}
```

Rust `StreamRequest`/`StreamData` mirror every field with serde camelCase and snake_case enum tags; `GetStream` adds `request_id:String` and required `relay_port:u16` to `FollowRequest`. Empty/disabled/not-found/stale/busy/unavailable responses use empty directions/arrays, null lastTurn and no content. A live found entry always has a generation; absence cases use null (clarifies the spec's illustrative response, which shows only found:true). Generation input is canonical `16 lowercase epoch hex digits:decimal u64`, maximum 37 characters; bad syntax is 400 at relay and ignored/content-free at agent. `requestId` is exactly 32 lowercase hex characters; never accept a browser-supplied request ID.

Require finite safe integer fields and explicit caps before allocation at both ends. Rust u64 counters encode as JSON numbers; TS saturates values above Number.MAX_SAFE_INTEGER to that maximum with an explicit display `≥` rather than wrap or treat them as exact. Page offsets remain exact u32 within 262,144. Unknown enum values map to visible unknown; structurally invalid payloads fail 502 without captured details. Unknown fields are ignored. Unknown classification never renders or saves its bytes; unknown direction never guesses a role.

## Task 1 / PR 1: bounded store and adversarial byte handling

**Interfaces:** Consumes borrowed logical TCP payloads/FlowKey and capture-time ticks; produces the API above plus a bounded read-only `with_entry<R>(&self, connection_id:&str, f:impl FnOnce(Option<&FollowEntry>)->R)->R` used by Task 3. `FollowEntry` exposes metadata and `copy_masked(dir, offset, end, output:&mut [u8])->usize`; callers cannot retrieve unmasked bytes. `copy_masked` refuses bytes beyond the TLS/redaction emission horizon. A `#[cfg(test)]` release observer checks zeroed chunks before deallocation. Fuzz-only instrumentation exposes counts and validates safe emission without exposing production raw-byte getters.

- [ ] Write failing Rust tests in `follow.rs` using small deterministic `FlowKey`/`FollowSegment` fixtures. Assert `new(1).reserved_bytes()==0`, an in-order SYN/request/response yields stable directions and exact bytes after classification resolves, reverse-order segments fill a hole, SYN/FIN consume sequence space, wrapping sequence numbers join correctly, duplicate retransmits do not duplicate payload, and conflicting overlap keeps the original bytes with an exact conflict count.
- [ ] Add boundary tests at zero, limit and limit+1 for every cap in Global Constraints; charge actual Vec/Box/HashMap capacity and coverage allocation before accepting it. Assert 64 KiB ahead-of-edge budget, hole expiry at capture time 2,000 ms, exact missing size, reasons within/outside snaplen window, no timer progress when wall time advances without a replay tick. Test tied pressure victims deterministically (closed first, then oldest activity, stable insertion counter tie-break); FlowTable eviction removes the corresponding entry; reset preserves generation monotonicity; pause does not clear it.
- [ ] Add D3 tests: ClientHello/ServerHello with/without SNI; two 0x17 records; mid-record capture resynchronization; header splits at every position; 18,432/18,433 length; 20/40 KiB search bounds; pending expiry at 2,000 ms and close; cleartext non-TLS. STARTTLS and CONNECT fixtures must fetch between each split of positions 1–4: no suspected byte crosses the emission horizon; refuted suspicion releases bytes; confirmed TLS drops/zeroes the suffix and stops both directions, preserving prior cleartext prefixes and tlsFrom.
- [ ] Add D7 tests: credential header segmented/paged at every byte; request starts inside its value; bearer under unlisted name; empty `X-Custom-Auth:` then a SP/HTAB continuation with a fetch between segments; gap through name/value/before line; uncaptured start at every header offset; uncertain line followed by multiple folded continuations; JSON body visible; header-like body conservatively masked; exact 16 KiB and overlong unterminated candidate/uncertain lines; adjacent range coalescing and range-cap stop. Assert same-length `*` output and original offsets, with no original value in copied pages or Debug.
- [ ] Run `cargo test --locked follow::`; demonstrate missing module/API failure, then implement `follow.rs` and widen only `redact::looks_like_bearer_token` to `pub(crate)`. Store original bytes only in fixed zeroizing chunks; every withheld/OOO copy must be zeroizing too. Metadata capacities, bounded index overhead and reusable classifier/scanner scratch all count toward 16 MiB. Allocate before mutating state only after budget admission; no secret-bearing reallocation.
- [ ] Exercise the release observer on capacity/idle/FlowTable eviction, global pressure, reset, initial TLS, upgrade, teardown, rejected allocation, and partially used chunks (check full allocated capacity). Counter/metadata-only diagnostics must contain no payload. Do not make tests read freed memory.
- [ ] Add `follow_store` fuzz target and Cargo bin registration. Feed bounded opcodes for ingest, tick, snaplen cut, close, eviction/reset and masked reads; assert reserved bytes/count caps, immutable first-seen bytes, no emitted pending/TLS/suspect data and no panic on wraparound. Seed TLS splits, overlapping retransmits and folded-header gaps. In `.github/workflows/ci.yml`, add `src/follow.rs`, `src/redact.rs`, `src/follow_response.rs` to the existing fuzz path regex, preserving every current path, and an explicit `Fuzz follow_store` step with the same filter and `cargo +nightly fuzz run follow_store -- -max_total_time=30`. Update comments to the actual target list; keep all existing fuzz runs.
- [ ] Verify `cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo build --release --locked`, `cargo +nightly fuzz run follow_store -- -max_total_time=40`; record output and demonstrate an intentional invariant mutation is caught before restoring it. PR 1 does not hook the store into main or expose a new wire message.

## Task 2 / PR 2: startup ports and pre-pipeline exclusion

**Interfaces:** `follow_config.rs`: `pub fn parse_relay_port(value:Option<&str>)->Result<u16,RelayPortError>` (default 3000; explicit values decimal 1..=65535, blank/invalid/zero/out-of-range fail startup) and `pub fn follow_enabled(value:Option<&str>)->bool`. `exclude_live_control_capture(packet:&ParsedPacket, live:bool, relay_port:u16)->bool` remains at the existing call site. Existing authenticated 9990 exclusion remains intact.

- [ ] First add pure tests for default, 1/65535, 0/65536, signs, whitespace/blank and malformed port; no global environment mutation in parallel Rust tests. Test relay port 3000 and 3100 in both directions on IPv4 and IPv6 loopback, retain off-loopback/UDP/unrelated port traffic and every replay frame. Keep all pre-existing 9990/fragment regressions.
- [ ] For fragmented loopback TCP, transport ports are not reliably available until reassembly. Preserve the current conservative fragment exclusion and extend it to all loopback address pairs (IPv4 and IPv6), instead of guessing a non-first fragment's port. State this visibility cost in docs; unrelated unfragmented loopback traffic remains visible. Add first/non-first fragment tests and ensure exclusion runs before raw recording as well as flow/store paths. Do not feed fragments twice.
- [ ] Run `cargo test --locked exclude_live_control_capture` and new config tests, show the relay-port tests fail on baseline, then implement the startup config and call-site signature. Runtime `set_interface` preserves configured exclusion ports; replay skips the exclusion entirely. `RELAY_PORT` selects an excluded transport, never a bind address.
- [ ] Document paired launch without changing package scripts: `RELAY_PORT=3100 FOLLOW_STREAM=1 cargo run --release --locked` in capture-agent and `npm run dev -- -p 3100` in repo root (production: `PORT=3100 npm run start`). Ordinary port 3000 needs no override. Only the agent reads RELAY_PORT; the relay reports its actual bound socket port per request. If dev auto-selects 3001 because default 3000 is occupied, agent's default 3000 rejects every content request until the agent is relaunched with RELAY_PORT=3001. Do not send content merely because the configured environments happen to agree.
- [ ] Verify Rust tests/build/clippy plus configuration tests. The full sentinel HTTP-content recapture test depends on Task 6; mark this PR's narrower pre-pipeline tests honestly.

## Task 3 / PR 3: wire contract, bounded response and agent integration

**Interfaces:** `follow_response.rs` owns `pub fn encode_stream_data(store:Option<&FollowStore>, request:&StreamRequest, relay_port:u16, output:&mut Zeroizing<Vec<u8>>)->Result<(),StreamResponseError>`; preallocate output capacity at exactly 192 KiB and use a fixed-capacity writer that refuses overflow (never let serde grow it first). Serialize base64 directly through the bounded writer or a preallocated zeroizing base64 scratch. Request offsets select stored-byte windows; the builder borrows the store for bounded work, then releases the lock before network I/O. `StreamRequest` and `StreamData` live in `wire.rs`, with corresponding TS types above.

- [ ] Add failing `wire.rs` serde round-trip tests and TS mapper fixtures in the same PR: every listed field, camelCase conversion, optional/busy/disabled/not-found/stale cases, request bounds and P2 port mismatch, unknown enum values, oversized arrays/base64 and malformed response IDs. `get_stream` is never added to generic `/api/control`'s allowlist.
- [ ] Add response tests with both directions full, maximal gap/mask metadata, 256 turns and lastTurn. Assert encoded bytes plus LF at most 196,608 before write, no raw secret in base64-decoded output or transient Debug, at most 32,768 bytes/direction, metadata 128/direction and 256 turns. If metadata limits bind, shorten the data page and return a progressing nextOffset; adjacent holes at one stored offset coalesce, so paging cannot become stuck on 129 zero-width gaps. Each gap belongs to one page (start inclusive, end exclusive; terminal end gap belongs to final page), masks are clipped to page intersections. Test offset-inside-mask, zero-length and held-back pages without artificial busy loops.
- [ ] Retrieve over 256 turns and over 128 gaps/direction across pages, including a turn spanning pages. Assert the complete turn index sequence and canonical gaps are delivered without omission; redacted-range intersections retain absolute offsets. Always include current `lastTurn`, even when turnsFrom is beyond existing turns. Validate generation before offsets: tuple reuse and reset return stale, empty data, current generation; first requests omit generation. Disabled/not-found responses reveal no entry data.
- [ ] Extend `main.rs` to share `Arc<Mutex<Option<FollowStore>>>` between capture and authenticated control tasks. Allocate only for FOLLOW_STREAM=1, epoch once. Capture path: use `sniff_outcome.reassembled_packet` when present; otherwise feed parsed TCP only when not an incomplete IP fragment. Feed once after flow observation/replacement cleanup, using `key_for`, same capture-time clock as reassembly. Notify snaplen cuts before parsing even when parse fails. Live idle ticks call store.tick using live clock; replay ticks advance only with capture timestamps (freeze after EOF). Reset store on successful interface switch, not a failed switch; pause stops feeding without clearing. Keep lock order FlowTable then FollowStore; response handler never takes FlowTable while holding FollowStore.
- [ ] `FlowTable` currently returns stale-tuple closure via `ObserveResult.closed_connection_id` and bulk idle/capacity eviction metadata separately; inspect `EvictedFlows` and capacity admission before coding. Add a bounded draining `take_evicted_keys()->Vec<FlowKey>` API if needed so every removal reaches FollowStore; drain under the same observation/snapshot lock rather than infer removals from sampled connection events. A new SYN replacing a terminal tuple removes old store state before new ingest. Test capacity eviction as well as idle and tuple reuse.
- [ ] Send `stream_data` directly on the authenticated requesting connection, never `broadcast::Sender`, and never the packet rate limiter. In each connection's single writer owner, track queued stream response byte lengths and count until write completion. Admit only if next response fits 512 KiB/four; serialize synchronously into one bounded scratch then queue only the admitted bounded body. If busy, send/coalesce one bounded content-free correlated busy response; under continued blocked output close the connection rather than allocate an unbounded busy-response queue. Exercise a blocked writer with fifth request, budget at/beyond 512 KiB, malformed requests, disconnect and error cleanup; normal event writes must not race/interleave response bytes. Zeroize output and scratch on successful write, failed write, cancel and disconnect.
- [ ] Create `tests/follow_replay.rs` using the existing generated pcap fixture/auth helpers: fast and realtime replay with cleartext, fragment-reassembled TCP, gaps, TLS and tuple reuse. Fetch through the real authenticated binary, assert masking and generation/clock parity; verify disabled binary has no content. Fixed port tests are ignored and serialized with existing replay tests; run them explicitly, do not count compile-only as pass. Extend no-disk invariant with the store/emission path in a temporary working directory.
- [ ] Extend `follow_store` fuzz operations to run the response builder with arbitrary bounded requests and maximal metadata. Assert encoded ceiling, all metadata progress, no pending/TLS emission and absence of seeded credentials after every operation. Run Rust tests/clippy/release, targeted ignored replay test, follow_store fuzz, TS contract tests and full Vitest; update `docs/wire-protocol.md` and limits table atomically.

## Task 4 / PR 4: request-scoped relay and HTTP lifetime

**Interfaces:** `AgentClient.requestStream(input:FollowRequest, options:{signal:AbortSignal;relayPort:number}):Promise<FollowResponse>` creates its own random requestId; bounded pending map is private. `FollowAdmission.tryAcquire(connectionId:string):FollowLease|null`; lease reserves 192 KiB and exposes idempotent `release():void`. `buildFollowStreamResponse(req:NextApiRequest,res:NextApiResponse,deps?:FollowRouteDeps):Promise<void>` owns lease through res finish/close/error. `isStreamContentAllowed(request:Request):boolean` implements the current decrypted gate predicate separately, tested for parity without importing its implementation. Thin route exports only handler/config (`bodyParser:false`, Node runtime); helper owns behavior/test seams.

- [ ] Add failing route/gate/admission tests first. Guard order is method (405), cross-site rejection (403), content predicate (403), bounded JSON/type validation (400/413), actual socket-port validation (503), then admission. Construct one `NextRequest` from validated local URL, raw request headers and actual bound port for `rejectIfCrossSite` and content checks; never trust X-Forwarded-Host/Proto for direct access or duplicate/fork gate logic. Preserve Caddy header semantics. Test spoofed/missing Origin, Fetch-Site same-site/cross-site, malformed/duplicate Host, x-mtls-verified absent/true/false and existing middleware Host allowlist coverage on the new URL. A content gate is not an authenticated caller session; document the same inherited limit.
- [ ] Parse JSON from the request only after guards; max 2,048 body bytes counted before buffering, regardless of Content-Length/chunked transfer. Reject unsupported media types, malformed JSON, unsafe integers, ID length 0/129, generation syntax, negative/over-cap offsets, turnsFrom above 4096. Do not use automatic Pages body parsing. Cancellation follows req.aborted and res.close; do not treat normal IncomingMessage `close` as response cancellation.
- [ ] Add correlation tests: create pending entry before writing; random ID 32 lowercase hex; never emit a matching, late, unknown, cancelled, forged or malformed stream_data event to generic listeners. Frame lines as byte-bounded buffers before StringDecoder/JSON.parse, not after accumulating an unbounded string: if a stream response exceeds 192 KiB, fail its request with fixed 502 and drop/drain the overlong line without retaining it. Establish a separate documented existing-event cap only after checking actual largest current event fixtures; do not silently truncate valid unrelated events. Timeout at 5 s, abort, disconnect, re-authentication and stop all settle pending exactly once and clear timers/listeners; normal events retain existing reconnect behavior.
- [ ] Add server-wide admission tests independent of browser conventions: 20 concurrent distinct flows forward at most four; same-flow concurrency forwards only one; excess immediately returns fixed 429, no pending state. If socket.writableLength is greater than 65,536 reject 503. Honor socket.write(false), keep at most one request waiting for drain, reject extra waiting requests with 503 rather than queueing. Writes already accepted by write(false) are not resent. Every error returns a fixed JSON body at most 256 bytes with no agent body, exception or captured text.
- [ ] Add real HTTP slow-reader tests (Node clients that do not consume bodies), not just mocked ReadableStreams. Four fast agent replies remove correlation entries but occupy all slots; fifth is still 429 until HTTP finish, cancellation or the 10 s deadline. Use a controllably blocked response transport when local kernel buffers absorb a small response; assert the event being tested is Node drain/finish, not client application consumption. Test compression on/off and production `next start` as well as dev. Assert logical reservation gauge <=786432, no permit double release, bounded response copies and no new work before release.
- [ ] Implement egress: write the validated response without an unbounded JSON reserialize/copy chain, set `Cache-Control: no-store`, disable cache at runtime, attach the idempotent release finalizer to finish/close/error before any write, respect write/drain, and destroy res at deadline even after headers. A deadline cannot replace an already-started success with a new JSON error body. Clear references to captured buffers immediately after completion. JavaScript/V8 copies cannot be reliably zeroized; do not claim the 768 KiB logical reservation is a byte-perfect JS heap bound.
- [ ] Add explicit stream_data early-return to `lib/stream-response.ts` before every generic forwarding branch. Test both normal AgentClient interception and direct defensive injection into two SSE subscribers. Neither gets content; only the matching HTTP requester does. Count unknown-response events without logging bodies or IDs derived from payload.
- [ ] Run focused AgentClient, route, gate, admission and stream tests, full Vitest, tsc, lint, production build and real HTTP slow-reader probe. Keep existing decrypted-payload-gate and decrypted-export-exclusion tests byte-identical and passing. Run no-disk-write coverage for the response path. Before implementation, settle P1's transport choice with the probe evidence below.

## Task 5 / PR 5: byte rendering and a single character policy

**Interfaces:** `safe-characters.ts` exports `escapeCapturedText(text:string,options?:{allowLfTab?:boolean}):string` and `capturedCharacterPolicySource():string` for embedding the same tested policy into the dependency-free CLI source. `stream-render.ts` exports `renderTextBytes(bytes:Uint8Array):string`, `renderHexRows(bytes:Uint8Array,offset:number):HexRow[]`, and `buildFollowRows(response:FollowAccumulation):FollowRow[]`. Define `HexRow={offset:number;hex:string;ascii:string}`; `FollowRow` is a discriminated union of direction/text, gap, mask and status rows, never HTML. The canonical FollowAccumulation type is in lib/types.ts from Task 3; Task 6 implements its accumulation. Avoid React imports and DOM APIs here.

- [ ] Write exact-output fixtures for ESC `[2J`, OSC 8, CR overwrite, NUL, all bidi controls including U+061C, soft hyphen, U+2060, U+200B, BOM, tag sequence, both variation-selector ranges, Zl/Zp, private use, surrogate and unassigned categories. Assert LF/TAB survive only in payload text mode; CLI field mode escapes them as before. Literal escapes use lowercase hex digits padded to at least four digits in `\\u{061c}` form; invalid original UTF-8 bytes use two-digit `\\xNN` (hex letter casing fixed consistently in implementation tests). Assert `<script>` and `</div>` remain text. A literal source escape is different from its actual Unicode code point; fixtures cover both.
- [ ] Test exact invalid UTF-8 byte preservation: lone continuation, truncated multi-byte sequence, overlong encoding, surrogate encoding, values above U+10FFFF and valid adjacent characters. Do not use lossy TextDecoder replacement that loses the original bytes. Decode complete fetched direction buffers before building turn rows; a code point crossing a gap must be split/escaped rather than joined across missing data. Redraw from the bounded accumulated bytes after more pages arrive, so a split code point can resolve without duplicating text.
- [ ] Implement Unicode category predicate with property escapes, LF/TAB exception and variation selector ranges from D10. Generate the CLI's pure policy source from that same policy definition, then embed it into `osiMonClientSource` rather than import a module on the user's machine. The CLI is a generated standalone String.raw script; copying a second regex into its template is not sharing. Check that its heredoc cannot acquire a line exactly `EOF`. Coordinate JAM-260 item 3: whichever PR lands second rebases to this common module.
- [ ] Hex tests assert 16 bytes/row, absolute offsets, lowercase/uppercase choice pinned consistently, all outside 0x20..0x7e mapped to `.`, including controls and non-ASCII UTF-8. Gaps are separate rows and do not fabricate zero bytes. Each D11 status and each stop reason has one shared label constant; exact spec wording is preserved.
- [ ] Run renderer/policy and generated CLI tests, full Vitest, tsc, lint/build. This PR changes no runtime Follow fetches or default retention.

## Task 6 / PR 6: accumulation, selected-flow view and integration

**Interfaces:** `follow-stream-client.ts`: `createFollowStreamSession(fetcher:typeof fetch):FollowSession`; session `load(request:FollowRequest,signal:AbortSignal):Promise<FollowAccumulation>`, `reset():void`. `FollowAccumulation` holds a single connectionId/generation, bounded masked `Uint8Array` per direction (at most 262144 each), canonical gaps/masks, turns and latest metadata. `FollowStreamView({connectionId,onClose}: {connectionId:string;onClose:()=>void})` owns session, request epoch and abort controller. `ConnectionsView` receives optional `onFollowStream:(connectionId:string)=>void`; page adds one opener/selection handler, not the accumulated data state.

- [ ] Add session tests before code: independent data/turn pagination, full retrieval beyond 256 turns/128 gaps per direction, no infinite pagination on classifying/unchanged live head, overlapping mask intersections, repeated page idempotence, and one HTTP request at a time. Validate pages before append: requested connectionId, offsets, base64 decoded length, cap, monotonic nextOffset and index ranges. Unknown classification/dir remains visible but cannot make raw export eligible.
- [ ] Generation tests: eviction and tuple replacement between pages; interface reset; stale response clears bytes/turns/masks and restarts from zero without generation. Selection change increments local request epoch, aborts in-flight work and clears accumulation; old completion cannot update the new flow. Raw save disabled during restart and until every stored page belongs to one confirmed generation. Never combine directions or generations just because connectionId is unchanged.
- [ ] Mutable-turn tests: after turn paging is complete, append same-direction bytes between data requests and replace lastTurn by index; grow old final turn then create an opposite-direction turn before next request, resume from client's previous last-held index (`count-1`), replace it, page until turnsNext=null. Assert turns cover every fetched byte exactly once with correct direction, length and firstSeenMs.
- [ ] Add component tests for all D11 states: complete, each gap reason, each head stop reason, missing start, pending, TLS, upgrade offset, disabled with `FOLLOW_STREAM=1` instruction, not retained, replaced and busy/retry. UI Text/Hex/Save uses React text nodes only, direction colors plus arrows and endpoint labels, `overflow-wrap:anywhere`, masked ranges styled/tooltipped with credential/uncertain, exact limitation text `content is shown as captured; only credential header lines are masked` on every cleartext view. No polling or implicit fetch on row hover/render; open and Load more are explicit. TLS explanation names `bin/osi-inspect.js` and points to existing decrypted packet view without importing its store.
- [ ] Raw save only concatenates already fetched masked bytes for the chosen direction, in byte order, with explicit gaps/partial-data warning; missing bytes are not fabricated or silently represented as contiguous original content. Use fixed `stream-1.bin`/`stream-2.bin`, MIME application/octet-stream, revoke Blob URLs on release. Test byte-for-byte export, masking, partial/gap warning, stale-selection/replacement cancellation and no path/filename from captured data. Check source guard forbids dangerouslySetInnerHTML and decrypted-store imports in the follow modules; keep existing decrypted-export tests untouched.
- [ ] Add a real-browser HTTP replay fixture using the real agent binary, deterministic generated pcap and valid auth helper. Separate it from fake-agent smoke: own server on a reserved loopback port, matching RELAY_PORT, one worker and exclusive 9990, explicit FOLLOW_STREAM=1, replay local addresses and fast/realtime clock assertions. Chromium sees complete segmented bidirectional HTTP, honest holes/truncation, pending/TLS/upgrade and hostile text without created DOM elements. Start the real agent with port/env known before Next, bounded readiness and cleanup, not by competing with the existing fake-agent beforeAll. Run this explicitly in CI after building Rust in that job; never claim the fake-agent smoke is this acceptance check.
- [ ] Add ignored real `follow_loopback` capture test and run on Linux with capabilities/macOS access_bpf as existing live_loopback does. Generate a harmless source flow containing sentinel S, fetch its masked page through real HTTP, and inspect only newly created relay-transport events/store entries/raw capture after that fetch. The source flow intentionally contains S: do not assert S is absent from the source itself. Assert S never appears from relay port in any packet event/hexDump, FollowStore entry or capture-file frame. Test default/nondefault port, IPv4/IPv6 loopback, fragmented responses, runtime switch to loopback, and mismatch (agent emits no stream content). Never log real captured data or include captured secrets in failure output.
- [ ] Wire the real replay browser job and live sentinel step into CI with existing pinned Actions, required packages, exclusive ports and reasonable existing job timeouts. Add no new dependencies or broad capabilities. Run ignored tests rather than only compile them. Re-run follow_store fuzz, full Rust/clippy/release, full TS/tsc/lint/build, normal Playwright and real replay browser suites; independent security review before publication.

## Task 7 / PR 7: operator documentation and final rollout review

- [ ] Update docs/wire-protocol.md for the final tested contract, examples for disabled/stale/busy/port-mismatch and paging. Update docs/security.md with opt-in retention, lifetime/cap accounting, D6a exclusion and conservative fragment visibility cost, bodies/non-HTTP credentials visible, no guaranteed encryption detection, JavaScript zeroization limit, and explicit no-LAN-before-JAM-196 policy. Do not imply absent x-mtls-verified authenticates a caller.
- [ ] Update usage/getting-started/capture-agent README with safe paired startup, actual port detection and mismatch failure, startup-vs-runtime interface behavior, live/replay limits, all states, escaped bytes, raw save semantics and encrypted-content pointer. Update CONTRIBUTING with follow_store fuzz command, path-filter coverage and commands for real replay browser/sentinel tests. Do not add a wrapper that duplicates Next port parsing; test actual socket-port discovery in dev/start, including dev auto-increment.
- [ ] Follow every documented command in a clean test worktree with feature unset and with FOLLOW_STREAM=1. Confirm default has no allocated store or content, while opt-in flows satisfy the table below. No .env/default config may set FOLLOW_STREAM. Scan for accidental disk/cache/log persistence and new dependencies. Record actual output, platform/runtime, limitations and exact head in task evidence.
- [ ] Re-mark every item of docs/security-plan-review-checklist.md against final implementation. Claude reviews the plan first and each security-sensitive diff as it lands; James approves the final plan (including P1/P2 decisions) before Task 1 starts. Feature remains off by default after completion; JAM-17 is Done only after all implementation and acceptance evidence, never on plan PR publication.

## Acceptance and detailed-test ownership

| Spec requirement | First owning task / proof | Final integration |
|---|---|---|
| HTTP end-to-end and distinct directions | 1 segment order/overlap tests; 5 renderer; 6 glyph/color/session | 6 real replay browser, both speeds |
| Gaps, snaplen and every cap | 1 cap/cap+1/time tests; 3 metadata paging; 5/6 rows | 6 replay truncation + full UI rows |
| Control/escape chars inert | 5 exact Unicode/UTF-8 fixtures; 6 React DOM/source guard | 6 hostile replay + DOM assertions |
| TLS explanation/no premature ciphertext | 1 every D3 fixture and emission horizon; 3 page tests | 6 TLS/STARTTLS/CONNECT replay |
| Decrypted content gated, unmodified tests | 4 gate parity/stream drop; 6 import/export guard | Existing decrypted tests unchanged |
| No broadcast to other viewers | 3 direct reply writer; 4 interception and two SSE clients | 6 two-viewer and recapture sentinel |
| Server work bounded | 1 capacity; 3 whole encoded line/unflushed writer; 4 admission/egress | 4 real fast-agent/slow-reader HTTP |
| All metadata retrievable | 3 paging; 6 data/turn accumulation and mutable final turn | 6 >256 turns, >128 gaps each dir |
| Continuations do not mix flows | 1 monotonic epoch/counter; 3 stale; 6 request epochs | Replay replacement + interface reset |
| D7 complete matrix | 1 scanner, masked read and zeroization; 3 page intersections | 6 text/hex/raw same-length masking |
| D7a every release path | 1 release observer; 3 response writer success/error/cancel | No-disk invariant + fuzz |
| D4a 20 concurrent requests | 4 real route without UI conventions; 3 agent blocked writer | HTTP production slow-reader probe |
| D6a matching/mismatched ports | 2 pre-pipeline exclusion; 3 fail-closed request | 6 live sentinel and runtime switch |
| Disabled/default semantics | 1 zero allocation; 3 enabled:false; 6 disabled state | 7 clean default startup |

## Plan review against security checklist

Status here means **planned coverage**, not a tested implementation pass. Reviewed source: FlowTable::key_for/ObserveResult/EvictedFlows, ReplayClock/reassembly result, pre-parse snaplen notifier, live exclusion call site, private authenticated agent writer, wire serde, AgentClient authentication/line buffer, generic SSE forwarding, current content/origin gates, generated CLI safe(), ConnectionsView affordance, fuzz Cargo/CI and no-disk tests. No Follow Stream implementation tests can run yet.

| Checklist item | Plan status and owning proof |
|---|---|
| §1 lengths before allocation | Planned: Task 1 budget admission; Task 3 capped writer and integer/array/base64 validation; Task 4 bounded request/line framing |
| §1 per-direction/flow/global capacities | Planned: fixed chunks, coverage/OOO/metadata/index capacities all charged; deterministic eviction and missing-entry response |
| §1 reorder/overlap/wrap, bounded loops | Planned: 64 KiB/2 s and first-seen policy; 20/40 KiB classifier limits; 16 KiB scanner; cap tests/fuzz |
| §2 failure classes/deadlines/independent state | Planned: capture-time pending/suspect/gap, terminal head limits, generation replacement, relay timeout/abort/busy; separate direction state |
| §2 fail-closed/on-path attacker | Planned: withheld TLS/undecided header bytes, uncertainty masks, no unknown content render; overlap/gap/flood cause bounded visibility loss, never invented plaintext |
| §3 cryptography | N/A: no decryption/nonce/key operations; epoch uses existing CSPRNG, socket authentication unchanged |
| §4 secret ownership/cleanup/Debug | Planned: store chunks/OOO/scratch/response all zeroizing with release seam; no derived Debug on payload owners; no disk/log/cache; V8 limitation named |
| §4 lifetime limit | Planned: FlowTable idle/capacity eviction and interface reset; no independent wall-time replay expiry; original credentials retained only within bounded flow lifetime |
| §5 time | Planned: same capture/replay clock for store, wall time only for live HTTP/socket deadlines |
| §6 wire parity/unknown values | Planned: atomic Task 3 Rust/TS/docs; unknowns shown safely; stream_data request-scoped, no SSE or packet rate limiter |
| §7 tests/tooling/reviewer evidence | Planned: first-red fixtures, every cap boundary and cleanup; follow_store fuzz shipped with CI filter/step; real replay and live sentinel; each PR states actual commands |
| P1 egress guarantee | Probe records default early release and zero-prefetch limitation below; Pages finish/close adaptation proposed, explicit James approval pending |
| P2 actual relay port | Pages req.socket.localPort chosen, real dev/start port test required; explicit James approval of fail-closed wire amendment pending |

## Throwaway HTTP-egress probe (2026-11-05)

Built a minimal synthetic Next 16.4.1 application outside the repo at `/private/tmp/jam17-egress-probe`, using the already installed dependency tree, then ran `next build --webpack` and `next start -H 127.0.0.1 -p 3137`. No project feature code or dependency was changed. A Node HTTP client paused reading a synthetic 32 MiB body to force backpressure (deliberately exceeds the production response cap; this tests stream mechanics, not cap compliance).

| Producer strategy | Reader paused | After reader drained |
|---|---|---|
| Default ReadableStream highWaterMark | 2 pulls; early release true | Released |
| Explicit highWaterMark:0, release on second pull | 1 pull; release false | 2 pulls; released |

`process.env.PORT` observed in production route was `3137`. Tests requesting gzip actually received identity encoding, so compressed behavior is **not verified**. Probe log `/private/tmp/jam17-egress-results.log`; client `/private/tmp/jam17-egress-client.cjs`; build log `/private/tmp/jam17-probe-build.log`. Server stopped after probe.

Conclusion: zero-prefetch avoids the demonstrated eager-pull bug while the sink is waiting for drain. It still does not expose HTTP finish: a small `res.write()` may return true while a bounded write remains queued, and producer pull is not sink close/finish. Together with unverified compression, that leaves P1's exact lifetime guarantee unproven for an App Router implementation. The proposed plan uses Pages API's public finish/close hooks and requires real HTTP/compression/deadline tests plus gate/middleware parity. This is an explicitly reviewed transport correction, not a claim the throwaway probe proves the entire feature or every HTTP-memory bound.

## Validation for this plan PR and execution handoff

This PR changes only documentation/task evidence; it does not claim feature tests pass. Check relative links and every named existing integration point against e78fd32, run `git diff --check`, reconcile source names/types across tasks, and have Claude review the full document against docs/security-plan-review-checklist.md. Preserve all prior .ai evidence when prepending task records. Record the throwaway runtime probe separately; do not commit prototype code or installed Next files.

After publication request Claude's review with the PR link in the task Slack thread. Resolve findings in the plan; ask James to approve the final plan including its labelled corrections before feature execution. As James separately authorized, proceed next to JAM-261's investigation in its own worktree after this plan PR is up; no automatic execution of Follow Stream tasks is authorized by that sequence.
