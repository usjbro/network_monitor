# TCP Stream Graphs — Implementation Plan

**Spec:** `docs/superpowers/specs/2026-11-11-tcp-stream-graphs-design.md` (merged in PR #314; James's go-ahead for this plan in chat on 2026-11-11).
**Issue:** KAN-129 (legacy JAM-19, GitHub #86), epic KAN-18.
**This PR:** plan only, no code. Each task below is its own PR, implemented through its own approved gate, in order; each must merge before the next starts.

## Global constraints

- Next.js and the agent stay on `127.0.0.1`; preserve `--webpack` flags and `next.config.ts` watch behaviour. No Caddy changes.
- Samples are header metadata only (spec D1/D2). No payload enters the ring, the reply or any log.
- `tcp_samples` replies never reach the SSE feed or `EventEmitter('event')` listeners (spec D5).
- Bounds (spec D1, D3, D5), each tested at the limit and limit + 1:
  - 4 096 samples per ring; 128 rings; 32-byte samples; 256 outstanding-data entries per direction per ring.
  - Reply line ≤ 256 KiB including LF; at most 4 096 samples per reply.
  - Relay: 4 `tcp_samples` requests in flight, 1 per `connectionId`, 256 KiB reservation per slot held until HTTP finish/close/error; agent socket `writableLength` > 64 KiB → 503; 5 000 ms correlation timeout.
  - Agent: unflushed reply bytes on the relay connection > 512 KiB → `busy`.
- Frame timestamps only (`system_time_us(timestamp)`), never wall time, so replay at any speed gives identical rings.
- Tests first in every task; show the new test failing for the missing behaviour before implementing (CLAUDE.md workflow step 4).
- Wire changes update `capture-agent/src/wire.rs`, `lib/types.ts`, `lib/agent-mapping.ts` and `docs/wire-protocol.md` in the same PR.

## Decisions taken by this plan (review before Task 1)

These are implementation choices the spec leaves open. James's approval of this plan covers them.

- **P1. Rings live inside `FlowTable`.** `FlowTable` gains a private `TcpSampleStore` field. `observe` / `observe_replay` / `observe_reassembled*` already know the flow key, direction, TCP header fields and `is_retransmit` at the moment they are computed, so they record the sample there. `evict_stale` releases the evicted flows' rings, and `FlowTable::reset` (the JAM-183 interface-switch path) clears every ring. This keeps ring lifetime and flow lifetime under one lock and one owner, instead of a second store that could disagree with `FlowTable` about which flows exist. The alternative, a separate `Arc<Mutex<TcpSampleStore>>` fed from `main.rs`, was rejected for that reason.
- **P2. Replies are built outside the flow lock.** The control task copies the requested ring's samples (≤ 4 096 × 32 B = 128 KiB) and its metadata under the `flow_table` lock, releases the lock, then encodes the JSON. The capture thread is never blocked on JSON encoding.
- **P3. The shared request core is generic now.** `lib/agent-request.ts` correlates any reply type registered with it; `tcp_samples` is the first registration. Follow Stream's plan Task 4 later registers `stream_data` with its own ceiling, content gate and admission numbers, without changing the core. This task does not implement anything of Follow Stream's.
- **P4. Byte-bounded framing only for registered reply types.** `AgentClient`'s line reader keeps today's behaviour for ordinary events. A line whose `type` is a registered reply type is measured as UTF-8 bytes and rejected over its ceiling (the request fails 502; the line is dropped). A general cap for every event line is out of scope here; Follow Stream plan Task 4 owns that change.
- **P5. The Pages API transport** (`pages/api/tcp-samples.ts`) follows Follow Stream plan P1, which James approved on 2026-11-05: admission slots are released on Node `ServerResponse` `finish`/`close`/`error`, never on a producer `close()`. The repo has no `pages/` directory today; Next 16 serves both routers. Tested in dev and in a production build.
- **P6. Time axis and pan/zoom are shared, not copied.** Task 4 moves the IO graph's pure tick, interval and zoom helpers that both views need from `lib/io-graph.ts` into `lib/time-axis.ts`, re-exported from `lib/io-graph.ts` so its tests and callers are unchanged.

## PR sequence

| Task | Responsibility | Files | Depends on |
| --- | --- | --- | --- |
| 1 | Sample rings, RTT matching, window-scale parsing, `FlowTable` integration | create `capture-agent/src/tcp_samples.rs`; modify `src/lib.rs`, `src/parse.rs`, `src/flow.rs` | plan merged |
| 2 | Shared request core, admission, Pages route, relay-side `tcp_samples` handling against a fake agent | create `lib/agent-request.ts`, `lib/agent-admission.ts`, `pages/api/tcp-samples.ts`, `lib/tcp-samples-route.ts`; modify `lib/agent-client.ts`, `lib/stream-response.ts`; tests | 1 merged (no code dependency; keeps PRs serial) |
| 3 | Wire contract, agent handler, `capture_stats` cost fields, end-to-end replay tests | modify `src/wire.rs`, `src/main.rs`, `lib/types.ts`, `lib/agent-mapping.ts`, `docs/wire-protocol.md`; create `capture-agent/tests/tcp_samples_replay.rs`, `lib/__tests__/tcp-samples-wire.test.ts` | 1, 2 |
| 4 | Plots, entry point, polling, performance and real-agent check | create `lib/tcp-graphs.ts`, `lib/time-axis.ts`, `components/TcpGraphsView.tsx`, `e2e/tcp-graphs.spec.ts`, tests; modify `lib/io-graph.ts` (re-exports), `components/ConnectionsView.tsx`, `app/page.tsx`, `docs/usage.md` | 3 |

## Task 1 / PR 1: rings, RTT, window scale

**Interfaces (new):**

```rust
// capture-agent/src/tcp_samples.rs
pub const SAMPLES_PER_RING: usize = 4096;
pub const MAX_RINGS: usize = 128;
pub const MAX_OUTSTANDING_PER_DIR: usize = 256;

#[repr(C)] #[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct TcpSample { pub t_us: u64, pub seq: u32, pub ack: u32, pub win: u32,
                       pub len: u16, pub flags: u8, pub mark: u8, pub rtt_us: u32, _pad: u32 }
// const assert: size_of::<TcpSample>() == 32

pub mod mark { pub const OUTBOUND: u8 = 1; pub const RETRANSMIT: u8 = 2; pub const WIN_SCALED: u8 = 4;
               pub const ZERO_WINDOW: u8 = 8; pub const RTT: u8 = 16; }

pub struct SegmentObservation { pub t_us: u64, pub outbound: bool, pub seq: u32, pub ack: u32,
    pub raw_win: u16, pub len: u16, pub flags: u8, pub retransmit: bool,
    pub wscale_option: Option<u8> /* only on SYN / SYN-ACK */ }

pub struct RingView { pub generation: (u64, u64), pub first_index: u64, pub next_index: u64,
    pub handshake_seen: bool, pub window_scale: Option<(u8, u8)> /* (local, remote) */,
    pub seq_base: (u32, u32) /* (outbound, inbound) */, pub relative_to_isn: bool,
    pub samples: Vec<TcpSample> }

pub struct TcpSampleStore { /* private: epoch, counter, map FlowKey -> ring index, rings, lru */ }
impl TcpSampleStore {
    pub fn new(epoch: u64) -> Self;            // allocates nothing
    pub fn record(&mut self, key: &FlowKey, obs: SegmentObservation);
    pub fn release(&mut self, key: &FlowKey);  // flow evicted
    pub fn clear(&mut self);                   // interface switch; keeps epoch and counter
    pub fn view(&self, key: &FlowKey, from_index: u64, max: usize) -> Option<RingView>;
    pub fn reserved_bytes(&self) -> usize;     // capacity-based, includes outstanding tables
    pub fn rings(&self) -> usize;
    pub fn recycled(&self) -> u64;
}
```

`parse.rs` gains `pub tcp_window_scale: Option<u8>` on `ParsedPacket`, filled only for segments with SYN set, from bounds-checked option walking over `header_bytes[tcp_start + 20 .. tcp_start + transport_header_len]` (kind 0 ends, kind 1 is one byte, every other kind needs a length ≥ 2 that fits; kind 3 needs length 3). A malformed option list leaves it `None`, never panics.

- [ ] **Tests first** (`tcp_samples.rs`, `parse.rs`, `flow.rs`), each shown failing before the code exists:
  - ring wraps at 4 096: `first_index` advances, `view(from_index < first_index)` returns from `first_index`, and samples are in order;
  - the 129th flow recycles the ring of the flow with the oldest last sample, increments `recycled`, and gives the new ring a new generation; a reused tuple also gets a new generation;
  - `release` and `clear` free rings; `reserved_bytes` equals rings × (4 096 × 32 + 2 × 256 × 12) plus fixed overhead, and is 0 with no rings;
  - sequence base: ISN when a SYN was seen (`relative_to_isn`), first seen sequence otherwise; wrapping arithmetic across 2^32;
  - RTT: an ACK covering outstanding data yields `now − t` of the newest covered entry and the RTT mark; a duplicate ACK yields none; Karn: after a retransmission overlapping an entry, the next ACK yields none; the 257th outstanding entry evicts the oldest; RTT goes on the ACK's sample;
  - window scale: applied only when both the SYN and the SYN-ACK carried the option (shift clamped to 14); never applied to the SYN/SYN-ACK's own window; midstream join leaves windows raw with the scaled bit clear;
  - zero-window mark only on an ACK-bearing segment with window 0;
  - `parse.rs`: options with MSS + NOP + WS + SACK-permitted; a truncated option; length 0 and length 1 options; option list running past the header; no options;
  - `FlowTable` integration: `observe` records exactly one sample per TCP segment with the same `is_retransmit` it returns; `evict_stale` releases the rings of the flows it returns; `reset` clears all; UDP flows get no ring.
- [ ] **Mutation checks:** break the Karn discard, the both-sides scale rule, the LRU choice and the wrap index; each must fail a test.
- [ ] **Fuzz:** fuzz corpora are gitignored (`capture-agent/fuzz/.gitignore`), so nothing is committed there. The window-scale and malformed-option cases live in `parse.rs` unit tests; copy their frames into a local `corpus/parse_packet/` and run `cargo +nightly fuzz run parse_packet -- -max_total_time=60` locally.
- [ ] **Verify:** `cargo build --release --locked`, `cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`. Re-run the IO graph benchmark (`capture-agent/tests/io_graph_bench.rs`, 0-series case) before and after to show the per-frame cost of recording samples, and record both numbers in the PR.

**As implemented in Task 1** (differences from the interfaces above; Task 3 builds on these):

- **Ring handles.** Each flow's `RingHandle` lives in its `FlowState` (`tcp_ring`), not in a store map keyed by `FlowKey`. So `TcpSampleStore` takes `record(&mut Option<RingHandle>, obs)`, `release(RingHandle)` and `view(RingHandle, from_index, max)`, and recording costs no extra `FlowKey` hash or clone per packet. Task 3 calls `FlowTable::tcp_sample_view(&FlowKey, from_index, max)` and `FlowTable::tcp_sample_store()` for the `capture_stats` counts.
- **Recycled rings.** A flow whose ring was recycled keeps no ring afterwards (spec D1 allocates on a flow's first segment). Its handle is stale and `tcp_sample_view` returns `None`. This also stops more than 128 interleaved flows from endlessly taking rings from each other.
- **Window scale and PSH.** These are new `TcpFlags` fields (`window_scale`, `psh`), not a `ParsedPacket` field. The option walker reads etherparse's `TcpSlice::options()`, not the tail of `header_bytes`, because the tail is not the TCP header when a frame carries an Ethernet trailer.
- **Frame timestamps.** The capture loop calls `FlowTable::observe_frame(physical, reassembled, l7, now_ms, frame_us, replay)` with `system_time_us(timestamp)`. The existing `observe*` methods are unchanged for their callers and derive the sample time from `now_ms`.
- **Karn's discard.** It drops every outstanding entry that ends after the retransmission's start; entries are in sequence order. So it can also drop RTT for later in-flight data, but it never gives a wrong sample.

## Task 2 / PR 2: shared request core, admission, Pages route

**Interfaces (new):**

```ts
// lib/agent-request.ts
export interface ReplyType { type: string; maxLineBytes: number; validate(json: unknown): unknown }
export function registerReplyType(t: ReplyType): void;
// AgentClient gains:
request<T>(message: Record<string, unknown>, opts: { replyType: string; signal: AbortSignal; timeoutMs?: number }): Promise<T>;
// creates requestId (32 lowercase hex, crypto.randomBytes), adds it to the message,
// writes one line, settles exactly once (reply | timeout 504 | disconnect/re-auth 503 | abort).

// lib/agent-admission.ts
export class Admission {
  constructor(opts: { maxInFlight: number; reservationBytes: number });
  tryAcquire(key: string): Lease | null;   // null = 429 (global or per-key)
}
export interface Lease { release(): void } // idempotent

// lib/tcp-samples-route.ts (behaviour; the Pages file only exports handler + config)
export async function handleTcpSamples(req: NextApiRequest, res: NextApiResponse, deps?: Deps): Promise<void>;
```

- [ ] **Tests first:**
  - correlation: a reply with a matching `requestId` resolves only its request and never reaches `on('event')` listeners or any SSE subscriber (`lib/stream-response.ts` drops registered reply types defensively, tested by direct injection); unknown, late, forged or malformed replies are dropped and counted; timeout, abort, disconnect and re-authentication settle every pending request exactly once and clear timers;
  - framing: a registered reply line over `maxLineBytes` (measured in bytes, with multi-byte UTF-8) fails its request with 502 and is not retained; ordinary event lines are unaffected;
  - admission: 20 concurrent distinct `connectionId`s → at most 4 forwarded, the rest 429 with no pending state; two concurrent requests for one `connectionId` → one forwarded; `writableLength` > 64 KiB → 503; a lease is released exactly once on `finish`, `close` or `error`, and not when the agent replies;
  - slow reader: four requests whose HTTP clients stop reading hold all four slots after the agent has replied; a fifth gets 429 until a body finishes or is aborted (real Node HTTP clients, not mocked streams);
  - route guards, in order: method 405; `rejectIfCrossSite` 403 (same table of Origin / `Sec-Fetch-Site` cases as `/api/control`'s tests); body over 512 bytes 413; invalid JSON, `connectionId` empty or over 128, a `generation` not matching `^[0-9a-f]{16}:\d{1,20}$`, a negative or unsafe `fromIndex` → 400; then admission;
  - the middleware Host allowlist applies to `/api/tcp-samples` (a disallowed Host is refused before the handler);
  - one `AgentClient` per process: the App Router stream route and the Pages route share `global.__agentClient` (singleton accessor moved to `lib/agent-client-singleton.ts`), checked in a production build with exactly one authenticated agent connection;
  - fixed error bodies ≤ 256 bytes, `Cache-Control: no-store`.
- [ ] Until Task 3 lands, the agent ignores `get_tcp_samples` (unknown control type), so the route answers 504 after the timeout; tests use a fake agent that answers.
- [ ] **Verify:** `npm run lint`, `npx tsc --noEmit`, `npx vitest run`, `npm run build` (then restore `AGENTS.md` and `next-env.d.ts`), Playwright under `E2E_PRODUCTION=1`.

**As implemented in Task 2** (what Task 3 must match):

- **Reply framing needs `type` first and `requestId` early.** The relay measures a reply line against its ceiling before parsing it, or before its newline has arrived. It recognises the line from its opening `{"type":"tcp_samples"` and reads its `requestId` from the first 512 characters, so it can fail that request with 502. The agent must therefore serialize `type` first (serde's internally tagged enums already do) and `requestId` right after it. Otherwise an oversized reply still never reaches anyone, but its request times out with 504 instead of failing with 502.
- **Generation format.** The relay accepts a `generation` only as `^[0-9a-f]{16}:\d{1,20}$`, so the agent renders the epoch as 16 zero-padded lowercase hex digits (`{:016x}`).
- **Write backlog.** The check that the agent socket's `writableLength` is at most 64 KiB is in `AgentClient.request` (503), not in admission.
- **Reply validation.** `lib/tcp-samples-reply.ts` checks only the envelope the relay relies on: `type` and `connectionId`, with `requestId` stripped. The route also answers 502 when the reply's `connectionId` is not the one requested. Task 3 adds full validation of the sample fields in `lib/agent-mapping.ts`.
- **Cross-site check.** The Pages route compares `Origin` with `proto://Host`, where `Host` is allowlisted by `middleware.ts`. An App Router `request.url` takes its origin from the server's own bind address instead. The two can differ only on the `Origin` fallback, which matters only for browsers that don't send `Sec-Fetch-Site`.
- **Relay start.** A request made before the relay's agent client has connected gets 503. The graph is opened from a tab whose SSE stream has already started the client.

## Task 3 / PR 3: wire contract and agent integration

**Wire** (spec D5): control `get_tcp_samples { requestId, connectionId, generation?, fromIndex? }`; event `tcp_samples` with the fields in the spec's example, columnar and delta-encoded; `capture_stats` gains `tcpSampleRings`, `tcpSampleRingBytes`, `tcpSampleRingsRecycled`.

- [ ] **Tests first:**
  - Rust `wire.rs`: decode of `get_tcp_samples` (missing/oversized fields rejected as the existing control decoders do); encoding of a full 4 096-sample reply with worst-case values stays ≤ 256 KiB (asserted before write) and decodes back to the same samples; absent cases (`found:false`, `stale:true`, `busy:true`) carry no samples;
  - handler: unknown `connectionId` → `found:false`; mismatched `generation` → `stale:true`; `fromIndex` paging returns at most 4 096 from `max(fromIndex, firstIndex)` with correct `nextIndex` and `droppedOlder`; unflushed bytes > 512 KiB → `busy`; the reply is not counted against the packet-event limiter;
  - TS mapper: both directions of delta decoding, `seqBase` per direction, unknown fields ignored, unknown enum values visible as unknown, malformed arrays (lengths differ, non-numbers) throw;
  - end to end (`capture-agent/tests/tcp_samples_replay.rs`, real binary, replayed generated pcaps): a bulk transfer's ring is a monotonic staircase; a forced retransmission is marked; a zero-window episode is marked; a handshake with window scale on both sides gives scaled windows, on one side only gives raw windows; RTT samples equal the fixture's ACK delay; `REPLAY_SPEED=realtime` and `fast` give identical replies; the cost fields in `capture_stats` match `reserved_bytes`.
- [ ] **Docs:** `docs/wire-protocol.md` sections for `get_tcp_samples`, `tcp_samples` and the new `capture_stats` fields, including the capture-point RTT caveat.
- [ ] **Verify:** the Rust trio, the TS checks, and `security-review` on the diff (new control message and request path).

## Task 4 / PR 4: plots and entry point

**Interfaces (new):** `lib/tcp-graphs.ts` (pure): `accumulate(state, reply)` merges pages by index and resets on `stale` or a new generation; `series(state, direction)` returns time/sequence points, ACK line, receive-window line, RTT points, throughput bins (interval from the visible window, as the IO graph picks it) and window points with zero-window spans. `components/TcpGraphsView.tsx` renders the five plots of spec D6, SVG only, sharing one time axis via `lib/time-axis.ts`.

- [ ] **Tests first:**
  - `lib/tcp-graphs.ts`: staircase points from a fixture; ACK and window lines from the opposite direction; scaled versus unscaled window labelling; RTT points with the capture-point label per direction; throughput bins equal byte sums; overwritten history (`droppedOlder`) yields a visible gap, never interpolation; a midstream join yields the "relative to first seen segment; window unscaled" note;
  - component: the five plots render for a short fixture flow, retransmissions red, RST/FIN marked, zero-window shaded, the horizon line shown, the direction selector switches series;
  - entry point: a "TCP graphs" button only on TCP flows in the Sockets view, next to "Trace Route"; opening it polls `/api/tcp-samples` once per second with `nextIndex` while open and live, and stops on close; a 429/503/504 shows a retry message, not an empty plot;
  - performance: `e2e/tcp-graphs.spec.ts` with a fake agent and a full 4 096-sample ring; median update under 16.7 ms with `E2E_PRODUCTION=1` (CI's mode), as the IO graph spec measures.
- [ ] **Real-agent check (§5b):** replay a generated capture with a bulk transfer, a retransmission and a zero-window stall; open the flow's graphs in a real browser; record what the plots show against the fixture's known values; screenshot.
- [ ] **Docs:** `docs/usage.md` section on TCP graphs, including what RTT means at the capture point and the retention horizon.
- [ ] **Verify:** lint, `tsc`, Vitest, build, Playwright (production mode).

## Acceptance → owning task

| Acceptance criterion (KAN-129) | Task |
| --- | --- |
| Time/sequence staircase for a real flow, retransmissions marked | 1 (samples), 3 (end to end), 4 (plot, real-agent check) |
| RTT sampled continuously, not once at handshake | 1 (matcher), 3 (end to end), 4 (plot) |
| Zero-window stall visually identifiable | 1 (mark), 3, 4 |
| Retention bounded, cost reported | 1 (bounds), 3 (`capture_stats`) |
| Rust tests for sample collection; plot renders for a short fixture | 1, 3, 4 |

## Security checklist (`docs/security-plan-review-checklist.md`) → where proven

- **§1 Bounds:** every bound above at limit and limit + 1 (Tasks 1–3); relay admission and slow-reader tests (Task 2).
- **§2 Failure semantics:** `found`, `stale`, `busy`, overwritten history and 429/503/504 are explicit in the reply and the UI (Tasks 3, 4).
- **§3 Cryptography:** request IDs and ring epochs from the system RNG (`crypto.randomBytes`, `ring::rand::SystemRandom`).
- **§4 Sensitive data:** header metadata only; replies never broadcast (Task 2 tests); no logging of reply bodies.
- **§5 Time:** frame timestamps; realtime = fast equality (Task 3).
- **§6 Interfaces:** four files per wire change; tolerant mapper (Task 3).
- **§7 Tooling:** tests first, mutation checks, a local `parse_packet` fuzz run seeded with the new option cases, `security-review` on Task 3.

## Validation for this plan PR

Docs only. Check relative links and `git diff --check`. Code facts cited here were read on `main` at `caf4835`: `FlowTable::observe*`, `ObserveResult.is_retransmit`, `evict_stale`, `FlowTable::reset` (JAM-183), `ParsedPacket` fields, `AgentClient`'s line reader, `global.__agentClient`, `rejectIfCrossSite` in `lib/same-origin.ts`, and the matcher-less `middleware.ts`.
