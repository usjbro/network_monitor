# TCP Stream Graphs — Design Spec

**Issue:** KAN-129 (legacy JAM-19, GitHub #86) — "TCP stream graphs: time/sequence, RTT and throughput per flow"
**Epic:** KAN-18 (Analysis surfaces, legacy JAM-127)
**Depends on:** KAN-77 / JAM-12 Expert Info (Done; its retransmission signal is reused, its rate-limited `finding` events are not). Soft: nothing else.
**Status:** DRAFT for James's review. The four product decisions below were made by James in chat on 2026-11-11; everything else is a proposal to review.

## Problem

Per flow, the product reports one latency number (`latency_ms`, the SYN→SYN-ACK delta, `capture-agent/src/flow.rs` `rtt_ms`), a loss percentage from retransmit counts, and a 20-sample throughput sparkline. Sequence numbers are parsed (`parse.rs` `seq`) and used only for retransmit detection; ACK numbers and windows are parsed (`TcpFlags.ack_number`, `window_size`) and never kept. Nothing answers "when did this flow stall, and was it the network, the sender or the receiver?"

## What this spec promises, and what it does not

- **Promised:** every plotted point is a header field the agent actually observed on a real segment, at that segment's own capture timestamp. Retained history is bounded, its horizon is stated on the plot, and its memory cost is reported. RTT samples are only taken where they are unambiguous (Karn's rule). A window shown as scaled is scaled by the factor both sides negotiated in a captured handshake; otherwise it is labelled unscaled.
- **Not promised:** the whole life of a long flow. Each flow keeps its most recent samples; older ones are dropped and the plot says from when it has data. Not SACK blocks, not payload, not UDP/QUIC.
- **Capture-point honesty:** RTT measured at the capture point is the time from a data segment passing the capture point to its ACK passing it. For data the local host sends, that is close to the network round trip. For data the local host receives, it is mostly the local stack's ACK delay. The plot labels each direction accordingly and never presents the second as network latency.

## Decisions

### D1. Retention: always on, bounded — **decided (James, 2026-11-11)**

Every TCP flow the `FlowTable` tracks may hold a **sample ring** of its most recent segments. Samples are header metadata only (no payload), so this is not a privacy-class store like Follow Stream's.

| Bound | Value | Why |
| --- | --- | --- |
| Samples per flow | 4 096 (both directions together) | About 40 s of a 100 packet/s flow, or the last ~6 MB of a bulk transfer at 1 460 B segments. Enough to see a stall and its recovery. |
| Flows with a ring | 128 | A reader looks at a handful of flows; far below `DEFAULT_MAX_FLOWS` (10 000). |
| Sample size | 32 bytes, fixed layout | See D2. |
| Worst case | 128 × 4 096 × 32 B = 16 MiB, plus the RTT matching state in D3 | Counted by reserved capacity, not length. Allocated once per ring, on the ring's first sample. |

- **Which flows:** a ring is allocated when a TCP flow first gets a segment and fewer than 128 rings exist. At 128, the ring of the flow with the **oldest last sample** is released and reused (least recently active). A flow evicted from `FlowTable` (idle or capacity) releases its ring at the same time (`evict_stale` / capacity eviction paths).
- **Rolling, not head-keeping:** a ring overwrites its oldest sample. That is the opposite of Follow Stream's head-keeping, deliberately: a graph's job is "what is happening now / what just happened", and the plot states its horizon ("samples since 14:05:10.123; 18 230 older samples dropped").
- **Generation:** each ring carries `generation = "<epoch hex>:<counter>"` (64-bit random epoch at agent start, `ring::rand::SystemRandom`; counter incremented for every new ring, including a reused tuple). A reader that asks for more samples of a replaced flow is told `stale` and starts over, as in Follow Stream D2.
- **Interface switch** clears every ring (JAM-183 precedent); pause stops feeding without clearing.
- **Cost reported:** `capture_stats` gains `tcpSampleRings` (rings allocated), `tcpSampleRingBytes` (reserved bytes) and `tcpSampleRingsRecycled` (rings taken from a less recently active flow). The Hosts/Sockets view shows nothing new; the cost is on the capture-stats banner's details.

Alternatives considered and rejected by James: recording only after a click (not retroactive), and a startup opt-in.

### D2. What a sample holds

```rust
// capture-agent/src/tcp_samples.rs — new, proposed layout (32 bytes)
pub struct TcpSample {
    pub t_us: u64,        // the frame's own timestamp (capture time live, recorded time in replay)
    pub seq: u32,         // raw sequence number
    pub ack: u32,         // raw ACK number (meaningful when flags has ACK)
    pub win: u32,         // window, scaled when the scale is known (D4); else raw
    pub len: u16,         // TCP payload length
    pub flags: u8,        // SYN, ACK, FIN, RST, PSH bits as on the wire
    pub mark: u8,         // bit 0: outbound (local is sender); 1: retransmission; 2: window scaled;
                          // 3: zero window; 4: RTT sample attached (see D3)
    pub rtt_us: u32,      // RTT for the data this ACK acknowledged, 0 when none (D3)
}
```

- **Sequence numbers are relative on the wire,** per direction, to that direction's ISN when the SYN was captured, otherwise to the first sequence number seen (`seqBase` is reported, and `relativeTo: "isn" | "first_seen"`). Wrapping arithmetic (`wrapping_sub`), as `flow.rs`'s retransmit detection already does.
- **Retransmission** is `FlowTable::observe`'s existing per-packet `is_retransmit` (the same signal the Expert Info `retransmission` finding uses), recorded on the sample itself. The plot does **not** read `finding` events for annotations: those are rate-limited (`docs/wire-protocol.md` "finding"), so they are a sample of the truth. The ring has every retained segment's own flag.
- **Zero window** is `win == 0` on a segment that carries the ACK flag (a pure SYN with window 0 is not a stall).
- **RST/FIN** are drawn from `flags`.

### D3. RTT: sampled per ACK, Karn's rule

Per direction, the ring keeps a bounded table of **outstanding data**: for each non-retransmitted segment with `len > 0`, `(end_seq = seq + len, t_us)`, at most 256 entries per direction (the oldest is dropped beyond that, and the sample loses its RTT, not correctness).

- When a segment in the **opposite** direction carries `ACK` with `ack` at or beyond an outstanding `end_seq` (wrapping compare), the RTT is `now − t_us` of the **newest** such outstanding entry, and every entry it covers is removed. The RTT goes on the ACK's sample (`rtt_us`, `mark` bit 4).
- **Karn's rule:** when a segment is marked retransmitted, every outstanding entry overlapping its range is discarded, so an ACK that might acknowledge either the original or the retransmission yields no RTT.
- Duplicate ACKs (no new data acknowledged) yield no RTT.
- Cost: 2 × 256 × 12 B = 6 KiB per ring, allocated with the ring; 128 rings ≈ 0.75 MiB, inside the reported reserved bytes.
- **Labelling (capture point):** RTT for **outbound** data is shown as "round trip from this host's capture point"; RTT for **inbound** data as "this host's ACK delay (not network latency)". The UI shows the outbound one by default.
- The existing handshake `latency_ms` is unchanged and is shown as a reference line.

### D4. Window scaling — **decided: parse it (James, 2026-11-11)**

`parse.rs` gains the TCP window-scale option (kind 3, RFC 7323) from SYN and SYN-ACK option bytes (already in `header_bytes`; options span `transport_header_len - 20`). Parsing is bounds-checked option walking (EOL/NOP/length rules), covered by the existing parse fuzz target's corpus plus new seeds.

- The scale applies only when **both** the SYN and the SYN-ACK of this flow were captured and both carried the option (RFC 7323 §2.2); shift counts above 14 are clamped to 14, as the RFC says.
- The window in a SYN or SYN-ACK is never scaled.
- When the handshake was not captured (flow joined midstream), or only one side offered scaling, windows are raw, `mark` bit 2 is clear, and the plot labels the window **"unscaled (handshake not seen)"** or **"unscaled (scaling not negotiated)"**. It never guesses a scale.

### D5. Data path: a request/response relay route, built now — **decided (James, 2026-11-11)**

Samples are fetched on demand by the tab that opened the graph, never broadcast on the SSE feed. This builds the relay's first request/response path, designed as **shared machinery** so Follow Stream (KAN-110, see "Source disagreement" below) reuses it rather than building a second one.

**Shared core (new, reusable):**
- `lib/agent-request.ts`: `AgentClient.request(message, { kind, key, signal })` creates a 128-bit random `requestId` (32 lowercase hex), writes the control line, and resolves with the agent's correlated reply. The line reader **intercepts correlated reply types before `emit('event')`**, so replies never reach an SSE listener; `lib/stream-response.ts` also drops them defensively. Unknown, late or forged `requestId`s are dropped and counted. Pending entries settle exactly once: reply, 5 s timeout (504), agent disconnect or re-authentication (503), or the HTTP request's abort.
- **Byte-bounded line framing for replies:** a reply line is measured as bytes before `JSON.parse`; over the reply type's ceiling (here 256 KiB) the request fails 502 and the line is dropped, never buffered further.
- `lib/agent-admission.ts`: per reply type, at most N requests in flight relay-wide and one per key, each holding a byte reservation from admission until the HTTP response has **finished or been aborted** (Follow Stream plan P1's lesson: a producer `close()` is not HTTP finish). Beyond either limit: 429 immediately, no pending state. Agent socket `writableLength` above 64 KiB: 503.
- **Transport:** a Node Pages API route (`pages/api/tcp-samples.ts`), as Follow Stream's plan P1 chose, so the reservation is released on `ServerResponse` `finish`/`close`/`error`. The route applies the same guards as `/api/control`, in order: method (405), `rejectIfCrossSite` (403), bounded JSON validation (400/413), then admission. Uses the shared `AgentClient` singleton (one agent connection per process). Fixed error bodies ≤ 256 bytes.

**TCP-samples specifics:**
- Limits: 4 in flight relay-wide, 1 per `connectionId`, 256 KiB reservation each (1 MiB total).
- **Browser → relay:** `POST /api/tcp-samples` `{ connectionId, generation?, fromIndex? }`. `connectionId` ≤ 128 chars; `fromIndex` a non-negative safe integer.
- **Relay → agent:** control message `get_tcp_samples { requestId, connectionId, generation?, fromIndex? }`. `/api/control`'s allowlist is not extended; only this route sends it.
- **Agent → relay:** event `tcp_samples` with the same `requestId`:

```json
{
  "type": "tcp_samples", "requestId": "9f2c…", "connectionId": "Tcp-192.168.1.10:51000-93.184.216.34:443",
  "found": true, "stale": false, "generation": "4be1a07c9d22f310:17",
  "handshakeSeen": true, "windowScale": { "local": 7, "remote": 8 },
  "seqBase": { "outbound": 1294467712, "inbound": 3011845120 }, "relativeTo": "isn",
  "handshakeRttUs": 23110,
  "firstIndex": 18230, "nextIndex": 22326, "droppedOlder": 18230,
  "samples": {
    "tUs": [1794120000000000, 1200, 1350],
    "seq": [0, 1, 1449], "ack": [0, 1, 1], "win": [65535, 131328, 131328],
    "len": [0, 1448, 1448], "flags": [2, 24, 24], "mark": [1, 1, 3], "rttUs": [0, 0, 0]
  }
}
```

  - **Columnar and delta-encoded:** `tUs[0]` is absolute (µs since the epoch), the rest are deltas from the previous sample; `seq`/`ack` are relative to `seqBase` per direction. This keeps 4 096 samples at about 200 KiB of JSON (about 8 numbers of ~6 characters each per sample), under the 256 KiB line ceiling, which the agent asserts before writing.
  - **Paging and live follow:** samples are indexed by a per-ring monotonic `u64` index. `fromIndex` asks for samples at or after it; the reply returns at most 4 096 from `max(fromIndex, firstIndex)` and `nextIndex`. A reader polls once per second while the graph is open and live, sending its `nextIndex`, so each poll returns only new samples. If `fromIndex < firstIndex`, older samples were overwritten: the reply's `droppedOlder` says how many, and the plot shows the gap.
  - **Absent cases:** `found: false` (no ring: not TCP, not tracked, or never allocated a ring), `stale: true` (generation changed). Both carry no samples.
- Agent side: answered synchronously from memory, bounded work (one ring), never subject to the packet-event limiter. If unflushed reply bytes on the relay connection exceed 512 KiB, answer `{ "busy": true }` (relay 503).
- Updated together, per the repo's wire rule: `capture-agent/src/wire.rs`, `lib/types.ts`, `lib/agent-mapping.ts`, `docs/wire-protocol.md`, tests on both sides.

### D6. Plots — **scope decided: the issue's four plots plus tcptrace overlays (James, 2026-11-11)**

Reached from the flow row in the Sockets view, a **"TCP graphs"** button next to "Trace Route" (TCP flows only). Opens a panel with a direction selector (default: outbound data) and four plots sharing a time axis (the IO graph's tick and pan/zoom code from `lib/io-graph.ts` and `components/IoGraphView.tsx` is reused, not copied):

1. **Time/sequence (Stevens):** one dot per data segment at (time, relative sequence end), so a healthy transfer is a staircase. Retransmissions drawn in red, RST/FIN marked.
2. **tcptrace overlays on (1):** the **ACK line** (the opposite direction's cumulative ACK over time) and the **receive window line** (ACK + advertised window, scaled when known). The gap between data and ACK is in flight; data reaching the window line is window-limited. A zero window shows as the window line meeting the ACK line, and is also marked.
3. **RTT over time:** one point per RTT sample (D3), with the handshake RTT as a reference line; labelled per D3's capture-point rule.
4. **Throughput per direction:** bytes per interval from the retained samples (interval chosen from the window, as the IO graph does), both directions on one plot.
5. **Window:** advertised window over time per direction, zero-window intervals shaded; labelled scaled/unscaled per D4.

- SVG, no charting dependency (IO graph spec D8's decision applies).
- Point budget: at most 4 096 samples per flow, so no decimation is needed; drawing reuses the IO graph's one-path-per-series approach. Performance: an update with a full ring stays within the 16.7 ms frame budget in production, measured by a Playwright spec as the IO graph's is.
- The horizon line ("samples since …; N older dropped") and, for a midstream join, "handshake not captured: sequence relative to first seen segment; window unscaled" are always visible when they apply.

### D7. Live and replay

Works on any flow with a ring, live and replay (`REPLAY_FILE`), since both feed `FlowTable`. Timestamps are frame timestamps (recorded time in replay), so a replay at any speed produces identical rings (tested as JAM-18 does). Recorded files on demand are JAM-255's question, not this one.

### D8. Scope

TCP only, IPv4 and IPv6. Not in this spec: SACK blocks, payload, UDP/QUIC, per-flow export, comparing two flows on one plot.

## Source disagreement (surfaced, not resolved here)

Jira shows **KAN-110 (Follow Stream) as Done**, but Follow Stream has not been implemented: only its spec (#290) and plan (#295) merged, no `follow.rs`, no `/api/follow-stream`, and the last migrated Linear comment says implementation had not started. This spec builds the relay request path Follow Stream's plan Task 4 describes, as shared code; Follow Stream's own content gate, payload store and admission numbers stay its own. KAN-110's status needs James's decision (reopen, or file a new implementation issue).

## Acceptance criteria → how each is met and tested

| Criterion (KAN-129) | Met by | Tested by |
| --- | --- | --- |
| Time/sequence plot for a real TCP flow shows the staircase, retransmissions marked | D2, D6 (1) | Rust: ring contents for a fixture flow with a forced retransmission; component test of the plot; real-agent check (replayed fixture with a retransmit) |
| RTT sampled continuously, not once at handshake | D3 | Rust: per-ACK samples, Karn exclusion on retransmit, duplicate ACK yields none, outstanding-table bound |
| Zero-window stall visually identifiable | D2 zero-window mark, D6 (2) and (5) | Rust: zero-window flag; component test; real-agent check with a zero-window fixture |
| Per-flow retention bounded, cost reported | D1 | Rust: 4 096-sample wrap with `droppedOlder`, 128-ring recycling of the least recently active, release on flow eviction and interface switch, reserved bytes in `capture_stats` |
| Rust tests cover sample collection; plot renders for a short fixture | D1–D4, D6 | as above, plus window-scale option parsing (fuzz seeds included) and a fixture flow rendered end to end in Playwright |

Plus the request path: AgentClient correlation (timeout, abort, disconnect, late/forged replies never reach SSE listeners), admission (concurrent requests beyond the limits get 429, one per flow, slots released only on HTTP finish/abort, slow-reader test), byte-bounded reply framing, route guards, and the 16.7 ms frame budget.

## Security-plan review (`docs/security-plan-review-checklist.md`)

- **§1 Bounds:** every store and reply bounded (D1, D3, D5), counted by reserved capacity; limit and limit+1 tests for each.
- **§2 Failure semantics:** absent, stale, busy and overwritten history are explicit states, never empty plots presented as data.
- **§3 Cryptography:** not applicable (no payload; random request IDs and epochs from the system RNG).
- **§4 Sensitive data:** header metadata only; the same fields already appear in `packet` events. Replies go only to the requesting HTTP client, never to the SSE broadcast.
- **§5 Time:** frame timestamps only; replay-speed equality test.
- **§6 Interfaces:** four files changed together; unknown fields ignored, unknown enum values visible as unknown.
- **§7 Tooling:** tests first per task; parse fuzz seeds for the window-scale option; reviewers state what they read and ran.

## Non-goals

SACK, payload, UDP/QUIC, recorded-file queries (JAM-255), multi-flow comparison, export.

## Next

On approval: an implementation plan under `docs/superpowers/plans/` in its own PR, splitting at least: (1) `tcp_samples.rs` ring, RTT matching and window-scale parsing; (2) the shared request core, admission and the Pages route; (3) the wire contract and agent integration; (4) the plots and the Sockets-view entry point.
