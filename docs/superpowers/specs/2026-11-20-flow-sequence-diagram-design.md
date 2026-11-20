# Flow Sequence Diagram (Ladder View) — Design Spec

**Issue:** KAN-130 (legacy JAM-20, GitHub #87) — "Flow sequence diagram: a ladder view of packet exchanges"
**Epic:** KAN-18 (Analysis surfaces, legacy JAM-127)
**Depends on:** KAN-129 TCP stream graphs (built: `capture-agent/src/tcp_samples.rs`, `pages/api/tcp-samples.ts`, `lib/tcp-samples-poll.ts`, `components/TcpGraphsView.tsx`). Nothing else.
**Status:** APPROVED (merged in PR #336). On 2026-11-20 James chose the recommendations for D2 (label table and pinned head) and D5 (per-flow only) in chat. Next: the implementation plan, `docs/superpowers/plans/2026-11-20-flow-sequence-diagram.md`.

## Problem

`components/PacketStreamView.tsx` is a flat, newest-first list. To see a TCP or TLS handshake, the reader has to rebuild it from timestamps and ports. A ladder diagram (participants as columns, time down the page, one arrow per segment) is the standard picture of how a protocol behaves. It is also the clearest teaching surface this product could have.

The 2026-10-11 readiness review (Jira comment) found four things the issue leaves open. This spec settles them:

1. **Source.** `packet` events are throttled to 100 per second (`PacketEventLimiter::new(100, 1000)`, `docs/wire-protocol.md` "Rate-limited event sampling"), and the browser keeps only the newest `buffer packets <n>` (100 by default). A ladder drawn from them can silently drop the SYN, the ClientHello or the FIN it exists to show. Its bulk totals would also be wrong.
2. **Click-to-select** for an arrow whose segment never became a `packet` event.
3. **Bounds:** the maximum number of rows, and an exact, testable collapse rule.
4. **Scope:** whether per-host-pair mode is in the first cut.

## What this spec promises, and what it does not

- **Promised:** every arrow is a TCP segment the agent actually observed on this flow, at its own capture timestamp, drawn from KAN-129's sample ring. The ring is filled before the packet-event limiter, so no segment is missing within the retained window. Where history is missing (older segments overwritten, the flow joined midstream, the flow has no ring), the ladder says so in a row of its own and never draws a gap as if nothing happened. Bulk totals are counts over retained segments and are labelled that way.
- **Not promised:** the whole life of a long flow (the ring rolls, KAN-129 D1). Not UDP, QUIC, ICMP or DNS-over-UDP. Not reassembled application messages: a label comes from one segment's own bytes. Not a guaranteed link to the packet view, which holds only sampled frames (D4).

## Source disagreements (surfaced, not resolved here)

- The issue says the ladder "reuses data already on the wire (`headerBreakdown`, TCP flags, L7 summaries)". There is no `headerBreakdown` field today; the per-packet data is the `fields` list. The `packet` events are sampled (Problem §1). TCP flags and sequence numbers are complete only in the `tcp_samples` reply, which carries no application labels. The ladder therefore needs one wire addition (D2) or must give up the ClientHello/SNI criterion on busy captures (D2 alternative).
- The issue says "renders legibly at terminal widths". The product is a web UI styled as a terminal, not a terminal program. This spec reads that as the panel's narrowest supported width (D6).

## Decisions

### D1. Source: KAN-129's sample ring, through the existing route

The ladder reads the same `POST /api/tcp-samples` route, poller and `TcpGraphState` as the TCP graphs. It does not add a new route, a control message or a second admission class.

- **One poller per flow, shared.** Admission allows one request in flight per `connectionId` (KAN-129 D5). Two independent pollers on the same flow would refuse each other with 429. The ladder is therefore a second tab, **Graphs | Ladder**, of the panel `app/page.tsx` already opens for `tcpGraphsFor`. It shares the one `TcpSamplesPoller` and its state. The flow row gets a **Ladder** button next to "TCP graphs" and "Trace Route" (TCP flows only), which opens the same panel on the Ladder tab.
- **Live and pause:** exactly as the graphs: polled once per second while live (`tcpGraphsLive`), stopped while paused. An interface switch clears the rings, and the next reply comes back `found: false` or `stale`.
- **Replay** works unchanged, because replay feeds `FlowTable` as live capture does.
- **Absent states,** each shown as a one-line notice instead of an empty ladder:
  - `found: false`: "No segment history for this flow." Only 128 flows keep one, a flow can be evicted, and non-TCP flows have none.
  - `stale`: the flow was replaced; the ladder starts over, as the graphs do.
  - Retained window starts after the first segment: a gap row (D3).

### D2. Labels and the pinned handshake head — **decided: (a) and (b) (James, 2026-11-20)**

The ring holds header fields only, so it can label `SYN`, `SYN,ACK`, `FIN,ACK`, `RST` and `PSH,ACK len=1448` but not `ClientHello (SNI: example.com)`. Two additions to the ring would close that gap. Both change the `tcp_samples` reply, so per the repo's wire rule `capture-agent/src/wire.rs`, `lib/types.ts`, `lib/agent-mapping.ts`, `docs/wire-protocol.md` and the tests on both sides change together.

**(a) A bounded label table per ring.** When the capture loop's `ParsedPacket` for a sampled segment carries one of the following, the ring records a label against that sample's index. This happens before the limiter, from the same parse every frame already gets.

| Kind | Source (already parsed today unless noted) | Text |
| --- | --- | --- |
| `tls_client_hello` | `L7Info::TlsClientHello` (present only when the hello has SNI) | `ClientHello (SNI: <sni>)` |
| `tls_server_hello` | **New, header-only check:** the segment payload starts with record type 22, version major 3 and handshake type 2. Six bytes are read; nothing else is parsed. | `ServerHello` |
| `http_request` | `http.request.method` and `http.request.uri` | `HTTP <method> <path>`, query and fragment removed |
| `http_response` | `http.response.code` and `http.response.phrase` | `HTTP <code> <phrase>` |

- **Text:** printable ASCII only; anything else is escaped as `\u{..}`, as `unanswered-request` summaries already are. Cut at 64 bytes after escaping, on a whole escape. The query string is dropped because it often carries tokens; the path is kept, as `http.request.uri` already appears in full in `packet` events. The phrase goes through the existing HTTP redaction.
- **Bound:** at most 32 labels per ring. A label is dropped when its sample is overwritten, or, when the table is full, the oldest label goes first. Labels on the pinned head (b) are never dropped this way; there are at most 16 of them, so at least 16 slots always remain for the rolling part. A label is one byte of kind, a `u64` index and at most 64 bytes of text: about 2.4 KiB per ring, about 300 KiB across 128 rings. It is counted in the existing `tcpSampleRingBytes`, allocated with the ring, released with it and cleared on interface switch.
- **A ClientHello without SNI** produces no `L7Info` today, so it gets no label. Extending `l7.rs` for it is out of scope.

**(b) A pinned head of the first 16 samples.** The ring rolls, so on a long flow the handshake, the very part a teaching view exists to show, is overwritten first. The ring keeps its first 16 samples (indices 0–15) and their labels separately and never overwrites them: 16 × 32 B = 512 B per ring, 64 KiB across 128 rings, also counted in `tcpSampleRingBytes`. When `fromIndex` is below 16 the reply carries a `head` block with the same columnar layout. A reader that has the head does not ask for it again.

**Reply budget.** KAN-129 caps a reply at 3,072 samples so that the worst case stays under the 256 KiB line ceiling. Labels (at most 32 × about 160 JSON bytes, worst case with every character escaped) and a head (16 × 79 B) add at most about 6.5 KiB. The plan must recompute the worst case exactly and lower the per-reply sample cap if it no longer fits. The agent keeps measuring each line before it writes it.

**Recommendation: (a) and (b) together.** Without (a), the ClientHello/SNI acceptance criterion holds only when the hello happened to become a `packet` event. Without (b), any flow older than 4,096 segments shows no handshake at all.

**Alternative (no wire change):** draw flags from the ring and attach an application label only where a buffered `packet` event matches the segment (D4's key). This is cheap but unreliable on a busy capture. The ladder would have to label it: "application labels only for frames still in the packet view".

### D3. Rows, collapse and bounds (exact, testable)

The ladder is built by a pure function in `lib/flow-ladder.ts`: `buildLadder(state) → Row[]`. Its input is the retained samples (head and rolling part) in index order, with their labels.

**Row kinds:** `arrow` (one segment), `run` (a collapsed run), `gap` (segments not retained) and `elided` (rows hidden by the row cap).

1. **Gap rows.** Between two consecutive retained indices *i* and *j* with *j > i + 1*, insert `gap { missing: j − i − 1 }`. This covers the space between the head and the rolling part, and the reader's own `droppedOlder`. Text: "1,822 segments not retained".
2. **Interesting segments** are always their own `arrow` row. A segment is interesting if any of these holds: SYN, FIN or RST is set; the `RETRANSMIT` or `ZERO_WINDOW` mark is set; it has a label; or it is the first segment with payload in its direction.
3. **Bulk segments** are every other segment (data with no label, or pure ACKs). A maximal sequence of consecutive bulk segments, not interrupted by an interesting segment or a gap, is a **run**. A run of at most `RUN_DRAW_MAX = 4` segments is drawn as arrows. A longer run becomes one `run` row: "1,203 segments over 2.310 s · → 1,190 data, 1.40 MB · ← 13 ACKs". Counts and byte totals are per direction, over retained segments only. Bytes are the sum of `len`, in decimal units, as the rest of the UI uses.
4. **Row cap.** If more than `MAX_ROWS = 200` rows remain, keep the first 100 and the last 100 and put one `elided { rows, segments }` row between them: "412 rows not shown (9,877 segments)". The first rows hold the handshake and the last hold the live tail. The cap applies after collapsing, so a busy flow normally needs none.
5. **Determinism.** The same samples and labels always produce the same rows; live polling only appends. Unit tests cover each rule at the boundary: a run of 4 is drawn and a run of 5 collapses; 200 rows are drawn and 201 are elided; a retransmission inside a bulk run splits it in two; a gap splits a run; and a head plus a rolling part produces exactly one gap row.

**Arrow text.** Flags in the `SYN`, `SYN,ACK` style (PSH included, since the ring has it), then `len=<n>` when `len > 0`, then the label if any: `PSH,ACK len=517 · ClientHello (SNI: example.com)`. Retransmissions add `retransmission`, and zero windows add `zero window`. Sequence and ACK numbers are relative, as the reply provides them (`relativeTo` is shown once in the header: "relative to ISN" or "relative to first seen segment").

### D4. Click-to-select in the packet view

The packet view holds only sampled frames, at most `buffer packets <n>`. Linking is a best-effort lookup, stated as such.

- **Match key:** a buffered `PacketFrame` matches a sample when all of these agree: the flow (its `src`/`dst` equal the connection's local and remote endpoints, in the sample's direction); the raw sequence number (`seqBase` for that direction plus the relative `seq`, mod 2³²) equals `tcp.seq`; the raw ACK number equals `tcp.ack_number` when ACK is set; the SYN, ACK, FIN and RST flags equal the `tcp.flags.*` fields (PSH is not in `fields`); and the timestamp in milliseconds equals `floor(tUs / 1000)`. The plan must check IPv6 endpoint formatting between `PacketFrame.src` and `NetworkConnection` before relying on string equality.
- **Ambiguity fails closed.** If two samples or two frames share a key (an identical retransmission within the same millisecond), neither is linked.
- **Linked arrow:** it is marked with a small "in packet view" affordance. Clicking it, or pressing Enter on it, switches to the Packets tab and selects and inspects that frame. This adds one optional prop to `PacketStreamView`, `focusPacketId`, following JAM-18's IO-drill precedent (`openIoDrill`). The lookup is repeated at click time; if the frame has since left the buffer, the ladder says so and stays put.
- **Unlinked arrow:** clicking it selects the row in the ladder and shows its sample details underneath (time, direction, flags, relative seq and ack, window, len, label). The text reads: "Not in the packet view: packet events are sampled at 100 per second and the view keeps the newest N." No navigation happens.
- `run`, `gap` and `elided` rows are not links.
- **Alternative considered:** the agent could record which segments became `packet` events and give the event id in the reply, for an exact link. That needs the limiter's decision fed back into the ring and widens the sample. Rejected for the first cut, because the client-side key is exact except in the ambiguous case, which fails closed.

### D5. Per-host-pair mode — **decided: out of the first cut (James, 2026-11-20)**

A host-pair ladder would merge several flows' rings (each separately bounded, with separate horizons and gaps) into one time order, with one column per endpoint and port. That multiplies the gap and horizon wording and the admission requests (one per flow). Per flow only now; host-pair is a follow-up issue if it is wanted.

### D6. Rendering and width

- **DOM rows, not SVG or a canvas.** Each row is one focusable element in a list (`role="list"`, arrows as buttons). Up and Down move the selection and Enter follows a link. That keeps the view accessible and keyboard driven, and fits the terminal styling. No charting dependency.
- **Layout:** a fixed time column (`+12.345 ms` relative to the first retained segment, or to the head's first when present), then a lane area with the two lifelines (local on the left, remote on the right, labelled `host:port`, truncated with an ellipsis). The arrow is a CSS line with an arrowhead (`→` or `←`) across the lane area, with its text above the line. Text is truncated with an ellipsis; the full text is in the row's accessible name and in the details line.
- **Colour:** the existing per-layer colour language (TCP rows use the L4 colour, TLS labels the L6 colour, HTTP labels the L7 colour; the plan names the tokens). Retransmissions and RST use the existing warning colour. Colour never carries meaning alone: every state is also in the text.
- **Width:** no horizontal scrolling from a 320 CSS px panel upward. Tested by Playwright at 320 px and 1,280 px, asserting `scrollWidth <= clientWidth` on the panel with the longest possible label.
- **Header:** the flow, the "relative to …" note, the retained horizon ("segments since 14:05:10.123") and the source note: "complete within the retained window; not sampled".
- **Performance:** at most 200 rows, so no virtualisation. `buildLadder` over a full ring (4,096 plus 16 samples) must stay within the 16.7 ms frame budget in a production build, measured as the TCP graphs' is.

### D7. Scope

TCP only, IPv4 and IPv6, one flow at a time. Not in scope: UDP and QUIC, DNS ladders, expanding a collapsed run, exporting the diagram, comparing two flows, a ClientHello without SNI (D2), and reassembled HTTP messages.

## Acceptance criteria → how each is met and tested

| Criterion (KAN-130) | Met by | Tested by |
| --- | --- | --- |
| A TCP handshake and close render as a readable ladder with flags labelled | D1, D3 | `buildLadder` unit tests on a fixture flow (SYN / SYN,ACK / ACK … FIN,ACK / ACK); component test; real-agent check on a replayed fixture |
| A TLS handshake shows ClientHello/ServerHello with SNI where known | D2 (a), (b) | Rust: label recorded for a ClientHello with SNI and for a ServerHello header; no label for a non-TLS segment, a short payload or a ClientHello without SNI; 32-label bound and the drop-with-sample rule; head retained past 4,096 samples. Wire tests on both sides. Replayed TLS fixture end to end. |
| Bulk transfer is summarised rather than drawn packet by packet | D3 | the run-of-4 and run-of-5 boundary tests, per-direction totals, a retransmission splitting a run, and the 200/201 row cap |
| Clicking an arrow selects the frame in the packet view | D4 | unit tests for the match key (IPv4 and IPv6, wrap-around of the raw sequence number, an ambiguous key that links nothing); a component test that a linked click selects the frame and an unlinked click shows the "not in the packet view" details |
| Renders legibly at terminal widths without horizontal scrolling | D6 | Playwright at 320 px and 1,280 px |

## Security-plan review (`docs/security-plan-review-checklist.md`)

- **§1 Bounds:** labels (32 per ring, 64 bytes each), the head (16 samples), rows (200) and the reply (recomputed worst case under 256 KiB, measured before writing). Each has a test at the limit and at limit + 1.
- **§2 Failure semantics:** absent, stale, not-retained and elided history are explicit rows or notices. A link that cannot be resolved without ambiguity is not offered.
- **§3 Cryptography:** not applicable. No key material, no decrypted data; the ServerHello check reads six cleartext header bytes.
- **§4 Sensitive data:** labels hold SNI (already in `packet` events as `tls.handshake.sni`), the HTTP method and path (query dropped, already in `packet` events), and the status code and redacted phrase. Labels are display-escaped in the agent and rendered as text, never as HTML. Replies go only to the requesting client (KAN-129 D5).
- **§5 Time:** frame timestamps only; a replay-speed equality test covers labels and the head as KAN-129's covers samples.
- **§6 Interfaces:** the four wire files change together. Unknown label kinds are shown as `unknown label`, not dropped silently.
- **§7 Tooling:** tests first per task. The ServerHello check is covered by exhaustive short-input unit tests. *(Amended 2026-11-20, plan decision P5: first written as `parse_packet` fuzz seeds, which would not reach the check, because it runs in `flow.rs`.)* The strings labels are built from come from `l7.rs`, which the existing `parse_packet` and `l7_transactions` fuzz targets cover.

## Non-goals

Host-pair ladders (D5), UDP/QUIC/DNS, recorded-file queries (KAN-125's query service), expanding runs, export.

## Next

An implementation plan under `docs/superpowers/plans/` in its own PR, split at least into: (1) the label table, ServerHello check and pinned head in `tcp_samples.rs`, with the reply budget; (2) the wire contract on both sides; (3) `lib/flow-ladder.ts` (`buildLadder`, the match key); (4) the Ladder tab, row component, `focusPacketId` and the entry button.
