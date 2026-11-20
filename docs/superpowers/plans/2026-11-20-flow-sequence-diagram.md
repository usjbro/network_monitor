# Flow Sequence Diagram (Ladder View) — Implementation Plan

**Spec:** `docs/superpowers/specs/2026-11-20-flow-sequence-diagram-design.md` (merged in PR #336). On 2026-11-20 James decided D2 (a)+(b) and D5 (out) in chat, and approved gate `kan-130__flow-sequence-diagram-plan` for this plan.
**Issue:** KAN-130 (legacy JAM-20, GitHub #87), epic KAN-18.
**Builds on:** KAN-129 (`capture-agent/src/tcp_samples.rs`, `flow.rs` `observe_inner`, `wire.rs` `answer_tcp_samples`, `pages/api/tcp-samples.ts`, `lib/tcp-samples-poll.ts`, `lib/tcp-graphs.ts`, `components/TcpGraphsView.tsx`).
**This PR:** plan only, no code. Each task below is its own PR, implemented through its own approved gate, in order. Each must merge before the next starts.

## Global constraints

- Next.js and the agent stay on `127.0.0.1`. Preserve the `--webpack` flags and `next.config.ts` watch behaviour. No Caddy changes.
- No new route, control message or admission class. The ladder uses `/api/tcp-samples` and its limits unchanged (spec D1).
- `tcp_samples` replies still go only to the requesting client and never reach the SSE feed (KAN-129 D5).
- Bounds, each tested at the limit and at limit + 1:
  - At most 32 labels per ring. Labels on the head are pinned; at most 16 exist, so at least 16 slots stay for the rolling part (spec D2).
  - Label text ≤ 64 bytes, printable ASCII only.
  - Head of 16 samples per ring.
  - Reply line ≤ 256 KiB including LF, for every possible value (Task 2 proves the worst case).
  - `MAX_ROWS = 200` and `RUN_DRAW_MAX = 4` (spec D3).
- The ring's only new payload-derived data is the label text of spec D2: SNI, HTTP method and path with no query or fragment, and HTTP status code and redacted reason phrase. Nothing else from the payload enters the ring, the reply or a log.
- Frame timestamps only, so a replay at any speed gives identical labels and heads (KAN-129 D7).
- Tests first in every task. Show the new test failing for the missing behaviour before implementing it (CLAUDE.md workflow step 4).
- Wire changes update `capture-agent/src/wire.rs`, `lib/types.ts`, `lib/agent-mapping.ts` and `docs/wire-protocol.md` in the same PR (Task 2).

## Decisions taken by this plan (review before Task 1)

These are implementation choices the spec leaves open. James's approval of this plan covers them.

- **P1. Labels are derived where the sample is recorded.** `FlowTable::observe_inner` already passes the `L7Info` and `packet.payload` of the segment it samples. It calls a new pure function, `tcp_samples::label_for(l7: &L7Info, payload: &[u8]) -> Option<SampleLabel>`, and hands the result to `TcpSampleStore::record`, which gets an `Option<SampleLabel>` parameter. The capture loop and `main.rs` do not change.
- **P2. The head is a copy, not a separate index space.** A ring copies its first 16 samples into a fixed `head: [TcpSample; 16]` as they are recorded. Indices stay the ring's own: the head holds indices 0–15. While the rolling buffer still holds them (`first_index == 0`), a view returns them once, as ordinary samples. A view returns a `head` block only when `from_index < head_len` and `first_index > from_index`, and then only the head samples at or after `from_index`. A sample is therefore never sent twice in one reply.
- **P3. The label table is a fixed array.** It is `[SampleLabel; 32]`, with `SampleLabel { index: u64, kind: LabelKind, len: u8, text: [u8; 64] }`. Eviction:
  - A label whose index is ≥ 16 and below `first_index` is dropped when its sample is overwritten.
  - When the table is full, the lowest-index label at or above 16 is dropped.
  - Labels below 16 are never evicted.

  It is allocated with the ring, released with it and cleared on interface switch. `RING_RESERVED_BYTES` gains `size_of::<[SampleLabel; 32]>() + size_of::<[TcpSample; 16]>()`, and its two `const` assertions are updated to the new exact bounds.
- **P4. One display-safe text helper.** `transaction.rs`'s private `display_safe` (which escapes as `\u{..}`) moves to a new `capture-agent/src/display_text.rs`. `display_safe_chars(text, max_chars)` keeps today's behaviour, including the `…`, and `unanswered-request` summaries are unchanged; that module's existing tests move with it. A new `display_safe_bytes(text, max_bytes) -> String` returns printable ASCII only: it cuts on a whole escape and marks a cut with `...` inside the limit. Labels use `display_safe_bytes(…, 64)`.
- **P5. ServerHello check: unit tests, not fuzz.** `is_tls_server_hello_start(payload)` guards the length (`payload.len() >= 6`) and makes three byte comparisons: `[0] == 22`, `[1] == 3`, `[5] == 2`. Each payload length from 0 to 8 is tested, along with each byte changed. This replaces spec §7's "parse_packet fuzz seeds", which would not reach this function, since it runs in `flow.rs`, not `parse_packet`. The rest of `label_for` only reads strings `l7.rs` already produced under its own fuzz coverage (`parse_packet`, `l7_transactions`).
- **P6. TCP graphs ignore the head.** `lib/tcp-graphs.ts` keeps the head and labels in new state fields (`head`, `labels`). Its plots use only the rolling samples, so KAN-129's plots and their tests do not change.
- **P7. Focusing a frame clears the packet view's local filters.** `PacketStreamView` gains `focusPacketId?: string` and `onFocusHandled?: () => void`. When it gets an id that is in `packets`, it clears its own search term and layer filter, unfreezes, selects and inspects that frame, scrolls it into view, then calls `onFocusHandled`. `app/page.tsx` also clears an active IO drill before switching tabs. If the id is not in the buffer, nothing changes and the ladder shows "This frame has left the packet view."
- **P8. The panel's tab is page state.** `app/page.tsx` gains `tcpPanelTab: 'graphs' | 'ladder'`. "TCP graphs" opens the panel on Graphs; the new "Ladder" button opens it on Ladder. Both use the existing `openTcpGraphs(connectionId)`, so one poller serves both tabs (spec D1).

## PR sequence

| Task | Responsibility | Files | Depends on |
| --- | --- | --- | --- |
| 1 | Label table, ServerHello check, pinned head, display-text helper; agent-internal only, no wire change | create `capture-agent/src/display_text.rs`; modify `src/tcp_samples.rs`, `src/flow.rs`, `src/transaction.rs`, `src/lib.rs` | plan merged |
| 2 | Wire contract: `head` and `labels` in the reply, worst-case budget, browser state | modify `src/wire.rs`, `capture-agent/tests/tcp_samples_replay.rs`, `capture-agent/tests/fixtures/replay_capture.rs`, `lib/types.ts`, `lib/agent-mapping.ts`, `lib/tcp-graphs.ts`, `docs/wire-protocol.md`; tests both sides | 1 |
| 3 | Pure ladder model: rows, collapse, arrow text, packet-view match key | create `lib/flow-ladder.ts`, `lib/__tests__/flow-ladder.test.ts` | 2 |
| 4 | Ladder tab, row component, entry button, `focusPacketId`, width and click e2e, docs | create `components/FlowLadderView.tsx`, `e2e/flow-ladder.spec.ts`, component tests; modify `components/TcpGraphsView.tsx` (tabs), `components/ConnectionsView.tsx`, `components/PacketStreamView.tsx`, `app/page.tsx`, `docs/usage.md` | 3 |

## Task 1 / PR 1: labels, head and the ServerHello check (agent-internal)

**Interfaces (new):**

```rust
// capture-agent/src/tcp_samples.rs
pub const HEAD_SAMPLES: usize = 16;
pub const MAX_LABELS_PER_RING: usize = 32;
pub const LABEL_TEXT_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelKind { TlsClientHello, TlsServerHello, HttpRequest, HttpResponse }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleLabel { pub index: u64, pub kind: LabelKind, len: u8, text: [u8; LABEL_TEXT_BYTES] }
impl SampleLabel { pub fn text(&self) -> &str; }   // always printable ASCII

pub fn is_tls_server_hello_start(payload: &[u8]) -> bool;
pub fn label_for(l7: &L7Info, payload: &[u8]) -> Option<(LabelKind, String)>; // index set by record

// TcpSampleStore::record gains `label: Option<(LabelKind, String)>`.
// RingView gains `head: Vec<TcpSample>` (P2) and `labels: Vec<SampleLabel>`,
// the labels whose index is in the view's head or samples, in index order.
```

**`label_for`, in order (first match wins):**
1. `L7Info::TlsClientHello { sni, .. }` gives `ClientHello (SNI: <sni>)`.
2. `is_tls_server_hello_start(payload)` gives `ServerHello`.
3. `L7Info::Http { method, path }` gives `HTTP <method> <path>`, with `path` cut at the first `?` or `#`.
4. `L7Info::HttpResponse { status, reason, .. }` gives `HTTP <status>`, plus ` <reason>` when present. `l7.rs` already redacts the reason.
5. Otherwise `None`. The whole string goes through `display_safe_bytes(…, 64)`.

**Tests first (Rust):**
- `label_for`, one test per kind. A ClientHello with no SNI yields no `L7Info`, hence no label. A DNS segment and an empty payload yield no label. A query string and a fragment are removed. Control characters, a bidi override and non-ASCII text come out escaped. A 200-byte path is cut at exactly 64 bytes and never mid-escape.
- `is_tls_server_hello_start`: lengths 0–8, each of the three bytes off by one, a ClientHello (type 1) and an application-data record (type 23). All fail except the exact match.
- Store: labels are recorded with their sample's index. The 32-slot bound holds at limit + 1, and the lowest rolling label is evicted first. Head labels survive 10,000 later labelled segments. A rolling label goes with its overwritten sample. A ring that is released, or cleared on interface switch, keeps no labels.
- Head: after 4,096 + 100 samples, `view(from_index = 0)` returns `head` holding indices 0–15 and `samples` from `first_index`, with no index twice. Before the ring wraps there is no `head` block. `view(from_index = 10)` after a wrap returns head indices 10–15. A flow with fewer than 16 segments has a short head.
- `reserved_bytes` and `RING_RESERVED_BYTES` include the head and label table, with exact numbers asserted. The `capture_stats` cost test is updated.
- `display_text.rs`: the moved `display_safe` tests are unchanged and still pass. New `display_safe_bytes` tests cover the byte limit, a cut on a whole escape, `...`, and ASCII-only output.
- Flow integration (`flow.rs` tests): a TCP fixture flow with a ClientHello (reuse `l7.rs`'s hand-built ClientHello helper) and a ServerHello header produces labels at the right indices. An IP-fragmented segment is still not sampled and not labelled twice.

**Done when:** `cargo test`, `cargo clippy --all-targets -- -D warnings`, and the existing fuzz targets build. No wire output changes; a grep of `wire.rs` shows no new field yet.

## Task 2 / PR 2: wire contract and budget

**Reply additions** (`tcp_samples`, `found: true, stale: false` only):

```json
{
  "head": { "firstIndex": 0, "tUs": [1794120000000000, 1200], "seq": [0, 0], "ack": [0, 1], "win": [65535, 65535],
            "len": [0, 0], "flags": [2, 18], "mark": [1, 0], "rttUs": [0, 0] },
  "labels": [[3, "tls_client_hello", "ClientHello (SNI: example.com)"], [5, "tls_server_hello", "ServerHello"]]
}
```

- `head` is present only under P2's condition. It uses the same columnar, delta-encoded layout as `samples`; `tUs[0]` is absolute.
- `labels` is always present, possibly empty. Each entry is `[index, kind, text]` and covers only indices in this reply's `head` or `samples`, in index order. Kinds are `tls_client_hello`, `tls_server_hello`, `http_request` and `http_response`. The browser keeps a kind it does not recognise and shows it as `unknown label` (spec §6).
- **Budget:** a test builds the worst-case reply and asserts the encoded line is at most 262,144 bytes including LF. The worst case is `TCP_SAMPLES_MAX_PER_REPLY` samples and 16 head samples with every column at its maximum, and 32 labels with 20-digit indices and 64 bytes of text that each need JSON escaping (64 backslashes, 128 bytes encoded). Estimate: 242,688 + 1,264 + 32 × about 175 ≈ 249,600 bytes plus the envelope, so the cap of 3,072 is expected to stand. If the test fails, the cap is lowered to the largest value that passes. That value is recorded in `docs/wire-protocol.md` and the spec as an amendment. `encode_tcp_samples_reply` keeps measuring every line before writing it.

**Browser:**
- `lib/types.ts`: the `TcpSamplesPage` success arm gains `head: TcpSample[] | null` and `labels: { index: number; kind: string; text: string }[]`.
- `lib/agent-mapping.ts` `mapTcpSamplesReply`: decodes `head` with the same delta decoder as `samples`. It validates labels: an integer index, a string kind, and a string text of at most 64 characters, all printable ASCII. A malformed label is dropped and counted in the mapping's existing malformed handling; one bad label does not reject the reply.
- `lib/tcp-graphs.ts` `accumulate`: the state keeps `head` (kept from the first page that carried it) and `labels` (a `Map<number, …>`). Labels are pruned with their samples when `MAX_SAMPLES` trims, except head labels. A `stale` reply or a new generation clears both. KAN-129's plot inputs are unchanged (P6).

**Tests first:**
- Rust `wire.rs`: the head appears only under P2's condition, label encoding, labels limited to the reply's indices, and the worst-case budget test.
- `capture-agent/tests/tcp_samples_replay.rs`: a replayed fixture (built in `fixtures/replay_capture.rs`) with a TCP handshake, ClientHello with SNI, ServerHello, an HTTP/1.1 request and response, more than 4,096 data segments and a FIN close. The reply has the head, all four labels, and identical results at replay speeds 1× and max.
- `lib/__tests__/tcp-samples-wire.test.ts`: head decoding, label validation (a bad index, an over-long text, non-ASCII text, an unknown kind kept), and an existing reply without `head` or `labels` fields still maps.
- `lib/__tests__/tcp-graphs.test.ts`: head and labels survive trimming, are cleared on stale or a new generation, and the plot series are unchanged.

**Docs:** `docs/wire-protocol.md` `tcp_samples` section, covering both fields, the P2 rule, the label kinds, the payload-derived content and the budget.

## Task 3 / PR 3: the ladder model (`lib/flow-ladder.ts`)

```ts
export const RUN_DRAW_MAX = 4;
export const MAX_ROWS = 200;
export type LadderRow =
  | { kind: 'arrow'; index: number; sample: TcpSample; text: string; label?: LadderLabel; interesting: boolean }
  | { kind: 'run'; firstIndex: number; lastIndex: number; segments: number; spanUs: number;
      out: { data: number; bytes: number; acks: number }; in: { data: number; bytes: number; acks: number } }
  | { kind: 'gap'; afterIndex: number; missing: number }
  | { kind: 'elided'; rows: number; segments: number };
export function buildLadder(state: TcpGraphState): LadderRow[];
export function arrowText(sample: TcpSample, label?: LadderLabel): string;
export function packetKey(frame: PacketFrame, conn: NetworkConnection): LadderKey | null;
export function sampleKey(sample: TcpSample, seqBase: { outbound: number; inbound: number }): LadderKey;
export function linkSamples(rows: LadderRow[], frames: PacketFrame[], conn: NetworkConnection,
                            seqBase: { outbound: number; inbound: number }): Map<number, string>; // sample index → packet id
```

- The rules are exactly spec D3 (gap, interesting, run, row cap) and D4 (key, ambiguity fails closed). "First segment with payload in its direction" is computed over the retained samples handed to `buildLadder`.
- `packetKey` reads `tcp.seq`, `tcp.ack_number` and `tcp.flags.{syn,ack,fin,rst}` from `frame.fields`. It returns `null` for a frame without them (not TCP). Direction comes from comparing `frame.src` with the connection's local endpoint. The test suite first records how `src` is formatted for IPv6 (from `lib/agent-mapping.ts` and its tests) and compares canonical forms, never raw strings, so `[::1]:443` and `::1` plus port 443 match.
- Raw sequence: `(seqBase[dir] + seq) >>> 0`. Raw ACK: `(seqBase[opposite] + ack) >>> 0`. The timestamp match is `Number(frame.timestamp) === Math.floor(tUs / 1000)`.

**Tests first** (`lib/__tests__/flow-ladder.test.ts`):
- Handshake and close fixture gives the exact rows and arrow texts.
- A run of 4 is drawn and a run of 5 collapses, with per-direction totals.
- A retransmission splits a run, and so does a gap.
- A head plus a rolling part gives exactly one gap row with the right `missing`.
- 200 rows stay as they are; 201 rows give 100 + elided + 100 with correct counts.
- The same input always gives the same rows, and appending samples changes only the tail.
- Match key: IPv4 and IPv6, a raw sequence that wraps past 2³², an ACK-less segment, a frame from another flow, and two frames with the same key, which link neither.
- An unknown label kind gives `unknown label`.
- Performance: `buildLadder` on 4,096 + 16 samples with 32 labels runs in under 16.7 ms. This is measured in the Vitest run with a generous CI margin; the real frame budget is checked in Task 4's production e2e, as KAN-129's was.

## Task 4 / PR 4: the Ladder tab and entry point

- `components/TcpGraphsView.tsx` gets a **Graphs | Ladder** tab strip, controlled by `tab` and `onTab` props (P8). The Graphs content is unchanged.
- `components/FlowLadderView.tsx` renders `buildLadder(state)` as spec D6 describes:
  - a `role="list"` with one focusable row per entry;
  - arrows as buttons, Up and Down to move, Enter to follow a link;
  - a time column, two lifelines and a CSS arrow with truncated text;
  - the full text in the accessible name and in the details line;
  - the per-layer colour tokens TCP→L4, TLS→L6 and HTTP→L7, using the same tokens `PacketStreamView` uses for layers (named in the PR);
  - the warning token for retransmissions and RST, with text always present;
  - the header with the flow, "relative to …", the horizon and "complete within the retained window; not sampled";
  - absent and stale notices as in spec D1.
- `linkSamples` runs over `packets` from `app/page.tsx` each render. A linked arrow shows "in packet view". On click, `app/page.tsx` repeats the lookup, clears an IO drill, sets `focusPacketId` and switches to Packets (P7). An unlinked arrow shows its details and the spec D4 sentence.
- `components/ConnectionsView.tsx`: a **Ladder** button next to "TCP graphs", for TCP flows only, calling a new `onOpenLadder(connectionId)`.
- `components/PacketStreamView.tsx`: `focusPacketId` and `onFocusHandled` as in P7.
- `docs/usage.md`: a "Flow ladder" section. The "TCP graphs" paragraph's "never payload" sentence is corrected: the ring now also keeps a short label derived from a segment's payload (SNI, HTTP method and path without query, status line).

**Tests first:**
- Component tests: tab switching keeps one poller (assert one `fetchTcpSamples` call per tick).
- Component tests: rows render for the Task 3 fixture.
- Component tests: keyboard navigation works.
- Component tests: a linked click calls back with the packet id; an unlinked click shows the details; a frame that has left the buffer shows the notice.
- Component tests: `PacketStreamView` with `focusPacketId` clears its filters and selects the frame.
- `e2e/flow-ladder.spec.ts`, against the fake agent (`e2e/fake-agent.ts`, extended with a `tcp_samples` reply carrying a head and labels):
  - the ladder opens from the flow row;
  - the handshake, ClientHello (SNI) and ServerHello rows are visible;
  - a collapsed run is visible;
  - clicking a linked arrow lands on Packets with that frame inspected;
  - at 320 px and 1,280 px the panel has `scrollWidth <= clientWidth`, tested with a 64-byte label;
  - in a production build, a full-ring update stays within the 16.7 ms frame budget, measured as `e2e/tcp-graphs.spec.ts` does.
- Real-agent check (manual, recorded in the PR): replay the Task 2 fixture with `REPLAY_FILE` and open the ladder.

## Acceptance → owning task

| Criterion (KAN-130) | Task |
| --- | --- |
| TCP handshake and close as a readable ladder with flags | 3 (rows and text), 4 (rendering) |
| TLS ClientHello/ServerHello with SNI where known | 1 (labels and head), 2 (wire), 4 (rendering) |
| Bulk transfer summarised | 3 |
| Click an arrow to select the frame in the packet view | 3 (match key), 4 (navigation) |
| No horizontal scrolling at terminal widths | 4 |

## Security checklist (`docs/security-plan-review-checklist.md`) → where proven

- **§1 Bounds:** labels, text, head (Task 1); reply budget (Task 2); rows (Task 3). Each is tested at the limit and at limit + 1.
- **§2 Failure semantics:** gap, elided, absent and stale states (Tasks 3, 4); ambiguous links fail closed (Task 3); malformed labels are dropped, not fatal (Task 2).
- **§3 Cryptography:** not applicable; six cleartext header bytes are read (Task 1, P5).
- **§4 Sensitive data:** the label content is limited to P1's list. The query is dropped and the reason phrase is already redacted (Task 1). The text is escaped in the agent, validated in the browser (Task 2) and rendered as text only (Task 4). The usage doc's "never payload" claim is corrected (Task 4).
- **§5 Time:** replay-speed equality for labels and head (Task 2).
- **§6 Interfaces:** the four wire files change together, and unknown kinds stay visible (Task 2).
- **§7 Tooling:** tests first in each task. P5 replaces fuzz seeds with exhaustive short-input tests, and the change is stated here and in the spec.

## Validation for this plan PR

Docs only. Every file, function and constant named above was checked against `main` at b449696: `flow.rs` `observe_inner` and its `record` call, `tcp_samples.rs` `RingView`, `RING_RESERVED_BYTES` and its assertions, `wire.rs` `TCP_SAMPLES_MAX_PER_REPLY`, `encode_tcp_samples_reply` and `answer_tcp_samples`, `l7.rs` `L7Info`, `transaction.rs` `display_safe`, `app/page.tsx` `openTcpGraphs` and `TcpGraphsView` mount, `ConnectionsView.tsx` `onOpenTcpGraphs`, `PacketStreamView.tsx` selection state, and `e2e/`.
