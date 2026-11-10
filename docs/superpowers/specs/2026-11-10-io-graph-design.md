# IO Graph: Filter-Defined Series over a Real Time Axis — Design Spec

**Issue:** JAM-18 (legacy GitHub #85) · **Epic:** JAM-127, Analysis surfaces (phase 2, epic D)
**Status:** draft for James's review. No implementation is approved by this document. The wire change (D3) and the open decisions (§"Decisions needed") are ask-first under `AGENTS.md`.
**Base revision read:** `main` at `f664407`.

## Problem

The product cannot answer "when did that start?" or "what happened at 14:05?". The issue's "Current state" understates the gap: there is no working time series at all.

- `sparkline: Vec<u32>` exists on `ConnectionJson` and `LayerStatsJson` (`capture-agent/src/wire.rs:28`, `:98`), but the agent always sends it empty (`vec![]` at `capture-agent/src/main.rs:3638`, `:3690`, `:3701`, `:3712`).
- `historyRx`/`historyTx` in `app/page.tsx:161-162` have setters that nothing calls. The history chart in `components/DashboardView.tsx:160-162` therefore always renders empty.
- The only live rate data is the per-tick aggregate `system_stats` (`rxTotalMbps`, `rxPpsTotal`, …; `wire.rs:525-552`) and per-layer `layer_update` speeds. Neither can be split by a filter.

The issue asks for a chart with a labelled time axis, selectable interval, pan and zoom, several series each defined by a display filter, packets/s and bits/s (later SUM/MIN/MAX/AVG of a numeric field), and click-through from an interval to its packets.

## The fact that shapes everything

**The browser cannot count.** Discrete `packet` events pass through `PacketEventLimiter::new(100, 1000)` (`main.rs:2883`, gate at `:3280`). It is a minimum-interval throttle: at most one event every 10 ms, with no burst allowance. Nothing on the wire records that a packet was skipped (`docs/wire-protocol.md:142`), and `packet_seq` only increments after the gate (`main.rs:3287`), so ids have no gaps at skipped packets. On top of that, the browser keeps by default only the newest 100 packets (`packetBufferLimit`, `app/page.tsx:175`).

A graph built from browser-side packets would flatten every interval busier than 100 packets/s to roughly 100, and it would look authoritative while doing so. **So every count in this feature must come from code that sees every frame**: the agent's capture loop, at the point where `FlowTable::observe` and the pcapng writer already run (before the limiter; `wire-protocol.md:144-145`).

The second fact: **display filters exist only in TypeScript** (`lib/display-filter.ts`, `compileDisplayFilter` at `:229`). The agent only knows BPF (`set_capture_filter`). Counting by display filter in the agent therefore means evaluating the same language in Rust.

## What this spec does and does not promise

- **Promises:** complete per-interval packet and byte counts for every series, for every frame the agent parsed while it was reading, during live capture and during `REPLAY_FILE` replay. Every interval where that was not true is labelled (kernel drops, unparseable frames, paused time, late frames).
- **Does not promise:** complete click-through. The browser only holds the packets it was sent. The drill-down says exactly how many of the interval's packets it can show, and how many it cannot (D7).
- **Does not promise:** history across a page reload in the first version (D5, decision B). It also does not promise graphs over a recorded file without replaying it. That is the JAM-255 query service's job; D9 keeps the bucket contract compatible with it.

## Decisions

### D1. Counts are computed in the agent, per series, before the rate limiter — **needs James's approval (wire change)**

Options considered:

| Option | Complete counts? | Cost | Verdict |
| --- | --- | --- | --- |
| A. Browser counts the packet events it receives | No. Capped near 100/s and silently wrong above it | none | Rejected: this is the failure the readiness review named |
| B. Agent evaluates series filters per frame and emits bucketed counts | Yes, for parsed frames while reading | Rust filter evaluator; a per-frame field tree while series are active | **Recommended** |
| C. Graph only recorded files through the JAM-255 query service | Yes, for finalized files | A service that does not exist and needs JAM-196 caller authentication, an OS-identity broker and retention policy first | Future path (D9), not this issue |
| D. Agent evaluates in the BPF filter | Only for BPF-expressible predicates | none | Rejected: BPF cannot express L7 fields, and the BPF filter changes what is captured rather than what is counted |

With B, while at least one series is active, the capture loop builds the frame's field tree with the same function that builds the browser's (`fields::build_packet_fields`, `capture-agent/src/fields.rs:494`). It evaluates each series' compiled filter against that tree and adds the frame to the series' open 100 ms bucket. All of this happens before `packet_event_limiter.allow(...)`.

**Zero cost when off.** With no series configured, which is the default and the state after the agent starts, the hot path does one relaxed atomic load and nothing else. This is the pattern the capture-file writer already uses (`writer_active`, `main.rs:3251`).

**Field-tree cost is real and must be measured, not assumed.** Today `build_packet_fields` runs only for the ≤100 emitted packets per second. With series active it runs for every frame. Evaluation is inline in the capture thread, so if it falls behind, the cost shows up as kernel drops (`captureStats.dropped`), which D6 already labels. It is never hidden. The plan must benchmark per-frame cost with 0, 1 and 8 series on replayed fixtures and record the numbers before the series cap (D4) is fixed. A lazy evaluator that resolves only the paths a filter references, directly from `ParsedPacket`, is the fallback if the numbers are bad. It is not the default, because a second field-resolution path is a second place for semantics to diverge.

### D2. One filter language, two evaluators, one conformance corpus

The Rust evaluator is a port of `lib/display-filter.ts`, not a new dialect:

- The same grammar (`or`/`and`/`not`, comparisons `== != > < >= <=`, `contains`, `in { … }`), the same limits (2048 chars, 512 tokens, nesting 64, set size 128; `display-filter.ts:15-18`), the same case-insensitive path and string matching, the same "first matching field wins" lookup (`display-filter.ts:63`), and the same rule that a group field is present but has no value.
- **Integer semantics:** uint fields are compared exactly. TS holds values above 2^53−1 as `bigint` (`display-filter.ts:66`). Rust uses `u64`, and the corpus includes values on both sides of 2^53.
- **Case folding:** both sides lower-case with the full Unicode default mapping (JS `toLowerCase`, Rust `str::to_lowercase`). The corpus includes non-ASCII cases, such as `İ`, final sigma and German ß, to pin any difference rather than assume none.
- **A shared corpus** (`testdata/display-filter-conformance.json`: filter source, a field tree, expected match or expected error with token position) is run by both Vitest and `cargo test`. A divergence fails CI on whichever side is wrong.
- **Fuzzing:** a `cargo-fuzz` target for the Rust tokenizer, parser and evaluator ships in the same PR and runs in CI (checklist §7).

**Paths that cannot be counted are rejected, not silently false.** A series filter is evaluated over packet records only, so:

- `connection.*` paths, which are always false on a packet record (`display-filter.ts:71-80`), are a compile error for a series: "connection fields are not available in IO graph series".
- `*.response_to` is attached only once a request has been *emitted* (`main.rs:3289-3293`; `wire-protocol.md:137`). Its presence therefore depends on the rate limiter, and a count over it would be sampling in disguise. It is a compile error for a series. `*.time_us` is computed regardless of emission and stays allowed.
- **Decrypted content is never a series input.** Decrypted TLS data arrives through separate `decrypted_*` events (gated, ephemeral) and is not part of the packet field tree. The evaluator only ever sees `build_packet_fields` output. A test asserts that a filter naming a decrypted-only path matches nothing, and that the series code path holds no reference to the decrypt store.

### D3. Wire: one control message and two events, broadcast on the existing SSE feed — **wire change, ask-first**

Counts are aggregate metadata of the same sensitivity as `system_stats`: they reveal no more than the packet fields every tab is already sent. So unlike Follow Stream's content (`2026-10-31-follow-stream-design.md` D4), they may ride the shared SSE feed. No new relay route or request/response machinery is needed in the first version.

**Browser → agent (via `/api/control`):**

```json
{ "type": "set_io_series", "version": 7,
  "series": [
    { "id": "all",  "filter": "" },
    { "id": "dns",  "filter": "dns" },
    { "id": "big",  "filter": "frame.len > 1000 and tcp" }
  ] }
```

- Replace-all semantics. An empty `series` list turns the feature off and returns the hot path to zero cost. An empty `filter` means every parsed frame.
- `app/api/control/route.ts` adds `set_io_series` to its allowlist (`route.ts:50-61`), after `rejectIfCrossSite` as today. It validates before forwarding: `version` a u32; at most `MAX_IO_SERIES` entries (D4); `id` matching `^[a-z0-9-]{1,32}$` and unique; `filter` a string of at most 2048 characters. (Note that the route's existing `set_capture_filter` bound is 1024. That is BPF, a different language, and stays unchanged.) The agent re-validates everything, since it does not trust the relay to have done so.
- **One series set per agent, shared by every tab** (decision A). The agent has no notion of which tab sent a control message, and per-tab sets would need relay caller identity (JAM-196). Every tab renders the agent's current set from `io_series_status`. A tab that edits the set sends the full new list with `version` = last seen + 1. Last writer wins, and the UI says "series changed in another tab" when it receives a version it did not send.

**Agent → browser:**

`io_series_status`: sent on every `set_io_series` and on every relay (re)connection, so a new tab learns the current set.

```json
{ "type": "io_series_status", "version": 7, "epoch": "4be1a07c",
  "series": [
    { "id": "all", "filter": "", "ok": true },
    { "id": "dns", "filter": "dns", "ok": true },
    { "id": "big", "filter": "frame.len > 1000 and tcpp", "ok": false, "error": { "message": "Unknown keyword", "token": "tcpp", "position": 18 } }
  ] }
```

**Every entry carries its authoritative `filter` source, including failed entries.** Ids are arbitrary labels, so without the source another tab could not rebuild the shared series editor, could not resend the other series unchanged in a replace-all update, and could not apply the series filter during click-through (D7). The browser always builds a `set_io_series` from the latest `io_series_status`, never from its own earlier copy. The status line is bounded by construction: at most 8 × 2048 characters of filter source, which fits within the 64 KiB line ceiling below.

A series that fails to compile is kept in the set, so the user can see and fix it, but it is never counted. A rejected message as a whole (too many series, a bad id) returns `io_series_status` with `"rejected": "<reason>"` and leaves the previous set in force.

`io_buckets`: sent from the 1 s emitter tick (`main.rs:3409`) with every 100 ms bucket that closed since the previous tick.

```json
{ "type": "io_buckets", "version": 7, "epoch": "4be1a07c", "bucketMs": 100,
  "coveredFromMs": 1794120000000, "coveredToMs": 1794120001000,
  "notObserved": [ { "fromMs": 1794120000300, "toMs": 1794120000600, "reason": "paused" } ],
  "loss": { "kernelDropped": 0, "ifDropped": 0, "unparseable": 3, "evaluationSkipped": 0 },
  "series": [
    { "id": "all", "late": 0, "buckets": [[1794120000000, 412, 301122], [1794120000100, 388, 280004]] },
    { "id": "dns", "late": 0, "buckets": [[1794120000100, 2, 180]] }
  ] }
```

- **Sparse and gap-explicit.** `buckets` lists only non-empty buckets as `[startMs, packets, bytes]`. Every bucket in `[coveredFromMs, coveredToMs)` that is neither listed nor inside a `notObserved` range is a true zero. The browser never infers zero for time outside `covered`. Consecutive messages' covered ranges abut. A gap between them, such as an agent restart, is "no data", never zero.
- **Bytes are the original on-wire length** (`original_len`, `main.rs:1568`), not the captured length. `frame.len` in filters is the *captured* length (`parsed.total_len` from `frame_data.len()`, `parse.rs:417`, mapped at `main.rs:553`). So a series filtered on `frame.len` and its bits/s measure can legitimately disagree under snaplen truncation. The chart says so in the measure's tooltip. The plan must check which length `system_stats` totals use, so that the "all" series and `rxTotalMbps + txTotalMbps` reconcile in a test, or document why they do not.
- **`epoch`** is a random id the agent generates at startup. A changed epoch means a new agent process, so the browser starts a new history segment rather than stitching. A runtime `set_interface` switch keeps the epoch but emits a `notObserved` range with reason `interface_switch` covering the switch.
- **Encoded-line ceiling:** 64 KiB per `io_buckets` line. If more buckets closed in one tick than fit, which only happens during fast replay, the agent writes several lines in the same tick, each with its own contiguous covered range. Nothing is dropped to fit.
- **Not rate-limited** by `PacketEventLimiter`, and not counted against the discrete-event budget. In live capture, volume is bounded by construction: at most 10 buckets per series per second.
- Updated together per the wire rule: `wire.rs`, `docs/wire-protocol.md`, `lib/types.ts`, `lib/agent-mapping.ts`, tests on both sides. The mapper ignores unknown fields, and an unknown `notObserved.reason` maps to a visible "unknown" rather than throwing (checklist §6).

### D4. Bounds

| Bound | Proposed default | Where enforced | Basis |
| --- | --- | --- | --- |
| Series per agent (`MAX_IO_SERIES`) | 8 | route and agent | confirm against the D1 benchmark; lower it if 8 series cost too much per frame |
| Agent bucket width | 100 ms, fixed | agent | the finest interval the issue asks for; every coarser interval is an exact sum |
| Agent open buckets | ≤ `ceil(grace / 100 ms) + 1` per series (grace = 500 ms ⇒ 6) | agent | D5 closing rule |
| Agent closed-but-unsent buckets | ≤ 36 000 per series (one hour of 100 ms buckets) | agent | only reachable in fast replay; see "Backpressure" below |
| `io_buckets` line | 64 KiB | agent, asserted before write | D3 |
| Browser history, 100 ms | 15 min (9 000 buckets/series) | browser ring | interval 100 ms |
| Browser history, 1 s | 1 h (3 600) | browser ring | intervals 1 s and 10 s |
| Browser history, 1 m | 24 h (1 440) | browser ring | interval 1 m |
| Rendered points per series | ≤ 2 000 | chart | D8 |

Browser memory at the defaults: about 14 000 buckets per series × (2 × 8-byte counts) ≈ 225 KiB per series, or about 1.8 MiB for 8 series. Aggregates (D10) add 4 more numbers per bucket. The browser rings are fixed-capacity typed arrays: allocated once, never grown.

**Backpressure in fast replay.** `REPLAY_SPEED=fast` feeds frames back to back, so recorded time runs far ahead of wall time and buckets close much faster than 10/s. In replay the capture loop can wait without losing anything, because the file is still there. So when closed-but-unsent buckets reach the cap, the replay reader blocks until the emitter drains them. Live capture can never reach the cap (10/s against an emitter that drains every second). If it ever does, because the emitter thread is stalled, the agent stops counting, emits the uncounted span as `notObserved` with reason `backlog`, and counts the frames in `loss.evaluationSkipped`. It never drops buckets silently.

**Showing N of M.** In the JAM-6 style, the chart header states its horizon: "history since 14:02:11 (tab opened)", or "(retention limit: 1 h at 1 s)" once a ring has wrapped. It also states the series count and the epoch start.

### D5. Time, closing and late frames

- **Bucket key** = `floor(frame_timestamp_us / 100 000)`, from the frame's own timestamp: pcap header time live, recorded time in replay. This is the same clock as the packet event's `timestamp` (`main.rs:3012`), which is what makes click-through (D7) line up. It is not `relativeTimeMs`, which is agent wall-elapsed time (`main.rs:3300`) and is wrong for replay.
- **Closing rule** (checklist §5, replay-aware clock): a bucket closes once the closing clock has passed its end by the 500 ms grace. The clock is chosen per mode, the same way `reassembly_now_ms` (`main.rs:1730-1741`) chooses the clock for reassembly and flow aging (`main.rs:3027-3034`). In replay it is the newest recorded frame timestamp seen. Live, it is the agent's wall-clock epoch time, checked on every frame and on the 1 s tick so a quiet link still closes buckets. Note that `flow_now_ms` itself cannot be reused directly: live, it is agent-relative (`start.elapsed()`), while bucket keys are epoch time. Because the replay clock is recorded time, replay at any speed produces identical buckets. A test replays the same fixture at `realtime` and `fast` and asserts identical `io_buckets` content.
- **End of source: finalize explicitly.** At replay EOF, or on `ReplayError` or a live device ending (`SourceFrame::Eof`/`ReplayError`, `main.rs:3355-3374`), the capture thread currently just `break`s, while the periodic emitter keeps running. Nothing would ever advance the recorded-time closing clock past the last frame, so the tail buckets within the grace window would never close. A capture shorter than 500 ms would emit no counts at all. So before the thread exits, it closes every open bucket, hands them to the emitter, and marks the covered range as ending at the end of the last frame's bucket. On `ReplayError` it adds a `notObserved` range with reason `replay_error` from there on. After finalization, `io_buckets` keeps the epoch but reports no further covered time. Tests: a replay shorter than the grace window yields all of its frames; a long replay's final bucket equals the hand count; a truncated file reports `replay_error`.
- **Late frames.** A frame whose bucket has already closed, because of an out-of-order file, a clock step backwards, or a frame older than the grace, is counted in that series' `late` for the current message. It is not placed. The chart marks the message's span "N late frames not shown". A late count is never added to a bucket that was already sent, because the browser may have already rolled it into a coarser interval.
- **Forward jumps** (a clock step forward, or a gap in a recorded file) produce empty covered time. Sparse encoding keeps this free on the wire.
- **Pause.** While paused, the capture loop does not read (`main.rs:2979-2982`), so the paused span is `notObserved` with reason `paused`, never zeros.

### D6. Coverage labelling — every incomplete interval says so

Each `io_buckets` message carries the loss deltas for its covered span:

- `kernelDropped` and `ifDropped`, from the existing pcap stats poll (`main.rs:2983-2990`, once per second, live only);
- `unparseable`, from the existing `unparseableFrames` counter;
- `evaluationSkipped` (D4 backlog path).

Kernel stats arrive once per second and cannot be attributed to a 100 ms bucket. The chart therefore shades the whole message span (≈ 1 s) as "incomplete: N frames dropped before parsing", and every finer bucket inside it inherits the shading. A drop is never spread across buckets as though its timing were known. Unparseable frames are not series inputs (they have no field tree) and are reported, not counted.

### D7. Click-through: what the browser can show, stated exactly

Clicking a bucket at any interval opens the Packets view constrained to `[t0, t1)` **and** that series' filter. The time range is a UI-level constraint next to the display filter, not new filter-grammar syntax, so the field model is unchanged. The header is computed, never assumed:

> **12 of 4 180 packets** in 14:05:10.000–14:05:11.000 matching `dns` are available here. The other 4 168 were counted by the agent but not sent to the browser (rate-limited to 100 packet events/s) or have aged out of the 100-packet buffer. To inspect all of them, record a capture file (`capture start …`) and replay it.

- N is the bucket's exact count, or the sum over the selected coarser interval. k is the number of buffered packets with `timestamp ∈ [t0, t1)` that match the filter, evaluated in the browser with the TS evaluator over the same fields.
- k can never exceed N, except that a buffered packet's `timestamp` is in milliseconds while bucket edges are exact multiples of 100 ms. Flooring µs to ms cannot move a frame across a 100 ms boundary, so k ≤ N holds. A test asserts it, and the UI clamps and flags any violation rather than display it.
- If the interval was `notObserved` or late frames were reported in it, the header says that too.
- **Future path:** with the JAM-255 query service, drill-down can page recorded packets by stable id beyond the browser buffer. The header's wording leaves room for that ("available here").

### D8. Rendering — SVG, no charting library — **dependency decision recorded**

The issue's implementation note cites a `CLAUDE.md` rule ("no CSS-in-JS, no state-management library", no charting library). That text no longer exists in `CLAUDE.md`, `AGENTS.md` or `CONTRIBUTING.md`. This spec makes the decision itself: **no new runtime dependency.** `package.json:17-29` has no charting library today, and the existing bars are plain `div`s (`DashboardView.tsx:266-275`). Adding one would be an ask-first dependency for a chart that needs only lines, two axes and hit-testing.

- A new `components/IoGraphView.tsx` holds the presentational SVG (one `<polyline>` or step path per series, axes, gridlines, a hover cursor and readout). A pure `lib/io-graph.ts` handles bucket ingestion, the rings, interval roll-up, the visible-window query and tick-label generation, so all of it is unit-testable without a DOM.
- **Intervals** 100 ms / 1 s / 10 s / 1 m are derived exactly by summing (MIN/MAX of a min/max, and AVG as sum ÷ count; D10). The interval selector disables any interval whose visible bucket count would exceed 2 000 points per series, so zooming out picks a coarser interval rather than decimating points. Disabled options say why.
- **Pan and zoom:** wheel or pinch zooms around the cursor, drag pans, and the keyboard handles both (arrows pan; `+`/`-` zoom; `End` returns to "live follow"). Panning away from now pauses follow mode, visibly.
- **Units:** packets/s and bits/s are computed as count ÷ interval and shown with SI prefixes. Series whose measures have different units share the chart through at most two y-axes (left and right). A third unit is refused in the series editor with a reason.
- **Smoothness:** ingest at most once per tick and render in one `requestAnimationFrame`. "Smooth at the retained window's full size" becomes measurable: with 8 series × 2 000 visible points, a Playwright check against a fixed fake feed asserts the update's render task stays under one 16.7 ms frame on the CI runner, and records the numbers.
- **Style:** a terminal aesthetic with Tailwind classes, the existing layer colours for series and monospace axis labels. It is reachable as an `io` tab and an `io` command-bar verb, alongside the existing `activeTab` set (`app/page.tsx:79`, `:612`).

### D9. Relationship to recorded data and JAM-255

- **Today, without JAM-255:** `REPLAY_FILE=x.pcapng REPLAY_SPEED=fast` already gives a graph over a whole file's duration, with complete counts, through exactly the path above (D4 backpressure, D5 recorded-time buckets). That is the issue's "a graph over a file can cover its whole duration", delivered with no new service. Replay is startup-only and has no seek (`docs/architecture.md:121-122`). That limit is inherited, not solved.
- **Replay start barrier — needed for the whole-file promise.** Today the replay reader starts the moment the agent starts and ends at EOF. A fast replay of an ordinary capture can therefore finish before any browser has opened the chart or sent `set_io_series`. With no series configured, nothing is counted (D1), and browser-held history (decision 3) cannot backfill. Proposal: a new startup option `REPLAY_WAIT_FOR_IO_SERIES=1`, valid only with `REPLAY_FILE` and off by default, so existing replay behaviour is unchanged. With it set, the replay reader waits before reading the first frame until the first valid, non-empty `set_io_series` arrives. Because that message reaches the agent through a browser's `/api/control` call, a subscribed tab exists by then and receives every `io_buckets` from the first bucket. While waiting, the agent says so: `capture_stats` and `io_series_status` report `replayWaiting: true`, and the chart shows "replay is waiting for series: add one to start". A test checks that with the option set, a short fixture's "all" series equals its frame count even though `set_io_series` is sent after agent startup. Without the option, the documented limit stands: a replay that finished before series were set has no IO graph. This is a startup-configuration change, so it is listed as decision 6.
- **Reloading mid-replay** loses the browser's history under decision 3 (B), as it does live. The chart labels the restart. Restarting the agent with the barrier option is the recovery path until agent-held history (decision 3 A) or JAM-255 exists.
- **Later, with JAM-255:** the service would answer "bounded time buckets over a selected recorded source" (`2026-10-11-local-query-service-spike-result.md:142`). This spec's bucket contract (100 ms base, `[startMs, packets, bytes]`, explicit covered and not-observed ranges, loss counters) is the shape that service should return, so `lib/io-graph.ts` can ingest either source unchanged. That integration is not part of this issue.

### D10. Numeric-field aggregates (SUM/MIN/MAX/AVG) — later PR in the same plan

The field model this depends on (#76, epic JAM-126) is done. A series may name `"aggregate": { "fn": "sum" | "min" | "max" | "avg", "field": "<uint path>" }`. Each bucket then carries `[startMs, packets, bytes, count, sum, min, max]`, where `count` is the number of matched frames that had the field.

- The value is the first matching field occurrence, consistent with filter lookup (D2). Only `uint` fields are allowed; any other type is a compile error. Sums are `u128` in Rust and serialized as decimal strings above 2^53−1, mirroring the existing uint convention.
- AVG is derived (sum ÷ count) at every interval, never averaged-of-averages.
- **Phasing:** packets and bits first. Aggregates land as their own PR once the base pipeline is merged and measured, because they add per-frame field reads and widen the bucket.

## Decisions needed from James

1. **D1 data source:** agent-side per-frame evaluation (B, recommended), with its wire change (D3). The alternative, deferring the feature until the JAM-255 service exists, means no live IO graph.
2. **Series scope:** one shared series set per agent, last writer wins, visible across tabs (recommended), versus per-tab sets, which wait on JAM-196 relay caller identity.
3. **History location in the first version:** **(B, recommended)** browser-held rings fed by `io_buckets`, lost on reload and labelled as such; versus (A) agent-held rings plus a paged backfill route. (A) survives reloads but needs the request/response relay machinery that JAM-17's plan introduces and has not yet built. B can be upgraded to A later without changing the bucket contract.
4. **Defaults in D4:** 8 series, 100 ms base bucket, 500 ms grace, browser retention 15 min / 1 h / 24 h. The series cap is provisional until the D1 benchmark.
5. **Aggregates:** in this plan as a later PR (recommended), or split into a separate issue.
6. **Replay start barrier (D9):** the opt-in `REPLAY_WAIT_FOR_IO_SERIES=1` startup option (recommended), versus documenting that a replay must still be running when series are set.

## Acceptance criteria → how each is met and tested

| Criterion (JAM-18) | Met by | Evidence the plan must produce |
| --- | --- | --- |
| Labelled time axis, selectable interval, pan and zoom | D8 | `lib/io-graph.ts` unit tests: tick labels at each interval and across midnight/DST; exact interval roll-up; visible-window query; a Playwright check of wheel zoom, drag pan, keyboard and follow mode against a fake feed and a real agent with `REPLAY_FILE` |
| At least two filter-defined series compared on one chart | D1–D3 | Rust test with a fixture of known composition: per-series counts equal a hand count. The conformance corpus is green on both sides. The UI is checked with ≥ 2 series against a real agent (epic-cycle §5b) |
| Clicking a point navigates to the packets in that interval | D7 | Tests: k ≤ N; the header text for available, partial, not-observed and late cases; the time-range constraint combines with the series filter |
| Rendering stays smooth at the retained window's full size | D4, D8 | The Playwright render-time check at 8 × 2 000 points, with recorded numbers |
| Visual style matches the terminal UI | D8 | Screenshot reviewed in the PR |
| *(added)* Counts are complete and never sampled | "The fact that shapes everything", D1, D5 | A fixture replayed at `fast` above 100 pkt/s: the "all" series equals the file's frame count (minus reported unparseable). The same fixture at `realtime` and `fast` gives identical buckets |
| *(added)* Incomplete intervals are labelled | D5, D6 | Tests for pause, interface switch, late frames, unparseable frames, the backlog path, and epoch change |
| *(added)* Zero cost when unused | D1 | A test that no field tree is built with an empty series set (seam counter); the benchmark at 0 series matches the baseline |

## Security-plan review (`docs/security-plan-review-checklist.md`)

- **§1 Inputs and bounds:** filter sources are untrusted browser input. They are bounded at the route (2048 chars, ≤ 8 series, id regex) and again by the Rust tokenizer limits before any allocation. Set literals are capped at 128, and nesting at 64 with an explicit depth counter rather than unbounded recursion. Per-frame evaluation work is bounded by series × AST size × fields-per-frame. Every buffer in D4 has a stated cap and a defined pressure behaviour (replay blocks; live reports `backlog`).
- **§2 Failure semantics:** a filter compile error is recoverable (the user edits it) and the series is shown but never counted. An over-limit set is rejected whole, and the previous set stays in force. A backlog failure is reported as `notObserved` with `evaluationSkipped` and is never silent. No partial count is presented as complete (D3 covered ranges, D6). An on-path attacker can inflate or deflate counts only by sending or dropping real traffic, which is the measurement itself, not a confidentiality issue. A packet crafted to be expensive to field-build costs no more than it already does for emitted packets, and with series active it costs that for every frame. That per-frame cost is exactly what the D1 benchmark bounds.
- **§3 Cryptography:** not applicable. No keys or ciphertext are involved.
- **§4 Secrets and sensitive data:** series never evaluate decrypted content (D2), with a test. Counts carry no payload bytes. Filter strings are echoed only in `io_series_status` (the user's own input) and are not logged by the agent. A compile-error message includes the offending token, which is the user's own text.
- **§5 Time:** buckets close on the replay-aware traffic clock (D5), with a test showing equal output at both replay speeds.
- **§6 Interfaces:** the wire change touches all four files together. Unknown reasons and fields do not throw. `io_buckets` is periodic, not per-event, so it cannot flood, and `io_series_status` is sent only on change or reconnect. Neither carries content, so neither is subject to the content-rendering gate.
- **§7 Tests and tooling:** tests first. The Rust filter fuzz target ships in the evaluator PR and runs in CI. Boundary tests cover 8 and 9 series, 2048 and 2049 characters, set sizes 128 and 129, and nesting 64 and 65. The reviewer states what was read and run.

## Proposed PR sequence (for the plan to refine)

1. **Rust display-filter evaluator + shared conformance corpus + fuzz target.** No wire change, and nothing calls it yet.
2. **Agent series pipeline + wire:** `set_io_series`, `io_series_status`, `io_buckets`; control-route allowlist; `types.ts` and mapper; `wire-protocol.md`; the D1 benchmark numbers in the PR.
3. **Browser history and chart:** `lib/io-graph.ts`, `IoGraphView`, intervals, pan and zoom, series editor, coverage shading.
4. **Click-through** (D7).
5. **Aggregates** (D10).

Each PR is separately reviewable, and the feature stays invisible to users until PR 3, because the agent does nothing while no series is configured.

## Non-goals

- Graphs over a recorded file without replaying it, and drill-down beyond the browser buffer (JAM-255).
- Persisting series definitions across reloads or as profiles (JAM-28).
- Per-tab series sets (needs JAM-196).
- TCP stream graphs (JAM-19) and the flow ladder (JAM-20), which have their own issues.
- Changing the 100/s packet-event limiter or the default packet buffer.

## Collateral findings (to file separately, not fixed here)

- `sparkline` on `ConnectionJson`/`LayerStatsJson` is always sent empty, and `historyRx`/`historyTx` are never set, so the Dashboard's history chart and sparklines are dead UI. That violates the "do not invent displayed data without a real producer" invariant in spirit: the UI shows an empty chart as if it were a measurement. Once this spec lands, the fix is either to remove them or to feed them from `io_buckets`. Either way it should be its own issue.

## Revision log

- 2026-11-10 — r2, Codex review on PR #302. Three changes: `io_series_status` now carries each series' filter source; D5 adds explicit finalization at end of source; D9 adds the opt-in replay start barrier (new decision 6).
- 2026-11-10 — r1, first draft (Claude Code), from the 2026-10-11 spec-readiness review on JAM-18 and the JAM-255 proposal-impact comments.

## Next

James reviews the five decisions above. Once the spec is approved, write `docs/superpowers/plans/2026-11-10-io-graph.md` per `CONTRIBUTING.md`'s spec → plan process. No feature code before the plan is approved.
