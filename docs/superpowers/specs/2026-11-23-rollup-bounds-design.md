# Bounded Endpoint and Conversation Rollups — Design Spec

**Issue:** KAN-131 (legacy JAM-162) — "Bound per-capture endpoint and conversation rollup growth"
**Epic:** KAN-18 (Analysis surfaces, legacy JAM-127)
**Status:** DRAFT. Nothing here is implemented. Open for James: the decisions in "Decisions needed" below. The implementation plan and code each need their own gate.

## Problem

`FlowTable` (`capture-agent/src/flow.rs`) keeps `endpoint_rollups` (one entry per remote host) and `conversation_rollups` (one per local/remote pair). Neither has a limit: `evict_stale` and `reset` never remove entries, so `MAX_FLOWS` does not bound them. Each one-second tick clones both maps while holding the flow-table lock, encodes them whole, and sends them to the relay. Each browser then replaces, sorts and renders every row.

## Already decided (James, in chat, 2026-10-11)

- Evict the least recently active key (LRU) and count evictions.
- Send top-N plus totals and omitted counts, not full maps.
- The user chooses the ranking in the web UI.
- Caps are configurable and sized for more than a home LAN.

This spec does not reopen these. It proposes the values and the semantics they leave open.

## Measurements

Throwaway benchmark, not committed. A separate release-built crate linked this repo's `capture_agent` library at `a6db720`. Apple M3, 16 GB, rustc 1.98.0, Node 26.12.1. Memory is bytes requested from the allocator (a counting `GlobalAlloc`), not resident memory. K is the number of keys in **each** table, with one local address, so conversations equal endpoints. Nothing here was run on Linux or against live traffic.

**Today** (the real `FlowTable` and `wire::encode_event`; one run; flows evicted so that only rollups remain; 1,000 extra priming keys are included in the rows and lines but not in the memory; rows filled with fixed, mid-sized counters, process `unknown`, no name or JA3):

| K | Memory, both maps | Lock held for both snapshots | Encode both | `endpoint_update` line | `conversation_update` line |
|---|---|---|---|---|---|
| 5,000 | 1.7 MiB | 0.6 ms | 5.4 ms | 1.5 MB | 1.8 MB |
| 10,000 | 3.9 MiB | 0.8 ms | 7.2 ms | 2.7 MB | 3.3 MB |
| 50,000 | 18.5 MiB | 3.4 ms | 25 ms | 12.8 MB | 15.6 MB |
| 100,000 | 36.8 MiB | 6.4 ms | 51 ms | 25.3 MB | 30.8 MB |
| 500,000 | 283 MiB | 66 ms | 281 ms | 125 MB | 153 MB |

An IPv4 row is about 250 B (endpoint) and 305 B (conversation). With IPv6 remotes at 100,000 keys they are 276 B and 339 B. The relay's `JSON.parse` plus `JSON.stringify` of one `endpoint_update` took a median 5.1 ms at 11,000 rows and 50 ms at 101,000; SSE forwarding stringifies once per open tab.

So the first thing to break is the wire, not memory: 10,000 keys already cost 6 MB/s per tab.

**Proposed structure** (prototype: hash index into a slab with an intrusive doubly linked recency list; median of five runs; both tables updated per packet, starting from the `String` addresses `ParsedPacket` carries; hits drawn from a log-uniform, Zipf-like mix):

| K | Hit, today's maps | Hit, LRU `String` keys | Hit, LRU `IpAddr` keys | Evict, `IpAddr` | Memory, `String` | Memory, `IpAddr` | Tick at N=200, both tables |
|---|---|---|---|---|---|---|---|
| 500 | 92 ns | 79 ns | 51 ns | 144 ns | 0.3 MiB | 0.2 MiB | 0.04 ms |
| 5,000 | 101 ns | 92 ns | 57 ns | 146 ns | 3.2 MiB | 2.6 MiB | 0.15 ms |
| 10,000 | 104 ns | 98 ns | 61 ns | 150 ns | 6.4 MiB | 5.3 MiB | 0.29 ms |
| 50,000 | 134 ns | 141 ns | 87 ns | 179 ns | 26.4 MiB | 21.1 MiB | 1.5 ms |
| 100,000 | 157 ns | 200 ns | 116 ns | 226 ns | 52.7 MiB | 42.3 MiB | 7.5 ms |
| 500,000 | 235 ns | 320 ns | 208 ns | 283 ns | 263 MiB | 202 MiB | 51 ms |

"Hit" is the rollup part only, not all of `observe`. "Tick" is selecting four top-N lists in each table and draining the per-tick counters; it excludes building rows and encoding.

The union of the four rankings has fewer than 4N rows because they overlap: at 50,000 keys, 190 rows for N=100, 396 for N=200, 974 for N=500, 1,943 for N=1,000. Overlap depends on the traffic; the worst case is 4N. The relay's parse plus stringify is 0.15 ms for 350 rows, 0.40 ms for 900 and 0.8 ms for 1,800.

## Design

### D1. One bounded LRU store per table

A `RollupTable<K>` (new `capture-agent/src/rollup.rs`) replaces both maps, with `K = IpAddr` for endpoints and `(IpAddr, IpAddr)` for conversations. Every packet recorded for a key moves it to the front of the recency list. At the cap, inserting a new key evicts the tail. This is exact LRU in O(1) per packet. Recency is arrival order, not `last_seen_ms`, so equal or backward replay timestamps cannot make eviction ambiguous.

- `IpAddr` keys are measured as cheaper than today's `String` maps at every size. The address strings come from `etherparse` via `to_string()`, so parsing back is lossless; rendering is the standard form already on the wire. A string that fails to parse is counted (`unkeyed`) and not recorded, never panics.
- The index keeps std's randomly keyed hasher, because remote addresses are attacker-chosen.
- The slab grows as keys arrive, never past the cap. A cap does not reserve memory up front.

### D2. Caps

| Variable | Default | Accepted |
|---|---|---|
| `MAX_ENDPOINTS` | 50,000 | 1 to 500,000 |
| `MAX_CONVERSATIONS` | 50,000 | 1 to 500,000 |
| `ROLLUP_TOP_N` | 200 | 1 to 1,000 |

Startup-only. Unset or blank means the default; zero, non-numeric or out-of-range fails startup with the variable's name, as `MAX_FLOWS` does. `MAX_FLOWS` has no upper limit today; these do, because tick work is linear in the cap and runs under the flow-table lock.

Why these: a home LAN (hundreds of keys) and a busy office (thousands) never evict. At 50,000 both tables full cost about 21 MiB and 1.5 ms per tick under the lock, which is below today's 3.4 ms at that size. At 100,000 the lock time rises to about 5 to 7.5 ms (the prototype falls out of cache), so it is an operator's choice. The 500,000 ceiling is a 50 ms stall per tick and 200 MiB; it is allowed for a datacenter link, and documented as such.

### D3. Ranking: one top-N per key, no control message

Each update carries the **union** of the top N by bytes, packets, current rate and most recent activity. The browser ranks the rows it has.

- *Why not a shared control message:* the agent broadcasts one stream to every tab, so one tab's choice would change another's table, and any process able to reach the control route could change what an operator sees. Per-viewer state in the agent would be larger than the cost it saves.
- *Cost:* at N=200, typically about 400 rows, so about 100 KB (endpoints) plus 120 KB (conversations) per second; worst case 800 rows, about 200 KB plus 244 KB, before names and JA3 labels. `observedName` adds at most 253 bytes plus its field name to an endpoint row. Process names are not bounded here and are unchanged.
- *Guarantee:* for each of the four rankings, descending, the first N rows shown are exactly the top N **retained** keys. No claim is made about evicted keys.
- *Ties:* higher rank value, then more recently active, then older insertion id. Rows are sent in insertion-id order, so output never depends on hash order.

### D4. Wire

`endpoint_update` and `conversation_update` keep their names and row fields. Each row gains `historyComplete`, and each event gains one `bounds` object:

```json
{
  "type": "endpoint_update",
  "endpoints": [{ "host": "93.184.216.34", "historyComplete": true, "...": "existing fields" }],
  "bounds": {
    "cap": 50000, "topN": 200,
    "tracked": 50000, "evictions": 812, "unkeyed": 0,
    "horizonMs": 41200,
    "totals":  { "rxBytes": 9, "txBytes": 9, "rxPackets": 9, "txPackets": 9 },
    "evicted": { "rxBytes": 1, "txBytes": 1, "rxPackets": 1, "txPackets": 1 }
  }
}
```

- `tracked`: keys held now. Keys held but not sent = `tracked` minus rows sent: **exact**.
- `evictions`: eviction **events** since the capture began: exact. It is an upper bound on distinct evicted keys, since one key may be evicted more than once. Distinct evicted keys cannot be counted exactly without unbounded memory, so the UI never calls this number "hosts".
- `totals`: every byte and packet recorded since the capture began, kept as four counters. `evicted`: the totals folded in from evicted entries. `totals - evicted` always equals the sum over tracked keys. These are the invariant the tests check.
- `horizonMs`: the latest `last_seen_ms` among evicted entries, `null` if none. With a forward-moving clock, every key active after it is still tracked. In a replay whose timestamps go backward this does not hold, and the doc says so.
- `historyComplete`: true only if the entry was inserted when `evictions` was 0. False means "may have earlier, evicted history": conservative, because remembering which keys were evicted is the unbounded set again.

All counters are JSON numbers; saturating arithmetic. Rust, `lib/types.ts`, `lib/agent-mapping.ts` and `docs/wire-protocol.md` change in one PR. The mapper requires `bounds` (relay and agent ship together) and rejects a malformed one rather than showing an unlabelled partial list.

### D5. A key that returns after eviction

It starts from zero, with `firstSeenMs` at its return and `historyComplete: false`. Nothing is restored or estimated.

**Flow count.** `flow_count` is incremented today only on a flow's first packet (`is_new`). If a host is evicted while its flow is live and then returns on that flow, the count would be 0. Each entry therefore gets a monotonic `u64` insertion id, and `FlowState` stores the endpoint and conversation ids it last counted towards (16 B per flow). A flow counts once per entry id. With no eviction the results equal today's. `flowCount` then means "flows seen since this entry was inserted".

**JA3** is written after `record` in the same `observe`, when the entry is at the front, so it cannot have been evicted in between (cap is at least 1).

**Attribution** (`processName`/`pid`) is computed from live flows as now, only for rows being sent.

### D6. Interface switch

`FlowTable::reset` clears both tables and all `bounds` counters. Today the rollups survive it (`docs/wire-protocol.md`: cumulative since capture start), so totals from one interface appear under another, with directions judged against different local addresses. This is a behaviour change; `protocol_hierarchy_update` and service times are unchanged.

### D7. UI

- `F7: HOSTS (n)` shows `tracked`, not rows received.
- A line in `EndpointsView`, always visible: "Showing top 396 of 50,000 tracked hosts." When `evictions` > 0: "812 evictions (cap 50,000): least recently active hosts were dropped; their totals (… bytes) are not in any row." With `horizonMs`, "Hosts last active before … may be missing."
- A **Rank by** control: bytes, packets, rate, recent. It picks and shows the first N rows by that ranking; default bytes; per tab, not persisted.
- Column sorts and search apply to the shown rows only. The search placeholder says "Filter shown rows…", and an empty result says "No match among the rows received; N more are tracked but not sent." An ascending or non-ranked sort carries the note "sorted within the top N by …".
- A row with `historyComplete: false` is marked `≥` on byte, packet and flow totals with a tooltip. First Seen reads "since re-added or later".
- Enrichment merge (`lib/rollup-state.ts`) keeps metadata only for rows in the previous list, so a host that leaves and re-enters the top-N would lose it. A bounded per-tab map (1,000 hosts, LRU) holds the metadata instead.
- A selected row that leaves the list keeps its key; its panel says it is no longer in the top-N.

Out of scope: fetching an arbitrary unsent key on demand, paging, history (KAN-253), recorded queries (KAN-125).

## Eviction flooding

Anyone able to put packets with many source addresses in front of the capture can evict real hosts. The window is cap ÷ new keys per second. Simulated with 500 real hosts each sending every 5 s, for 60 s; "lost" is how many of 6,000 real packets found their host already evicted:

| Cap | 1,000 new keys/s | 10,000/s | 100,000/s |
|---|---|---|---|
| 10,000 | 0 | 5,904 | 5,990 |
| 50,000 | 0 | 5,504 | 5,950 |
| 100,000 | 0 | 0 | 5,900 |

This is an availability effect on an analysis view, not disclosure, and it is visible: `evictions` climbs and `evicted` accounts for every dropped byte. Memory, wire and tick cost stay bounded throughout. Plain LRU cannot prevent it. A segmented LRU (one-packet keys evicted first) would protect repeat talkers, but it changes the decided policy; see question 5. `observe` work per flood packet rises to about 180 ns at 50,000 for these tables.

## Failure and locking

Snapshotting stays under the `FlowTable` lock, so a row set and its `bounds` are from one instant; encoding stays outside it. The whole-table scan (rank selection and drain) is the only linear work. Per-entry tick epochs could remove the drain, and the plan may use them, but the ranking scan remains.

## Tests the plan must include

Rust: cap+1 evicts exactly the least recent; recency survives equal and backward timestamps; `totals - evicted == sum(tracked)` under random operations; memory stable over 10x cap distinct keys; returning key (`historyComplete`, flow count on a still-live flow, two live flows); counters unchanged by flow closure, idle and capacity eviction; tables evict independently; each ranking's exact top N against a full sort, with ties; identical output from two runs; `reset`; env parsing; IPv4/IPv6 address rendering unchanged; line size at N=1,000 measured and bounded.

TypeScript: mapper accepts and rejects `bounds`; each notice; `≥` marks; Rank by; search and empty text; enrichment surviving leave and re-entry; map bound. Plus a replay end-to-end with small caps, and a real-browser check against a real agent.

## Delivery

1. Rust `RollupTable`, caps, D5, D6 and docs for the variables. Wire rows unchanged.
2. Wire, mapper, UI, `docs/wire-protocol.md`, `docs/usage.md`, `docs/analysis-guide.md`, `docs/architecture.md` together.

Merging part 1 alone would bound the tables without saying so on the wire, so the two parts must land together or part 1 must stay unreleased behind part 2: the plan picks one branch with two commits, or a stack merged the same day.

## Decisions needed from James

1. **Defaults:** 50,000 / 50,000 / N=200, ceilings 500,000 and 1,000. (Recommended.)
2. **Ranking:** union of four top-N lists, no control message. (Recommended.)
3. **Interface switch clears the rollups.** (Recommended; behaviour change.)
4. **No feature flag.** Standing Rule 6 asks for new features off by default. This is a bound on an existing feature, and off-by-default would leave it unbounded. (Recommended: exempt, with caps raisable by variable.)
5. **Plain LRU, flooding accepted and shown.** The alternative is a segmented LRU, which amends the 2026-10-11 decision. (Recommended: plain.)

## Not verified

Linux, live traffic, resident memory, browser render time, and tick cost with real process attribution. `historyComplete` and the flow-id scheme were reasoned from the code, not prototyped. Benchmark numbers are from one machine, and the "today" column is a single run.
