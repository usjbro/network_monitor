# Bounded Endpoint and Conversation Rollups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound the endpoint and conversation rollups, and say on the wire and in the UI exactly what the bounded list leaves out.

**Architecture:** A new `RollupTable<K>` (hash index, slab, intrusive recency list) replaces both `FlowTable` maps. Each tick sends the union of four top-N lists plus a `bounds` object under new event names; the browser re-ranks the received rows itself.

**Tech Stack:** Rust (`capture-agent`, std only), TypeScript, React 19, Vitest. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-23-rollup-bounds-design.md` (merged in PR #348, `7fe5f29`). D-numbers below refer to it.
**Issue:** KAN-131, epic KAN-18. **This PR:** plan only, no code. The code needs its own approved gate.

## Global Constraints

- Defaults and ranges: `MAX_ENDPOINTS` 50,000 (1 to 500,000), `MAX_CONVERSATIONS` 50,000 (1 to 500,000), `ROLLUP_TOP_N` 200 (1 to 1,000). Startup-only; blank means default; anything else out of range fails startup naming the variable.
- Exact LRU by packet arrival, O(1) per packet. The index keeps std's randomly keyed hasher. A cap reserves no memory up front.
- Events are `endpoint_rollup` and `conversation_rollup`; the agent stops sending `endpoint_update` and `conversation_update`.
- No control message, no feature flag, no bind change, no new dependency.
- All counters saturate. Nothing is restored or estimated for a returning key.
- Text taken from packets is rendered only as React text.
- Snapshots stay under one `FlowTable` lock hold; encoding stays outside it.
- Commit steps apply only once James has authorized commits for the code gate. James merges.

## Landing

One branch, one PR, one commit per task, squash-merged. After Task 2 the branch would send a bounded list with no label, so no intermediate commit may be merged or released. Each task is still reviewed on its own commit.

## Spec re-check (before Task 1; report, do not silently change)

Checked against `7fe5f29`. James approved this plan in chat on 2026-11-23, including re-measuring in Task 3 before the defaults ship, and chose subagent-driven execution.

1. **The "Tick" measurements do not cover the merged D3.** The benchmark took "recent" from the first N of the recency list (free) and ranked rate as an integer byte sum, breaking ties by slot. D3 now ranks recent by `lastSeenMs` and rate by `rxSpeed + txSpeed`, with a `lastSeenMs` tie-break. Neither is measured, so 1.5 ms is not evidence for this design. Task 3 measures it and stops if it fails its limit.
2. **Saturated counters are invalid beyond 2^53 in JavaScript.** The relay also re-encodes them, so precision is lost before the browser. D3 already stops its guarantee there; the mapper must accept such values, not reject them. No change proposed.
3. **D7 does not say whether a selected row that is received but filtered out keeps its panel.** Plan: it does (P7).
4. **`historyComplete` does not say whether the insertion's own eviction counts.** Plan: it does not (P3).

## Decisions taken by this plan

- **P1. Rate rank uses the sent f64s.** The agent ranks by `(rx_speed + tx_speed).total_cmp`, not by the integer byte sum: dividing first can round two unequal sums into a tie, and the browser sees only the quotients.
- **P2. Selection.** For each ranking, `select_nth_unstable_by` over one reusable `Vec<u32>` of slots, comparing (rank value desc, `last_seen_ms` desc, id asc). The union is deduplicated and sorted by id.
- **P3. `historyComplete`** is decided from `evictions` before the insertion's own eviction: the key inserted at cap+1 is complete, the next new key is not.
- **P4. Ids** start at 1; 0 in `FlowState` means "not counted yet". They keep rising across `reset`.
- **P5. Bounds validation.** The mapper rejects the event unless every number is finite and at least 0, `cap` and `topN` are at least 1, `sinceMs`/`horizonMs` are a number or `null`, every row is a non-null object, `historyComplete` is a boolean, `host`/`localAddr`/`remoteAddr`/`processName` are strings (the addresses non-empty), `ja3Label`/`observedName` are strings or absent, `tracked <= cap`, `rows.length <= min(tracked, 4 * topN)`.
- **P6. Rank by and column sort.** Changing Rank by also sets the column sort to the matching column, descending ("recent" sets Last Seen). Clicking a column never changes Rank by.
- **P7. Selection** is looked up in all received rows. Its panel stays when a filter or Rank by hides the row, and says "No longer among the received rows" only when it is not received.
- **P8. Shared fixture.** `testdata/rollup-rank.jsonl`, next to the display-filter corpus. Rows are built by the same library conversion the emitter calls (Task 4), not a copy. Written by the Rust test under `UPDATE_ROLLUP_FIXTURE=1` and otherwise compared byte for byte, so it cannot drift from the encoder.
- **P9. Lock limit.** Both tables full at the default caps with IPv6 remotes, one lock hold for both snapshots, row building included: the median of five runs must not exceed the median of five runs of `7fe5f29` at the same K on the same machine. Above it, stop and ask James; do not raise the limit or lower the caps. Process attribution runs after the flow lock is released, so it is not part of this number.

## Review Focus

1. A capture with **no local address** (canonical direction): returning keys and flow counts must behave as in the normal case. Pinned in Task 2.
2. **Cap 1 and N=1**: every packet from a new host evicts; no panic, totals still balance. Pinned in Task 1.
3. **Two tabs, or a tab reconnecting mid-capture**: the first event received must render whole, with its own counts. Pinned in Task 5.
4. **The agent is upgraded under an open new tab that showed the old-agent notice**: the notice must clear on the first valid event. Pinned in Task 5.
5. **Interface switch with a row selected and a search active**: rows and counts restart with no stale `since`, horizon or selection panel claims. Pinned in Task 6.

## Files

| File | Responsibility |
|---|---|
| `capture-agent/src/rollup.rs` (new) | `RollupTable<K>`, eviction, ranking, bounds counters |
| `capture-agent/src/flow.rs` | owns two tables; flow ids; `reset`; snapshots |
| `capture-agent/src/main.rs` | env parsing, emitter |
| `capture-agent/src/wire.rs` | new events, `BoundsJson` |
| `capture-agent/tests/rollup_cost.rs` (new) | ignored measurement |
| `capture-agent/tests/rollup_rank_fixture.rs` (new), `testdata/rollup-rank.jsonl` (new) | shared ranking fixture |
| `lib/types.ts`, `lib/agent-mapping.ts` | types and mappers |
| `lib/rollup-rank.ts` (new) | ranking in the browser |
| `lib/rollup-state.ts` | per-tab enrichment map |
| `app/page.tsx`, `components/EndpointsView.tsx` | state, notices, view |

---

### Task 1: `RollupTable`

**Files:** Create `capture-agent/src/rollup.rs`; modify `capture-agent/src/lib.rs` (module). Tests inline.

**Interfaces — produces:**

```rust
pub const DEFAULT_MAX_ENDPOINTS: usize = 50_000;
pub const DEFAULT_MAX_CONVERSATIONS: usize = 50_000;
pub const MAX_ROLLUP_CAP: usize = 500_000;
pub const DEFAULT_ROLLUP_TOP_N: usize = 200;
pub const MAX_ROLLUP_TOP_N: usize = 1_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Traffic { pub rx_bytes: u64, pub tx_bytes: u64, pub rx_packets: u64, pub tx_packets: u64 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounds {
    pub cap: usize, pub top_n: usize, pub tracked: usize,
    pub evictions: u64, pub unkeyed: u64,
    pub since_ms: Option<u64>, pub horizon_ms: Option<u64>,
    pub totals: Traffic, pub evicted: Traffic,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RollupRow<K> {
    pub id: u64, pub key: K, pub total: Traffic,
    pub rx_speed: f64, pub tx_speed: f64, pub flow_count: u64,
    pub first_seen_ms: u64, pub last_seen_ms: u64,
    pub ja3_label: Option<&'static str>, pub history_complete: bool,
}

impl<K: Copy + Eq + std::hash::Hash> RollupTable<K> {
    pub fn new(cap: usize, top_n: usize) -> Self;
    /// Returns the entry's id. Counts a flow when it differs from `last_counted`.
    pub fn record(&mut self, key: K, is_outbound: bool, bytes: u64, now_ms: u64, last_counted: u64) -> u64;
    pub fn record_unkeyed(&mut self, now_ms: u64);
    pub fn set_ja3_label(&mut self, key: &K, label: &'static str);
    /// The union of the four top-N lists in id order; drains the tick counters of every entry.
    pub fn snapshot(&mut self, elapsed_s: f64) -> Vec<RollupRow<K>>;
    pub fn bounds(&self) -> Bounds;
    /// Clears entries and counters; keeps cap, top_n and the next id.
    pub fn clear(&mut self);
}
```

- [ ] **Step 1: Write the failing tests** (`K = u32`):
  - `cap_plus_one_evicts_exactly_the_least_recent`: cap 3, record 1, 2, 3, 1, 4; the keys are {1, 3, 4} and `evictions == 1`.
  - `recency_ignores_equal_and_backward_timestamps`: the same, all at `now_ms = 5`, then with 9, 8, 7, 6, 5; same keys.
  - `totals_minus_evicted_equals_the_sum_over_tracked`: 20,000 xorshift records over 500 keys at cap 64 and N=64, checked after each 1,000 for all four fields.
  - `cap_one_top_one_balances`: 100 distinct keys; `tracked == 1`, `evictions == 99`, the same equation.
  - `slots_are_reused`: 10 × cap distinct keys; slab length is never above cap. In the same test, with cap 1,000, the index capacity never exceeds 4 × cap. This is the CI check for "memory stable over 10x cap".
  - `history_complete_follows_p3`: cap 2; keys 1, 2, 3 are true and 4 is false.
  - `a_returning_key_starts_from_zero`: evicted then recorded: `total` covers one packet, `first_seen_ms` is the return time, a new id, `history_complete == false`.
  - `evicted_and_returned_within_one_tick`: the rate covers only the packets after its return; the next tick's rate is whole.
  - `flow_counts_once_per_entry_id`: pass the returned id back as `last_counted`: count stays 1; pass 0: it becomes 2.
  - `horizon_is_the_latest_evicted_last_seen` and `since_is_the_first_recorded_or_unkeyed_packet`, each `None` first.
  - `each_ranking_matches_a_full_sort_with_ties`: 2,000 keys drawn from 5 byte sizes and 3 timestamps, N in {1, 10, 200}. Rank the returned rows by each of the four values from row fields only, tie-break (`last_seen_ms` desc, position asc), and compare the first N keys with a full sort of a reference model.
  - `identical_input_gives_identical_rows`: two tables, equal `Vec<RollupRow>`.
  - `counters_saturate`: record `u64::MAX` bytes twice; no panic.
  - `clear_resets_everything_but_the_id`.
- [ ] **Step 2:** `cd capture-agent && cargo test --locked --lib rollup` fails to compile (`RollupTable` missing).
- [ ] **Step 3: Implement** to the signatures, P2 and P3. Entries live in `Vec<Entry<K>>` with `u32` prev/next links and `HashMap<K, u32>`; at the cap the tail's slot is reused for the new key after its `Traffic` is added to `evicted`.
- [ ] **Step 4:** The same command passes; `cargo clippy --all-targets --locked -- -D warnings` is clean.
- [ ] **Step 5: Commit** `feat(agent): bounded LRU rollup table (KAN-131)`.

### Task 2: `FlowTable` uses it; flow ids, reset, caps

**Files:** Modify `capture-agent/src/reassembly.rs:1905` (the test's tuple return only; its assertions stay), `capture-agent/src/flow.rs` (maps at 190-197, `RollupState`, `observe_inner` 762-840, snapshots 1104-1160, `reset` 1172), `capture-agent/src/main.rs` (parsers near 1398, construction near 2643, emitter near 3620).

**Interfaces — consumes** Task 1. **Produces:**

```rust
pub struct RollupConfig { pub max_endpoints: usize, pub max_conversations: usize, pub top_n: usize } // Default = the constants
impl FlowTable {
    pub fn with_rollup_config(self, config: RollupConfig) -> Self;
    pub fn endpoint_snapshot(&mut self, now_ms: u64) -> (Vec<EndpointSnapshot>, Bounds);
    pub fn conversation_snapshot(&mut self, now_ms: u64) -> (Vec<ConversationSnapshot>, Bounds);
}
// both snapshot structs gain: pub history_complete: bool
// FlowState gains: endpoint_entry_id: u64, conversation_entry_id: u64
fn parse_bounded_env(name: &str, raw: Option<String>, default: usize, max: usize) -> usize; // main.rs; calls parse_positive_env, then checks max
```

- [ ] **Step 1: Write the failing tests** in `flow.rs`:
  - `a_returning_host_on_a_live_flow_counts_that_flow`: `max_endpoints` 1; flow A to host 1, a packet to host 2, then A again: host 1 has `flow_count == 1`, `history_complete == false`.
  - `two_live_flows_to_a_returning_host_count_two`; `the_same_holds_with_no_local_address` (`FlowTable::new(vec![])`).
  - `flow_counts_are_unchanged_without_eviction`: the two existing flow-count tests pass unedited apart from the tuple return.
  - `rollups_survive_idle_and_capacity_flow_eviction`: totals unchanged after `evict_stale` both ways.
  - `the_tables_evict_independently`: 3 remotes, `max_endpoints` 2, `max_conversations` 10: `evictions` are 1 and 0.
  - `an_unparsable_address_is_counted_and_not_recorded`: with a valid local address and remote `"not-an-ip"`, `unkeyed == 1` in both tables; with local address `"not-an-ip"` (in `local_addrs`) and a valid remote, `unkeyed == 1` for conversations and 0 for endpoints. Neither panics, and the flow itself is still tracked.
  - `ipv4_and_ipv6_render_as_before`: `"93.184.216.34"`, `"2001:db8::1"`, `"::ffff:1.2.3.4"` come back byte-identical.
  - `reset_clears_rollups_and_bounds`: both snapshots are empty; `tracked`, `evictions`, `unkeyed`, `totals`, `evicted` are 0; `since_ms` and `horizon_ms` are `None`; the next packet sets `since_ms`; `protocol_hierarchy()` is unchanged; the snapshot timestamps are unchanged (D6).
  - `a_ja3_label_reaches_both_tables_at_cap_one`.
  - In `main.rs`, `rollup_env_parsing`: `None`, `""`, `"  "` give the default; `"1"` and the max are accepted; `"0"`, `"-1"`, `"x"`, max + 1 panic with the variable's name (one case per variable).
- [ ] **Step 2:** `cargo test --locked` fails to compile on `with_rollup_config`.
- [ ] **Step 3: Implement.** Remove `RollupState`. In `observe_inner`, take the `FlowState` entry first, then call `record` on each table with that flow's stored id and store the result; the fields are disjoint, so the borrows do not conflict. The unkeyed rule: an endpoint is unkeyed if the remote fails to parse; a conversation if either side does. The emitter discards the bounds in this task only.
- [ ] **Step 4:** `cargo test --locked && cargo clippy --all-targets --locked -- -D warnings` pass.
- [ ] **Step 5: Commit** `feat(agent): bound the endpoint and conversation rollups (KAN-131)`.

### Task 3: Measure, and stop if it fails

**Files:** Create `capture-agent/tests/rollup_cost.rs` (ignored; counting allocator, as in `dns_names_entry_cost.rs`).

**Interfaces — consumes** `FlowTable::with_rollup_config`, both snapshots.

- [ ] **Step 1:** Write `rollup_cost`: one local address, K distinct IPv6 remotes in {10,000, 50,000, 100,000, 500,000}, caps K, N=200; five runs. Traffic: before **each** timed snapshot, feed packets so that bytes, packets, rate and recency have disjoint leaders (four groups of N hosts, each leading one ranking only), with log-uniform sizes elsewhere and an advancing clock; assert the union is 4N rows per table and that no run has all-zero rates. Keep few flows: after loading the keys, call `evict_stale` past the idle limit before timing. Print per K: median lock-hold time for both snapshots together (row building and observed-name lookup included), and row counts. Then at 50,000 for N=1,000.
- [ ] **Step 2:** Feed the identical traffic to the same loop against `7fe5f29` in a throwaway worktree (old snapshot API; not committed) and run both on one machine: `cargo test --release --locked --test rollup_cost -- --ignored --nocapture`.
- [ ] **Step 3: Apply P9.** If the new median at 50,000 is above the old one, stop and report both tables to James.
- [ ] **Step 4:** Measure memory on `RollupTable<IpAddr>` and `RollupTable<(IpAddr, IpAddr)>` directly, so no `FlowState` is counted: print live bytes per K at first fill, and again after 10 × cap distinct keys of churn (index growth under remove/insert included).
- [ ] **Step 5:** Put the results in the spec's Measurements section as a new dated table, marking the old "Tick" column as superseded. **Commit** `test(agent): measure bounded rollup cost (KAN-131)`.

### Task 4: Wire events

**Files:** Modify `capture-agent/src/wire.rs` (45-88, 335-350, tests near 2110), `capture-agent/src/main.rs` emitter, `capture-agent/tests/non_ip_replay.rs:563`. Create `capture-agent/tests/rollup_rank_fixture.rs`, `testdata/rollup-rank.jsonl`.

**Interfaces — produces:** `AgentEvent::EndpointRollup { endpoints: Vec<EndpointJson>, bounds: BoundsJson }`, `AgentEvent::ConversationRollup { conversations: Vec<ConversationJson>, bounds: BoundsJson }` (replacing the two `*Update` variants); `history_complete: bool` on both row structs; `BoundsJson` and `TrafficJson` in camelCase, with `since_ms`/`horizon_ms` as `Option<u64>` serialized as `null`; `impl From<rollup::Bounds> for BoundsJson`; and in `wire.rs`, moved out of the emitter, `EndpointJson::from_snapshot(snapshot: EndpointSnapshot, process_name: String, pid: u32) -> EndpointJson` and the same for `ConversationJson`. `main.rs` calls only these and keeps the snapshot order.

Fixture: one JSON object per line, `{"event": <event>, "topN": n, "expected": {"bytes": [...], "packets": [...], "rate": [...], "recent": [...]}}`, where each list is the first N keys (`host`, or `local|remote`). Four lines: endpoints and conversations, each with many ties and at N=3 and N=200. Timestamps include a backward step.

- [ ] **Step 1: Write the failing tests:** `encodes_endpoint_rollup_exactly` and `encodes_conversation_rollup_exactly` parse the line and compare the **whole** value with `serde_json::json!` (the spec's D4 example, `null` horizon included); `rank_fixture_matches` (P8), with `expected` from a full sort of the reference model, not from `RollupTable`; `worst_case_line_length`: N=1,000, 4,000 IPv6 rows, 253-byte names and the longest JA3 label, u64-max counters: print the length and assert it is below 4 MiB.
- [ ] **Step 2:** `cargo test --locked` fails to compile.
- [ ] **Step 3: Implement**; the emitter sends both events, with `bounds` from the same lock hold. Update `non_ip_replay.rs` to the new name. Generate the fixture: `UPDATE_ROLLUP_FIXTURE=1 cargo test --locked --test rollup_rank_fixture`.
- [ ] **Step 4:** `cargo test --locked` passes without the variable; so does `cargo test --locked --test non_ip_replay -- --ignored --test-threads=1` (ignored tests otherwise do not run); `grep -rn "endpoint_update\|conversation_update" src tests` prints nothing. If the line test exceeds 4 MiB, stop and report the size.
- [ ] **Step 5: Commit** `feat(agent): endpoint_rollup and conversation_rollup wire events (KAN-131)`.

### Task 5: Types, mappers, state and notices

**Files:** Modify `lib/types.ts` (552-610), `lib/agent-mapping.ts` (582-645), `lib/rollup-state.ts`, `app/page.tsx` (126-134, 363-370, 420-432, 1121, 1248), `components/EndpointsView.tsx` (props, notices and empty states only), `lib/__tests__/endpoints-view.test.tsx` (new props and `historyComplete`; assertions unchanged), `lib/__tests__/agent-mapping.test.ts`, `rollup-state.test.ts`, `agent-wire-contract.test.ts`, `fixtures/agent-wire-samples.jsonl`. Create `lib/rollup-rank.ts`, `lib/__tests__/rollup-rank.test.ts`, `lib/__tests__/page-rollup-handling.test.tsx`.

**Interfaces — produces:**

```ts
export interface RollupTraffic { rxBytes: number; txBytes: number; rxPackets: number; txPackets: number }
export interface RollupBounds {
  cap: number; topN: number; tracked: number; evictions: number; unkeyed: number;
  sinceMs: number | null; horizonMs: number | null; totals: RollupTraffic; evicted: RollupTraffic;
}
export interface RollupUpdate<T> { rows: T[]; bounds: RollupBounds }
export type RollupState<T> =
  | { status: 'waiting' } | { status: 'ready'; rows: T[]; bounds: RollupBounds }
  | { status: 'agent-too-old' } | { status: 'unreadable' };
// Endpoint and Conversation gain: historyComplete: boolean

export function mapEndpointRollupEvent(json: unknown): RollupUpdate<Endpoint>;
export function mapConversationRollupEvent(json: unknown): RollupUpdate<Conversation>;

export type RollupRanking = 'bytes' | 'packets' | 'rate' | 'recent';
export function rankRows<T extends RankedRow>(rows: readonly T[], ranking: RollupRanking): T[]; // lib/rollup-rank.ts; stable, array position last
// RankedRow: the wire counter, speed and lastSeenMs fields Endpoint and Conversation share

export class EnrichmentMap {                       // lib/rollup-state.ts
  record(event: RollupEnrichmentEvent): void;
  setCurrentHosts(endpointHosts: Iterable<string>, conversationHosts: Iterable<string>): void;
  get(host: string): Pick<Endpoint, 'remoteHostname' | 'enrichment'> | undefined;
  get size(): number;
}
export const MAX_IDLE_ENRICHMENT = 1_000;
export function withEnrichment<T extends Endpoint | Conversation>(rows: T[], map: EnrichmentMap): T[];
```

These replace `mapEndpointUpdateEvent`, `mapConversationUpdateEvent` and the four merge/apply functions in `rollup-state.ts`.

- [ ] **Step 1: Write the failing tests:**
  - Mapper: accepts the D4 example, `null` since and horizon, and 2^60 counters; preserves row order; rejects each P5 violation, one case each.
  - `rollup-rank.test.ts`: every line of `testdata/rollup-rank.jsonl`, mapped, gives `expected` for all four rankings.
  - Enrichment: survives leaving and re-entering; a name or PTR gone from a snapshot follows today's rules (`observedName` is never kept; the PTR name and ownership are); 1,001 idle hosts keep 1,000, evicting the oldest; 8,000 current hosts are all kept and `size <= 9,000`; a result for a host in neither list is kept as idle.
  - `page-rollup-handling.test.tsx`: an `endpoint_update` shows "The running capture agent is older than this page. Restart the agent." and renders no rows, as does `conversation_update`; a malformed event clears that table only and shows "This table's data could not be read."; each clears on the next valid event; a first event received mid-capture renders whole; the tab reads `F7: HOSTS (50,000)` from `tracked`, and `F7: HOSTS (–)` unless ready.
  - Wire contract: `agent-wire-samples.jsonl` regenerated from the real agent by that test's documented procedure, with one `endpoint_rollup` and one `conversation_rollup` line replacing `endpoint_update`.
- [ ] **Step 2:** `npx vitest run lib/__tests__/endpoints-view.test.tsx lib/__tests__/rollup-rank.test.ts lib/__tests__/rollup-state.test.ts lib/__tests__/page-rollup-handling.test.tsx lib/__tests__/agent-mapping.test.ts lib/__tests__/agent-wire-contract.test.ts` fails.
- [ ] **Step 3: Implement.** In `page.tsx`, each rollup event gets its own inner `try/catch` that sets `unreadable`; the outer catch stays. The enrichment map is a ref, and `connection_enrichment` calls `record` and re-derives the rows. `EndpointsView`'s props `endpoints`/`conversations` become `RollupState<Endpoint>`/`RollupState<Conversation>` here, and it shows the notices and empty states; its other changes are Task 6. A page test covers each empty state: waiting `Waiting for the first update.`; `agent-too-old` and `unreadable` show their notice and no other row; ready with nothing tracked `No endpoints observed yet.` (or `conversations`).
- [ ] **Step 4:** The same command passes; `./node_modules/.bin/tsc --noEmit` and `npm run lint` are clean.
- [ ] **Step 5: Commit** `feat(web): map bounded rollups and surface version mismatch (KAN-131)`.

### Task 6: `EndpointsView`

**Files:** Modify `components/EndpointsView.tsx`, `lib/__tests__/endpoints-view.test.tsx`.

**Interfaces — consumes** `RollupState`, `rankRows` and Task 5's props.

Exact copy (hosts shown; the conversations table says "conversations"):

- `Showing 200 of 396 received; 50,000 hosts tracked since 1,200 ms.` (without ` since …` when `sinceMs` is `null`)
- `812 evictions (cap 50,000): least recently active hosts were dropped; their totals (<formatBytes of evicted rx+tx>) are not in any row.` when `evictions > 0`
- `Hosts last active at or before 41,200 ms may be missing.` when `horizonMs` is not `null`
- `<n> packets had an unreadable address and are not counted.` when `unkeyed > 0`
- Search placeholder `Search received rows…`; with a term, the first line becomes `3 matches in 396 received; 50,000 hosts tracked since 1,200 ms.`
- Empty search: `No match among the 396 rows received; 49,604 more are tracked but not sent.`; when nothing is unsent, only `No match among the 396 rows received.`
- Note: `sorted within the top 200 by bytes` unless the sort is the current Rank by, descending (so Packets descending under Rank by bytes shows it); `sorted within matching received rows` with a search
- `≥` tooltip: `Earlier history may have been evicted. The rate can be low in the second this row returned.` First Seen reads `may be earlier` after its value.

- [ ] **Step 1: Write the failing tests:** every string above, present and absent, with Packets descending under Rank by bytes among the note's cases; 396 rows with `topN` 200 show 200; Rank by each ranking shows `rankRows(...).slice(0, topN)`, per table, default bytes, and sets the column sort (P6); search finds a row ranked 300th; `≥` on bytes, packets, flows and duration but not on rate, and only when `historyComplete` is false; a filtered-out selected row keeps its panel, one no longer received shows P7's text; after a reset event (`tracked` 1, new `sinceMs`, no evictions) with a row selected and a search active, no old notice remains and the panel says it is no longer received; markup in a name is still text. Existing tests change only their placeholder query (`/search received rows/i`).
- [ ] **Step 2:** `npx vitest run lib/__tests__/endpoints-view.test.tsx` fails.
- [ ] **Step 3: Implement.** Order of work on rows: search if there is a term, otherwise rank and slice; then the column sort, which must be stable.
- [ ] **Step 4:** Passes; then `npx vitest run && ./node_modules/.bin/tsc --noEmit && npm run lint`.
- [ ] **Step 5: Commit** `feat(web): honest partial host and conversation lists (KAN-131)`.

### Task 7: Docs, replay end to end, real browser

**Files:** Modify `docs/wire-protocol.md` (267-330, plus the references near 334 and 391), `docs/usage.md`, `docs/analysis-guide.md`, `docs/architecture.md` (limits table), `docs/security.md:74` (event name; eviction flooding), `docs/feature-flags.md:15`, `docs/troubleshooting.md`, `.env.example` (three names), `capture-agent/README.md` (env table and its "All nine" / fail-startup text near 186-198), `.github/workflows/ci.yml` (one step beside the `non_ip_replay` one near line 102; approved by James in chat, 2026-11-23). The release note goes in the PR body and `docs/troubleshooting.md` (the repo has no changelog). Test: `capture-agent/tests/rollup_replay.rs` (new).

- [ ] **Step 1: Write the failing test** `rollup_replay_through_the_real_binary`, modelled on `non_ip_replay.rs` (including its `#[ignore]` for exclusive 127.0.0.1:9990): a generated pcap with 5 remotes, `MAX_ENDPOINTS=2 MAX_CONVERSATIONS=3 ROLLUP_TOP_N=1`. The last `endpoint_rollup` has `tracked == 2` and `evictions == 3`, `conversation_rollup` has 3 and 2, totals balance, the rows equal the expected hosts, order and `historyComplete` values exactly, each event carries its own table's `cap`, and no `endpoint_update` or `conversation_update` line appears. A second run with `ROLLUP_TOP_N=1001` exits with an error naming `ROLLUP_TOP_N`.
- [ ] **Step 2:** Run `cargo test --locked --test rollup_replay -- --ignored --test-threads=1`, and add the same command as the CI step. Show it failing with the emitter's `EndpointRollup` send disabled, then restore it and see it pass.
- [ ] **Step 3: Docs.** State the limits, the reset, the backward-clock caveat, the `evictions` versus distinct-host distinction, and the 2^53 limit. Then `grep -rn "endpoint_update\|conversation_update" docs/*.md capture-agent/README.md lib app components` prints only the old-agent handling, its tests and the release or troubleshooting notes. Release note, verbatim: "After upgrading the capture agent, reload every open Network Monitor tab. A tab left open keeps its last host and conversation lists without a warning until it is reloaded."
- [ ] **Step 4: Full checks:** the five commands in `CLAUDE.md` §4 that apply (web, Rust, docs sync, manual bind check), plus `cargo build --release --locked`, both ignored replay tests (`non_ip_replay`, `rollup_replay`) and `npx playwright test`.
- [ ] **Step 5: Real browser** against the real agent, replaying the Task 7 pcap with small caps and then a live capture: the counts, each Rank by, search, an interface switch, and the old-agent notice using a `7fe5f29` agent with the new page. Record what was and was not seen.
- [ ] **Step 6:** Run the `security-review` skill and an independent `/code-review` on the branch. **Commit** `docs: bounded rollups (KAN-131)`.

## Not covered

Linux resident memory, sustained live load, and browser render time at N=1,000 are not automated. Task 7 observes render time once; it does not gate on it.
