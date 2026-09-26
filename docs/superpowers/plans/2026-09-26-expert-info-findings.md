# Expert Info: Findings Stream Implementation Plan

> **For agentic workers:** Use the executing-plans skill to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Ship the `finding` wire event plus three finding codes (`retransmission`, `connection-reset`, `malformed-frame`), a findings panel, and row markers — closing JAM-12's acceptance criteria without the riskier `parse_packet` signature change (see the spec's "Deliberate deviation").

**Spec:** `docs/superpowers/specs/2026-09-26-expert-info-findings-design.md`.

## Global Constraints

- No finding summary text may assert intent, cause, or maliciousness ("annotate, never conclude").
- A `retransmission` finding is only emitted for a packet that also got a `packet` wire event (same rate-limiter gate, same `pkt-...` id) — never a finding pointing at a frame the UI never received.
- `connection-reset` fires once per flow, on the `rst_seen` transition, not on every subsequent packet.
- `parse::parse_packet`'s signature and its ~20 existing call sites are unchanged.
- `docs/wire-protocol.md` is the single source of truth for the new event; Rust and TypeScript must match field-for-field in camelCase, per `CONTRIBUTING.md`.

## Review Focus

- The retransmit/reset signal computed in `FlowTable::observe()` correctly reaches the finding emission point even though packet-id generation happens later in `main.rs`'s capture loop, past the rate-limiter's early `continue`.
- `connection-reset` genuinely fires once per flow lifetime (a flow that resets, later reconnects under a fresh `FlowKey`, is a *different* flow — no dedup needed across keys, only within one).
- Findings-panel and row-marker additions don't alter any existing decrypted-content, display-filter, or export behavior — regression-test that explicitly.

---

### Task 1: Wire event and Rust types

**Files:** Modify `capture-agent/src/wire.rs`; test in `capture-agent/src/wire.rs`'s own test module (existing convention) or a new `capture-agent/tests/wire_finding.rs`.

- [ ] Write a test asserting `AgentEvent::Finding{..}` serializes to the exact JSON shape in the spec (snake_case Rust fields -> camelCase wire fields via existing `#[serde(rename_all = "camelCase")]`/`#[serde(tag = "type", rename_all = "snake_case")]` conventions), including optional `frame_id`/`flow_id` both present, both absent, and one-of-each.
- [ ] Run it and confirm it fails (the type doesn't exist yet).
- [ ] Add `Severity` (error/warning/note/chat) and `FindingCode` (retransmission/connection-reset/malformed-frame) enums with `#[serde(rename_all = "kebab-case")]` or explicit renames matching the spec's exact strings; add `FindingJson` and the `AgentEvent::Finding` variant.
- [ ] Run the test and confirm it passes.

### Task 2: Retransmission and connection-reset findings

**Files:** Modify `capture-agent/src/flow.rs` (extend `observe()`'s return type); modify `capture-agent/src/main.rs` (emit the two findings).

- [ ] Write `flow.rs` unit tests: a retransmitted segment makes `observe()` report `is_retransmit: true` exactly once (not on the original segment); a flow's first RST makes it report `rst_transitioned: true` exactly once, a second RST-flagged packet on the same already-reset flow reports `false`.
- [ ] Run and confirm both fail against the current `Option<bool>` return type.
- [ ] Change `observe()` to return `Option<ObserveResult { is_outbound: bool, is_retransmit: bool, rst_transitioned: bool }>` (or equivalent), updating `main.rs`'s one call site's destructuring accordingly. Every other `observe()` behavior (flow bookkeeping, direction) is unchanged.
- [ ] Run flow.rs tests, confirm pass; run full `cargo test` to confirm the `main.rs` call-site update didn't regress anything else.
- [ ] In `main.rs`'s capture loop, after the existing `packet_event_limiter.allow(now_ms)` check and `pkt-...` id generation (so a finding's `frameId` always corresponds to a real emitted `packet` event), emit a `retransmission` finding (severity `warning`, `frameId` = that packet's id) when `is_retransmit` was true.
- [ ] Emit a `connection-reset` finding (severity `note`, `flowId` = `FlowKey::connection_id()`) when `rst_transitioned` was true — this one is *not* gated by the packet-event rate limiter (a flow's `connection_update` event has its own independent tick-based cadence, unrelated to per-packet limiting), so emit it right where `rst_transitioned` is read, not after the packet-event gate.
- [ ] Add a `main.rs`-level integration-style test (or extend an existing one) confirming a retransmitted+rate-limited-out packet produces no dangling `retransmission` finding.

### Task 3: Malformed-frame finding

**Files:** Modify `capture-agent/src/main.rs` at the existing `unparseable_frames.fetch_add(1, ...)` call site.

- [ ] Write a test (extending whatever harness already exercises `unparseable_frames`, e.g. `capture-agent/tests/protocol_regression.rs`'s unparseable-frame case, or a new small unit test around the emission call) asserting a `malformed-frame` finding is emitted with no `frameId`/`flowId` and a summary naming the active `LinkType` and byte length.
- [ ] Run and confirm it fails.
- [ ] Emit the finding alongside the existing counter increment. Keep the summary observational: "N-byte frame did not decode as `<LinkType>` framing" — no claim about why.
- [ ] Run and confirm pass; run the full Rust suite (`cargo test`, `cargo clippy --all-targets -- -D warnings`).

### Task 4: TypeScript mapping and docs

**Files:** Modify `lib/types.ts`, `lib/agent-mapping.ts`, `docs/wire-protocol.md`; test in `lib/__tests__/`.

- [ ] Write `lib/__tests__/finding-mapping.test.ts`: `mapFindingEvent` maps a well-formed wire event to the `Finding` domain type; throws (loudly, matching every other mapper's convention) on a missing required field (`id`/`timestamp`/`severity`/`code`/`summary`); correctly carries `frameId`/`flowId` when present and omits them when absent.
- [ ] Run and confirm it fails (type/function don't exist).
- [ ] Add the `Finding` interface to `lib/types.ts` and `mapFindingEvent` to `lib/agent-mapping.ts`.
- [ ] Run and confirm pass.
- [ ] Document the `finding` event in `docs/wire-protocol.md` (own `###` section, matching the existing events' depth: JSON example, field notes, the three codes, the "annotate never conclude" framing, and the malformed-frame non-navigability note).

### Task 5: Findings panel and app wiring

**Files:** New `components/FindingsPanel.tsx`; modify `app/page.tsx` (state + SSE wiring, matching the existing `packets`/`connections` pattern) and `app/api/stream/route.ts` if it enumerates event types explicitly (check first — it may already forward unknown-to-it event types generically).

- [ ] Write `lib/__tests__/findings-panel.test.tsx`: renders one row per finding grouped by `code`; a `retransmission`/`connection-reset` row is clickable (calls an `onNavigate` callback with the right target) and a `malformed-frame` row is not (no button/clickable affordance, per the spec's non-navigability note) — assert this structurally (no `role="button"`/`onClick` on that row), not just by convention.
- [ ] Run and confirm it fails.
- [ ] Implement `FindingsPanel`, matching the terminal aesthetic (`components/PacketStreamView.tsx`'s existing severity-colored badge conventions are the reference, not a new visual language).
- [ ] Wire it into `app/page.tsx`: a `findings: Finding[]` state array fed by the SSE stream (same pattern as `packets`), a new command-bar/keyboard-shortcut entry point to show it (matching the existing `F1`-`F5` pane convention), capped the same way `packets` already is (reuse the existing buffer-limit mechanism, don't invent a second one).
- [ ] Run and confirm pass; run the full `npx vitest run` suite to confirm no regression in decrypted-content, display-filter, or export tests.

### Task 6: Row markers

**Files:** Modify `components/PacketStreamView.tsx`, `components/ConnectionsView.tsx`.

- [ ] Write tests: a packet row whose id has a matching finding shows a severity-colored marker; a connection row whose `flowId` has a matching finding shows the same; a row with no finding shows neither.
- [ ] Run and confirm fail.
- [ ] Implement the markers as a small addition next to each row's existing badges (protocol/layer badge for packets, status badge for connections) — additive, not a layout rework.
- [ ] Run and confirm pass; `npm run lint`; `npm run build`.
