# Expert Info: Findings Stream — Design Spec

**Issue:** JAM-12 (GitHub #79) — "Expert info: surface the anomalies the engine already computes"
**Epic:** JAM-126 (#56)
**Depends on:** #61 (capture-drop reporting) — already shipped as `capture_stats`'s `dropped`/`ifDropped`/`relayLaggedEvents`/`unparseableFrames` fields (JAM-125). JAM-9's field registry (byte-offset-addressable fields) and JAM-10's display-filter language are also already shipped.

## Problem

The agent already detects several real anomalies and throws the detail away:

- **Retransmissions** (`flow.rs`'s `observe()`) survive only as an aggregate `packet_loss` percentage per flow. Which frame retransmitted is unknowable from the UI.
- **Malformed frames** (`parse::parse_packet` returning `None`) vanish with no per-frame record — only a cumulative `unparseableFrames` counter (`capture_stats`).
- **Resets** (`TcpFlags.rst`) are folded into a flow's `status` string ("TIME_WAIT"), never reported as a discrete event.

This is the cheapest credibility feature on the roadmap: the underlying data already exists; the work is mostly plumbing plus a view.

## Framing constraint (non-negotiable)

Per the baseline design document, a finding **annotates, it does not conclude**. No finding's text may assert intent, cause, or maliciousness (no "attack", "suspicious", "malicious") — only what was observed ("retransmitted segment", "connection reset by peer or self"). This is a declared product non-goal, not a phase-1 simplification.

## Wire contract: `finding` event

New agent → relay event, emitted immediately (like `packet`), not batched per tick:

```json
{
  "type": "finding",
  "finding": {
    "id": "finding-<epoch_ms>-<seq>",
    "timestamp": "<epoch ms as string>",
    "severity": "error" | "warning" | "note" | "chat",
    "code": "retransmission" | "malformed-frame" | "connection-reset",
    "summary": "<human text, observation only>",
    "frameId": "pkt-...",
    "flowId": "Tcp-192.168.1.10:51000-93.184.216.34:443"
  }
}
```

- `frameId`/`flowId` are each optional; a finding carries whichever target(s) it can attribute to (see "Non-navigable findings" below). At least one of the four content fields (`code`, `summary`) is always present; `frameId`/`flowId` may both be absent.
- `id` is a stable, monotonic identity for React keys and de-duplication — mirrors `packet.id`'s own `pkt-<epoch_ms>-<seq>` shape.
- `code` is a small, closed, stable set (like `path` in the field registry) — new codes are additive, existing ones are never renamed once shipped, matching `docs/wire-protocol.md`'s existing "adding a new field" discipline.
- Severity is advisory display metadata, not derived from the "how bad is this" axis the annotate-never-conclude rule forbids — `warning` for something a user should look at, `note` for an observed-but-normal event (a reset is not inherently bad), matching Wireshark's own Expert Info severity vocabulary the baseline document cites.

## Phase 1 scope (this task)

Three finding codes, chosen because each is either fully wire-supported already or a small, low-risk addition:

1. **`retransmission`** — frame-attributable (`frameId`), `warning`. Emitted for the same packet `flow.rs::observe()` already flags via `state.retransmits += 1`, using that same per-direction, payload-only, first-segment-safe logic (no new detection logic; see `flow.rs`'s existing comment for why this is not a false-positive-prone signal).
2. **`connection-reset`** — flow-attributable (`flowId`), `note` (not `error` — a reset is a normal TCP closing mechanism as often as an abnormal one; per "annotate, never conclude" this must not read as bad news). Emitted once, on the *transition* into `rst_seen = true` for a flow (not repeated on every subsequent packet of an already-reset flow).
3. **`malformed-frame`** — **not frame- or flow-attributable** (see below), `warning`. Emitted when `parse::parse_packet` returns `None` (already counted via `unparseable_frames`; this makes each occurrence individually visible, not just the running total).

### Deliberate deviation: no per-parse-stage failure reason

The issue's proposed scope asks for "malformed frame (with the parse failure reason)". `parse_packet`'s current signature (`-> Option<ParsedPacket>`) discards *why* at ~6 different return points across Ethernet/loopback/raw framing and IPv4/IPv6/TCP/UDP decoding, and it is the capture agent's most heavily fuzzed, most-tested public function (`fuzz/fuzz_targets/parse_packet.rs`, 20+ call sites across `tests/protocol_regression.rs`, `fields.rs`, `main.rs`). Changing its signature to `Result<ParsedPacket, ParseFailureReason>` to thread a granular reason through is a much larger, riskier change than this task's actual payoff justifies.

Instead, the `malformed-frame` finding's summary states what the call site already knows without touching `parse_packet` at all: the active `LinkType` and the frame's byte length (e.g. "58-byte frame did not decode as Ethernet framing"). This satisfies the acceptance criterion ("malformed frames are counted and inspectable instead of vanishing") without the parse.rs API change. A follow-up to thread a real per-stage reason through `parse_packet` is left explicitly open, not silently dropped.

### Non-navigable findings

Acceptance criterion "every finding row navigates to its frame or flow" is satisfiable for `retransmission` (a `packet` event with that `frameId` was — almost always — also emitted; see rate-limiting note below) and `connection-reset` (a `connection_update` for that `flowId` already exists once the flow's next periodic tick fires). It is **not** satisfiable for `malformed-frame`: `parse_packet` failing means no `ParsedPacket` and therefore no `packet` event ever existed for that frame — there is nothing to navigate to. The findings panel renders a `malformed-frame` row as informational-only (no click affordance), which is the honest behavior, not a bug to fix later.

### Rate-limiting interaction

`main.rs`'s capture loop only emits a `packet` event when `packet_event_limiter.allow(now_ms)` is true; under sustained high packet rates some packets never get a `packet` event or a `pkt-...` id at all. A `retransmission` finding must only be emitted for a packet that *also* got a `packet` event — otherwise `frameId` would point at a frame the UI never received. Concretely: the retransmit/reset signals are computed in `FlowTable::observe()` (before the rate-limit check, cheap booleans), but the actual `Finding` wire event is only sent after the `packet_event_limiter.allow(...)` check and packet-id generation, reusing that same id. A rate-limited-out retransmission simply produces no finding, the same as it already produces no `packet` event — consistent, not a new gap.

## Deferred to a later task (explicitly, not silently)

- **Duplicate ACK, zero window** — both need genuinely new detection state in `flow.rs` (duplicate-ACK requires tracking the last few ACK numbers per direction; zero-window requires tracking the advertised window trend), not just surfacing something already computed. Real work, not plumbing — out of this task's "cheapest credibility feature" framing.
- **`capture-drop` / `relay-lag` findings** — `capture_stats`'s `dropped`/`ifDropped`/`relayLaggedEvents` already have a dedicated, always-visible "capture degraded" banner (`app/page.tsx`). A duplicate finding-stream entry for the same three counters adds surface area without adding information a user doesn't already have. Revisit only if the findings panel becomes the primary place users are told to look for capture health.
- **Severity-based display-filtering** (issue's item 5, "once #77 lands") — JAM-10's `lib/display-filter.ts` scopes evaluation to `{kind: 'packet' | 'connection', ...}`. Adding a third `finding` kind is a real, if small, extension of that evaluator and its field-registry-style abbreviations (`expert.severity`, mirroring the baseline's `_ws.expert.severity`). Deferred so this task's vertical slice (wire event → panel → markers) ships first; filtering findings is a natural, separately-reviewable follow-up once the panel exists to filter.

## Frontend

- `lib/types.ts`: new `Finding` interface; `lib/agent-mapping.ts`: new `mapFindingEvent`, following the existing throws-on-missing-required-field convention.
- A `FindingsPanel` component: rows grouped by `code`, each row showing severity, count-if-repeated is *not* done in Phase 1 (each finding is its own row — aggregation-by-count is a display nicety, not required by any acceptance criterion, and premature before real usage volume is seen).
- Row markers: `PacketStreamView`'s packet list gets a small severity-colored marker on any row whose `pkt-...` id has a finding; `ConnectionsView` gets the same for `flowId`. Both are additive to existing rendering, matching JAM-11's "keep the terminal aesthetic" precedent.

## Out of scope, unchanged

- Decrypted-payload gating, TLS visibility, ownership/GeoIP enrichment — untouched.
- No new wire *request* (control) message; findings are agent → relay only.
