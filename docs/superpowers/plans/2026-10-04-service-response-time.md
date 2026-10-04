# Request/Response Matching and Service Response Time — Implementation Plan

**Goal:** JAM-15's acceptance criteria: DNS and HTTP responses linked to their requests with service time shown and filterable; unanswered requests time out, are reported, and don't accumulate; matching covered by tests including out-of-order and duplicate responses; fuzz coverage for the new parsers.

**Spec:** `docs/superpowers/specs/2026-10-04-service-response-time-design.md`.

## Global Constraints

- Every structure the matcher holds is bounded (spec's "Bounds" table), and the fuzz target asserts it.
- A `response_to` link or an unanswered finding's `frameId` only ever names a packet event the UI actually received.
- Service time and timeouts run on capture timestamps.
- Rust and TypeScript wire contracts change together. `docs/wire-protocol.md` is updated in the same change, and the contract fixture holds lines captured from a real agent.

## Tasks

1. **DNS response decoding** (`capture-agent/src/l7.rs`): `L7Info::DnsResponse`, `Dns { id, qtype }`, a compression-aware name reader with hop and length caps, answer decoding capped at 16. Tests: rcode/answers, AAAA, a compressed CNAME, a pointer loop, a truncated answer section, the answer cap, a response missing its question type.
2. **Fields** (`fields.rs`): `dns.id`, `dns.flags.response`, `dns.flags.rcode`, `dns.qry.type`, `dns.count.answers`, indexed `dns.answer.<i>.*`. `transaction_fields` for `*.time_us`, `*.response_to` and `dns.response.duplicate`. Test that paths are unique and every group exists.
3. **Matcher** (`transaction.rs`): matching, duplicates, retransmits, bounds, timeouts, reset and statistics, with a unit test per rule.
4. **Wire** (`wire.rs`): `FindingCode::UnansweredRequest`, `AgentEvent::ServiceTimeUpdate`, `ServiceTimeSummaryJson`. Exact-JSON encoding test.
5. **Capture loop** (`main.rs`): tracker on the capture thread; observe after `FlowTable::observe` (with the reassembled datagram's flow for a completed fragment group); attach the frame id once the packet event is built; sweep on every frame and on live read timeouts; reset on interface switch; tick emitter sends `service_time_update`.
6. **Fuzz**: `fuzz/fuzz_targets/l7_transactions.rs` plus its CI step, and `src/transaction.rs` added to the fuzz path filter.
7. **UI**: `ServiceTimeSummary` type and mapper, `lib/service-time.ts` link helpers, `ServiceTimeView` (F5), the badge and link bar in `PacketStreamView`, the finding code in `Finding`.
8. **Verify in the real app**: replay a pcap with an answered DNS query, an unanswered one, a duplicate response and an HTTP exchange through the release agent, drive the UI in Chromium, and add the captured `service_time_update` and `finding` lines to `lib/__tests__/fixtures/agent-wire-samples.jsonl`.
