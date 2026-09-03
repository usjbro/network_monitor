# Network Path Visualization — Design Spec

**Sub-project:** 3 of 4
**Status:** Approved by usjbro (jamesmbrownjr@gmail.com) on 2026-09-01, pending self-review pass below
**Date:** 2026-09-01
**Resolves:** issue #24 ("Epic: Network Path Visualization — traceroute + geoIP")

## Purpose

Give a connection in `ConnectionsView` an on-demand "trace route" action: run a real traceroute to that connection's remote IP, resolve each hop's approximate geographic location, and display the result as a hop-by-hop table (IP, round-trip time, city/country) inside the connection's detail panel — with an optional map rendering of the path as an explicitly-scoped stretch goal, not part of the core deliverable.

This sits alongside, and deliberately does not duplicate, sub-project 2's ownership enrichment: that feature answers "who owns this IP" (org, ASN, country via RDAP), opt-in and on-demand. This feature answers a different question — "what path did traffic take to get there, and roughly where geographically" — using different data sources (live ICMP probing for the path, a dedicated geoIP lookup for hop locations) and a different agent capability (the capture agent gains the ability to *send* packets for the first time; it has only ever read them until now).

## Scope

**In scope:**
- A new `traceroute.rs` module in `capture-agent` that runs a real ICMP-based traceroute to a target IP: send an ICMP Echo Request with TTL=1, wait for a reply (Time Exceeded from the first hop, or Echo Reply if the destination is one hop away), record the replying IP and round-trip time, increment TTL, repeat up to a hop-count ceiling or until the destination itself replies.
- A new agent-side control message, `trace_route { target_ip }`, sent over the existing TCP control channel (the same connection `pause`/`resume` already use), triggering one traceroute run.
- A new `traceroute_hop` NDJSON wire event, one per hop, streamed to the relay as each hop resolves (not batched at the end) — so the UI can render hops arriving progressively, matching what running traceroute at a terminal actually feels like.
- A new relay-side `GeoIpClient` (`lib/geoip.ts`), architecturally a sibling to sub-project 2's `EnrichmentClient`, not a fork of it: same default-off/runtime-only-opt-in/scope-filtered/disk-cached/rate-limited shape, its own small module, reusing sub-project 2's `lib/enrichment/scope-filter.ts` (`isPrivateOrReserved`, `cidrContains`) directly rather than reimplementing private-range filtering a second time.
- UI: a "trace route" action on the selected connection in `ConnectionsView`; a hop table in the detail panel (IP, RTT, city/country, org-if-already-enriched) populated as `traceroute_hop` events arrive.
- **Stretch, explicitly separable:** a simple path visualization (e.g., an ordered list rendered as connected nodes, not necessarily a world map with real geographic projection) — ships only if the hop table and core plumbing land cleanly first. The spec's Testing and Security sections both treat this as optional; nothing else in this spec depends on it.

**Explicitly out of scope:**
- Automatic traceroute on every new connection. Rejected during design review: this repo's established pattern (sub-project 2) is default-off/on-demand for exactly this class of feature, and automatic traceroute would mean continuous outbound probe traffic and continuous new-agent-privilege exercise scaling with connection churn rather than with user intent. Every trace is a deliberate, one-connection, one-shot user action.
- A live third-party geoIP *and* a bundled offline database both being built — pick one (see Components §2 below); the other is not a fallback path in this version.
- UDP-based traceroute (the classic Unix default). ICMP-echo-based traceroute is used instead — see Components §1 for why.
- Continuous/repeated path monitoring (MTR-style rolling statistics). One trace is one point-in-time snapshot; re-running is a new user action, not a background job.
- Correlating JA3 fingerprints or ownership-enrichment org data with path/hop data. Real potential value, own future analysis feature, not core plumbing (same reasoning sub-project 4's spec used to defer the equivalent JA3↔RDAP correlation).

## Architecture

```
Capture Mac
┌──────────────────────────────────────────────────────────────────┐
│  Browser: ConnectionsView "trace route" button (per-connection,   │
│  on-demand only)                                                  │
│         │ POST /api/traceroute/start { connectionId, remoteAddr } │
│         ▼                                                         │
│  Next.js relay                                                    │
│   ├─ sends trace_route{target_ip} control message to the agent    │
│   │    over the existing TCP control channel                      │
│   └─ GeoIpClient (new, sibling to EnrichmentClient) — opt-in,      │
│        scope-filtered, cached, rate-limited geoIP lookups per hop │
│         ▲                                                         │
│         │ traceroute_hop events (NDJSON, one per resolved hop)    │
│  Rust capture agent                                                │
│   └─ traceroute.rs (new): sends ICMP Echo Request, TTL=1..N,       │
│        via an unprivileged ICMP datagram socket (see Components   │
│        §1 for the privilege model and its fallback)                │
│         │                                                          │
│         ▼                                                          │
│      real network path to the connection's remote host             │
└──────────────────────────────────────────────────────────────────┘
```

No new listening port. The control channel is the existing agent↔relay TCP socket; the wire event is a new NDJSON line type on the existing stream, same pattern sub-project 4 used for `decrypted_payload` and sub-project 1a already established for `connection_update`/`packet`.

## Components

### 1. `capture-agent/src/traceroute.rs` — probe mechanism and its privilege model

**Mechanism:** ICMP Echo Request/Reply, not UDP. Classic Unix traceroute sends UDP datagrams to a high port and relies on "TTL exceeded"/"port unreachable" ICMP *error* replies — but *receiving* an ICMP error reply to a plain UDP send reliably, cross-platform, without a raw socket, is the genuinely fiddly part of a UDP-based design (platforms differ on how/whether they deliver that error back to the originating socket). ICMP-echo-based traceroute sidesteps this: the agent sends its own ICMP Echo Request with an incrementing TTL and listens on the *same* ICMP socket for any reply — a Time Exceeded from an intermediate hop, or an Echo Reply once the destination itself is reached — both of which the kernel correctly routes back to the socket that "owns" the outbound sequence/identifier, on macOS as on Linux.

**Privilege model — the one open engineering question this spec flags rather than asserting confidently:** macOS (like Linux, gated there by `net.ipv4.ping_group_range`) supports `SOCK_DGRAM` sockets with `IPPROTO_ICMP` — "ping sockets" — which let an unprivileged process send ICMP Echo Requests and receive Echo/error replies without `SOCK_RAW` and without root, unlike a traditional raw-socket ping implementation. This is the mechanism this spec recommends, and it plausibly extends the existing one-time setup story (`capture-agent/README.md`'s `access_bpf` group grant) with, at most, one more one-time step rather than a `sudo`-at-runtime requirement — but this repo has not verified `SOCK_DGRAM`/`IPPROTO_ICMP` actually works unprivileged on the target macOS versions this agent supports, and the spec does not claim it does. **This is the first task of the implementation plan, framed as a spike:** confirm the unprivileged ping-socket path works via a minimal standalone probe before writing `traceroute.rs` against it. If it doesn't pan out on the supported macOS versions, the named fallback is **not** a redesign — it's `traceroute.rs` shelling out to the OS's own `traceroute` binary (already correctly privileged by the OS installer) and parsing its stdout into the same `HopResult` shape the rest of this spec describes, isolating the fallback to one module's internals. Either way, the wire event, `GeoIpClient`, and UI in this spec are unaffected — they consume `HopResult { hop_number, ip: Option<String>, rtt_ms: Option<f64> }` regardless of which mechanism produced it.

**Bounded by design:** a hop ceiling (30, matching standard traceroute's default), a per-hop timeout (1s, three retries before recording that hop as "no response" and moving to the next TTL — a silent hop, like a firewall dropping ICMP, doesn't abort the whole trace), and a total-trace timeout (45s) so one trace can never run indefinitely. Same tolerance-for-partial-failure posture as `parse.rs`'s "malformed input never blocks other fields" precedent — a non-responding hop is data (something worth showing), not an error.

### 2. `lib/geoip.ts` — `GeoIpClient`

A **live, opt-in geoIP lookup service** (not a bundled offline database) — chosen over bundling because a static database needs manual, periodic updates to stay accurate and this repo has no existing release/update mechanism for shipped data files, while a live lookup (mirroring sub-project 2's already-reviewed RDAP pattern) gets that maintenance for free at the cost of one more outbound dependency to vet. That tradeoff was made explicitly during design review, not defaulted into.

- **Same default-off/runtime-only opt-in as `EnrichmentClient`** — no config flag persists "geoIP enabled" across a relay restart; every session is a conscious opt-in, extending sub-project 2's precedent to a second feature rather than treating that precedent as a one-off.
- **Scope filtering reused, not reimplemented:** calls `isPrivateOrReserved` from `lib/enrichment/scope-filter.ts` (sub-project 2, Task 1) before ever looking up a hop IP — a private/reserved hop (common on the first few hops of any trace, inside the user's own LAN/ISP CGNAT) is never sent to a third-party service.
- **Cached and rate-limited on the same shape as `EnrichmentCache`** — disk-persisted, TTL'd (geoIP data is coarser and more stable than RDAP org data; a 30-day TTL is reasonable, longer than sub-project 2's 14-day RDAP TTL, and is a deliberate, named difference not an oversight), under `.data/geoip/` (sibling to `.data/enrichment/`, same `{ recursive: true, mode: 0o700 }` posture).
- **Provider and dependency hygiene:** the specific geoIP HTTP API is an implementation-plan-time decision (this spec deliberately does not pin a vendor), but it is bound by the same rules sub-project 2's spec already established for this repo: HTTPS only, response size cap, request timeout, no API key logged even if one is required, and the extra-scrutiny dependency review `docs/security.md` calls for on any new outbound-network dependency.
- **Not a WHOIS/RDAP replacement:** a hop already covered by sub-project 2's ownership enrichment (if the user has that opted in too) can show both — org/ASN from `EnrichmentClient`, city/country from `GeoIpClient` — but neither client depends on the other being enabled. A user with only geoIP opted in still gets hop locations without org data, and vice versa.

### 3. Wire/event changes

- New `traceroute_hop` NDJSON event (agent → relay), `#[serde(tag = "type", rename_all = "snake_case")]` matching every existing event's convention:
  ```json
  { "type": "traceroute_hop", "targetIp": "93.184.216.34", "hopNumber": 4, "hopIp": "12.122.1.1", "rttMs": 18.4 }
  ```
  `hopIp`/`rttMs` are both optional (absent = no response at that hop, not an error — see Components §1). A final hop's `hopIp` equal to the connection's own `remoteAddr` signals trace completion to the UI; no separate "trace complete" event is needed.
- New relay → agent control message, `{ "type": "trace_route", "targetIp": "93.184.216.34" }`, following the exact framing `pause`/`resume` already use on the same control channel.
- New relay → browser SSE: `traceroute_hop` events pass through unmodified from the agent (no relay-side transformation needed — the agent's hop data is already display-ready), interleaved with hop-level `geo_hop_update` events the relay emits itself once `GeoIpClient` resolves each hop's location (kept as a *separate* event from `traceroute_hop`, not merged, because geoIP resolution is opt-in and can lag behind or be entirely absent while the hop itself always displays — same "don't couple an optional enrichment to the required data it augments" reasoning sub-project 2 already applied to `connection_update` vs. `connection_enrichment`).
- `docs/wire-protocol.md` gets the `traceroute_hop` event and `trace_route` control message documented (agent-originated, so it belongs there). `geo_hop_update` is relay-originated only, so it's documented in a new `docs/geoip-protocol.md`, mirroring how sub-project 2's `connection_enrichment` got its own `docs/enrichment-protocol.md` separate from the agent-originated wire protocol doc.

### 4. UI surface

- `ConnectionsView`'s detail panel gains a "Trace Route" button, disabled while a trace is already in flight for that connection (one trace at a time per connection; nothing in this spec supports concurrent traces to the same target).
- Hop results render as a table as they arrive: hop #, IP (or "* * *" for no response, matching real traceroute's own convention), RTT, and — once/if `geo_hop_update` arrives for that hop — city/country. A hop with geoIP still pending shows "resolving…"; a hop whose geoIP lookup ultimately fails or was skipped (private range, opt-in not enabled) shows "location unavailable" rather than blocking or hiding the row.
- **Stretch (Scope):** a simple ordered path visualization once the table is solid — explicitly not gating the table's own ship-readiness.

## Setup & operations

**One-time setup:** if the Task-1 privilege spike (Components §1) confirms the unprivileged ping-socket path, likely one additional one-time macOS grant alongside the existing `access_bpf` step in `capture-agent/README.md` — the exact mechanism (an entitlement, a `sysctl`, or nothing extra at all) is determined by that spike, not asserted here. If the spike fails and the system-`traceroute` fallback is used instead, no additional setup is needed beyond that binary already being present on macOS by default.

**Per-use:** click "Trace Route" on a connection. One trace, one connection, one point in time — nothing persists or re-runs automatically.

**GeoIP opt-in:** mirrors sub-project 2's `enrich`-style command-bar verbs — `geoip enable` / `geoip disable` / `geoip clear`, wired through `CommandLineBar`'s existing help-text pattern.

## Security model summary

| Threat | Mitigation |
|---|---|
| Agent gains a new capability class — sending packets, not just observing them, for the first time in this repo | Scoped tightly: ICMP Echo Requests only, only in response to an explicit user-triggered `trace_route` control message, only to the one target IP requested, bounded hop count/timeout/total-trace-time (Components §1). Never automatic, never background, never a general-purpose "send arbitrary packets" capability. |
| Elevated-privilege requirement for probe sending | Addressed head-on via the unprivileged-ping-socket approach and its explicit fallback (Components §1) — this spec does not ship a `sudo`-at-runtime requirement under any resolution of that open question. |
| GeoIP lookups leaking hop IPs (including the user's own ISP/CGNAT infrastructure on early hops) to a third party | Same scope-filter-before-lookup posture as sub-project 2, reusing its actual filter function; opt-in, never automatic; disk-cached to minimize repeat exposure of the same IPs. |
| Traceroute used as a scanning/reconnaissance primitive against arbitrary hosts | Out of scope as a threat this design defends against — same posture RDAP lookups took in sub-project 2 ("the user deliberately chose this target, as themselves"); a trace only ever targets a `remoteAddr` already present in `ConnectionsView`, i.e. a host the machine already has a real connection to, not an arbitrary user-supplied IP. |
| Oversized/runaway trace consuming agent resources | Bounded hop ceiling (30), per-hop timeout+retry cap, total-trace timeout (45s) — Components §1. |
| GeoIP provider response data (city/country strings) rendered unsafely in the UI | Plain text rendering only, no `dangerouslySetInnerHTML`, covered by the existing `no-dangerous-html.test.ts` regression suite extended with geoIP-response fixtures — same posture every other network-sourced string in this app already gets. |

## Error handling & lifecycle

- **A hop never replies:** recorded as "no response" after the timeout+retry budget for that TTL is spent; the trace continues to the next hop, not aborted (Components §1).
- **The destination is unreachable / trace never completes:** stops at the total-trace timeout (45s) or hop ceiling (30), whichever comes first; the UI shows whatever hops did resolve plus a plain "trace did not reach destination" state, not an error.
- **GeoIP lookup fails or times out for a hop:** that hop's row shows "location unavailable"; never blocks the hop's own IP/RTT from displaying, never blocks other hops' geoIP from resolving.
- **User navigates away / closes the detail panel mid-trace:** the agent-side trace runs to completion or timeout regardless (it's a bounded, cheap operation); the browser simply stops rendering hop events for a connection it's no longer displaying — no cancellation control message is needed given the 45s bound.
- **Two trace requests for the same connection in flight:** the UI's disabled-button-while-in-flight state (UI surface) prevents this from user action; if it happens anyway (e.g. a second browser tab), the agent runs both — traceroute is a `type` value the agent script simply processes as two triggers, cost-bounded the same as one, since the queueing/dedup discipline sub-project 2 applied to RDAP lookups was justified there by a 3-10s inter-request rate limit against a third party, which doesn't apply to a mostly-local probe sequence the same way.

## Dependency hygiene

- `capture-agent/src/traceroute.rs`: pure Rust, ICMP socket handling via the standard library or a small, already-audited-in-the-Rust-ecosystem socket crate if the standard library's socket API doesn't expose what's needed for `SOCK_DGRAM`/`IPPROTO_ICMP` directly — flagged for the same extra-scrutiny review sub-project 4 applied to its own new Rust crates, decided at implementation-plan time once the Task-1 spike (Components §1) determines the exact mechanism.
- `lib/geoip.ts`: matches sub-project 2's zero-new-npm-dependency precedent where possible (built-in `fetch`); the specific geoIP provider's SDK, if any exists and is used instead of raw `fetch`, gets the extra-scrutiny dependency review `docs/security.md` calls for.
- `npm ci`, `ignore-scripts=true`, exact pinning — unchanged, repo-wide policy.

## Testing

- **Traceroute correctness:** fixture-driven tests against captured ICMP reply sequences (Time Exceeded from intermediate hops, Echo Reply from the destination, malformed/truncated ICMP), same posture as `parse.rs`'s fixture-driven tests — folded into the existing `cargo-fuzz` target's input space for the new ICMP-reply-parsing code path, not a new target, since it's the same "untrusted bytes off the wire" shape `parse.rs` already fuzzes.
- **Privilege-spike verification:** a standalone, documented manual check (not a `cargo test`, since it depends on OS/account state a CI sandbox may not replicate) confirming the chosen probe mechanism (unprivileged ping-socket or the system-`traceroute` fallback) actually works on the supported macOS version — this is Task 1 of the implementation plan, and its outcome determines which of the two `traceroute.rs` implementations the rest of the plan builds against.
- **Hop bounding:** tests asserting the hop ceiling, per-hop timeout+retry, and total-trace timeout are all honored — a trace against a deliberately non-responding fixture target must terminate at the bound, not hang.
- **`GeoIpClient`:** mirrors `EnrichmentClient`'s existing test suite shape directly — injected fetch, no live network calls, scope-filter-skips-private-IPs test, cache-hit/TTL-expiry tests, opt-in-never-persists-across-restart test.
- **Wire event correctness:** `traceroute_hop`/`geo_hop_update` JSON shape tests, camelCase field-name assertions, matching the convention checks sub-project 4 applied to `ja3Fingerprint`/`decrypted_payload`.
- **UI:** hop table renders progressively as events arrive (not waiting for trace completion), "no response"/"resolving…"/"location unavailable" states each render distinctly, "Trace Route" button correctly disables while a trace is in flight for that connection.
- **Rendering safety:** geoIP response fixtures (city/country strings, including deliberately HTML/script-like ones) added to `no-dangerous-html.test.ts`.

## Deferred to later sub-projects / follow-ups

- **Path visualization map** — ships only if the hop table lands cleanly first (Scope); if deferred, it's a follow-up to this same sub-project, not a new epic.
- **JA3↔path or ownership↔path correlation** — real potential value, own future analysis feature, not core plumbing (Scope).
- **Continuous/rolling path monitoring (MTR-style)** — one-shot traces only in this version (Scope); a background/repeated mode would need its own automatic-vs-on-demand and privilege-load discussion this spec deliberately avoided by staying on-demand.
- **UDP-based traceroute as an alternative probe mode** (e.g. for environments that block ICMP but allow UDP) — named here so it isn't rediscovered from scratch, not attempted in this version given the cross-platform ICMP-error-delivery complexity noted in Components §1.

## Spec self-review

- **Placeholder scan:** no TBD/TODO markers; the one genuinely open item (exact privilege mechanism, Components §1) is stated as an open, spike-resolved question rather than hidden or asserted without evidence — that's a deliberate research item carried into the plan, not a placeholder.
- **Internal consistency:** the on-demand-only scope decision (Scope, Architecture) is carried consistently through Components §1's bounded-cost reasoning, the Security model table's "never automatic" row, and Error handling's no-dedup-needed reasoning — no section contradicts it.
- **Scope check:** focused enough for a single implementation plan; the map visualization is explicitly separable so it doesn't need to gate the plan's initial task sequence.
- **Ambiguity check:** "geoIP" was ambiguous at the issue level (bundled DB vs. live service vs. reusing RDAP country) — resolved explicitly in Components §2 with the tradeoff stated, not left to the implementer to guess.
