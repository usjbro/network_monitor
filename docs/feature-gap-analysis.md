# Feature gap analysis — OSI NetStriker vs. the Wireshark design baseline

**Status:** product input, not a commitment. Written 2026-09-18 against commit `c966340` (post PR #51).
**Baseline document:** *Wireshark — Technical Design Document* (feature/capability specification, rev 18).
**Audience:** whoever picks the next epic after #23/#24/#25 closed out the original roadmap in issue #26.

## How to read this

The baseline document specifies Wireshark's feature set across 17 sections. This file walks the same
sections against what this repo actually does today, and turns each divergence into either a **missing
feature** (nothing exists) or an **improvement** (something exists but is thinner than the job needs).

Two things this is *not*:

- It is not a plan to clone Wireshark. Wireshark is a 3,000-protocol forensic workbench; this is a live
  OSI-layer terminal for one Mac. Section "Deliberate non-goals" below records what we are declining and why.
- It is not a spec. Per `CONTRIBUTING.md`, anything here that gets picked up needs a design spec under
  `docs/superpowers/specs/` before code.

Sizing is engineering-effort shorthand: **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ 3–6 weeks, **XL** ≈ a quarter-ish epic.

## Coverage today, by baseline section

| Baseline section | Our state | Where it lives |
| --- | --- | --- |
| 5. Capture subsystem | Partial — one interface, live only, no capture-time controls | `capture-agent/src/main.rs` |
| 6. Protocol dissection | Thin — Ethernet II + IPv4/6 + TCP/UDP/ICMP, three L7 sniffers | `capture-agent/src/parse.rs`, `src/l7.rs` |
| 7. Filtering model | Thin — client-side substring/protocol/layer filters, no filter language | `components/ConnectionsView.tsx`, `components/PacketStreamView.tsx` |
| 8. Analysis and statistics | Partial — per-layer + per-flow stats, sparklines, traceroute, ownership | `capture-agent/src/flow.rs`, `lib/agent-mapping.ts`, `lib/enrichment/` |
| 9. Decryption | Partial — TLS 1.3 for one opted-in PID via key log | `capture-agent/src/tls_decrypt.rs`, `bin/osi-inspect.js` |
| 10. File formats and interchange | **None** — no read, no write, no export | — |
| 11. Command-line toolchain | Minimal — `osi-inspect` launcher only | `bin/osi-inspect.js` |
| 12. Extensibility | **None** beyond themes | `lib/osi-engine.ts` (`THEMES`) |
| 13. Performance and resource model | Partial — caps and eviction exist, no visibility into them | `src/core_limits.rs`, `src/rate_limit.rs`, `src/flow.rs` |
| 14. Security model | Strong on transport/privilege, gaps in parser containment and CI fuzzing | `docs/security.md`, `deploy/`, `.github/workflows/ci.yml` |
| 15. Platform support | macOS-only in practice | `capture-agent/README.md` |
| 16. Known limitations | Mostly unsurfaced to the operator | — |

The headline: **the capture and presentation ends are real, the middle is thin.** We capture honestly and
render beautifully, but between those two points there is no field model, no filter language, no reassembly,
and no file format — which is exactly the layer the baseline document says carries the design (its sections 4–7).

## Tier 1 — foundational gaps

These unblock multiple downstream features. Everything in Tier 2 gets cheaper once these exist.

### F1. Capture-to-file and file replay (pcapng) — **XL**, missing entirely

Nothing in the repo reads or writes a capture file. The agent streams JSON to whoever connects and the
browser holds the last 100 packets (`app/page.tsx:145`) and 200 connections (`app/page.tsx:133`); everything
else is gone forever.

Why it matters: it is the single biggest multiplier in the baseline document. File support buys offline
analysis, handing a capture to someone else, "what happened 20 minutes ago", regression tests over fixed
captures in CI, and — once pcapng Decryption Secrets Blocks land — portable decryption. Every analysis
surface in Tier 2 is also easier to build and test against a file than against a live stream.

Scope: pcapng write from the agent (Section Header, Interface Description, Enhanced Packet blocks at minimum),
a file-source mode for the relay so the UI can replay a capture through the same mapping path, and `capinfos`-style
metadata in the UI. Explicitly *not* 30 foreign formats — pcapng plus classic pcap read is the whole ask.

### F2. Capture-time controls: BPF filter, snap length, ring buffer, autostop — **M**, missing entirely

`main.rs:360-370` opens the device with `promisc(true)`, `snaplen(65535)`, `timeout(1000)`,
`immediate_mode(true)`, and **no BPF filter** — every frame on the segment is copied to user space and
dissected. There is no way to scope a capture to a host, port or protocol, no way to truncate payload, and no
bounded-duration or bounded-size run.

Why it matters: the baseline document calls capture filters "the cheapest way to cut volume" and is blunt
that display filters do not reduce memory. Today our only volume control is dropping data on the floor after
we have already paid to parse it. This is also the privacy control: a snap length of 96 bytes captures headers
and not payload, which is the difference between a capture you can share and one you cannot.

Scope: extend the control channel (`capture-agent/src/wire.rs` `ControlMessage`, `app/api/control/route.ts`)
with a `set_capture_filter` / `set_snaplen` pair, validated and applied by reopening the handle; command-bar
verbs (`filter tcp port 443`, `snaplen 96`); plus ring-buffer and autostop once F1 exists.

### F3. Capture-side drop counters — **S**, missing entirely

`pcap::Stat` is never read anywhere in `capture-agent/src/`. The only loss signal is an `eprintln!` when a
slow client is skipped (`main.rs:684`), which never reaches the browser.

Why it matters: the baseline document is emphatic that kernel drops are "silent data loss that looks like
network loss", and that any analysis of a lossy capture must account for it. We compute and display a
`packetLoss` percentage per flow from retransmits (`flow.rs:293`) — if the kernel is dropping frames, that
number is wrong and nothing tells the operator. Cheap to fix, disproportionate trust value.

Scope: poll `Capture::stats()` on the existing snapshot tick, add `received`/`dropped`/`ifDropped` to a wire
event, and surface a persistent "capture degraded — N frames dropped" indicator plus a caveat on the loss
column. Include the relay-side lag counter from `main.rs:684` in the same event.

### F4. A field model and a display-filter language — **XL**, missing entirely

Filtering today is: a substring match over five connection fields (`ConnectionsView.tsx:46-51`), a protocol
tab, and a layer number filter in the packet view. Packet fields exist only as a fixed five-layer struct
(`wire.rs` `HeaderBreakdownJson`) rendered as labelled text (`PacketStreamView.tsx:180-224`).

Why it matters: the baseline document's central design insight is that one field registration simultaneously
defines the decode, the tree label, the filter grammar and the exportable column — "one registration, four
capabilities". We have four hand-maintained surfaces instead, so every new protocol field costs four edits and
buys no query power. This is the keystone: custom columns, colouring rules, filter-scoped statistics, and
field export (F14) all fall out of it, and none are sensibly buildable without it.

Scope, phased: (a) turn `HeaderBreakdown` into a registry of typed, named, addressable fields with stable
abbreviations (`tcp.flags.syn`, `tls.handshake.sni`) documented in `docs/wire-protocol.md`; (b) a display-filter
parser supporting `==`/`!=`/`>`/`<`/`contains`/`matches`, existence tests, `and`/`or`/`not`, and `in {…}`;
(c) evaluate it client-side over the packet and connection buffers. Slices, arithmetic and functions are a
later phase, not a first release.

### F5. Bounded history with an honest horizon — **M**, improvement

Caps are hard-coded and invisible: 100 packets, 200 connections, `DEFAULT_MAX_FLOWS` = 10,000 in `flow.rs:95`, ring-buffer capacity
in `ring_buffer.rs`, stale-flow eviction in `flow.rs:328`. Nothing persists across a relay restart, and nothing
tells the operator what was discarded.

Why it matters: the caps were the right call for the known-gap issues (#27, #28) but the product now silently
lies about its own memory. The baseline document's whole performance section is about making the resource model
explicit so the operator can plan around it.

Scope: configurable buffer sizes, an on-screen "showing last N of M observed" line, and a retained rolling
window (backed by F1's file writer rather than RAM) so "what happened five minutes ago" has an answer.

## Tier 2 — analysis surfaces the baseline treats as table stakes

Ordered by value per unit of effort, assuming F4 has landed where noted.

### F6. Conversations and endpoints aggregation — **M**, improvement

`ConnectionsView` lists live flows, one row per 5-tuple, from `flow.rs`. There is no per-host or per-pair
rollup, no per-layer breakdown, and no sortable byte/packet/duration totals across the capture.

Scope: aggregate flows into endpoint (per host) and conversation (per pair) tables with bytes, packets,
duration and rate, sortable, scoped by the active filter once F4 lands. Natural home: a new tab beside
`ProtocolMatrixView`.

### F7. Measured protocol hierarchy — **M**, improvement

`ProtocolMatrixView` is an encapsulation *illustration* driven by `STATIC_LAYER_INFO`, with live per-layer
speeds merged in (`mergeLayerStats`). It is not the baseline's Protocol Hierarchy: the capture broken down by
protocol as a percentage of bytes and packets.

Scope: accumulate per-protocol byte/packet counters in `flow.rs`, emit them as a rollup event, and render a
real hierarchy with percentages. This is the single best answer to "what is this machine actually doing",
and it fits the existing tab perfectly.

### F8. Stream reassembly and Follow Stream — **L**, missing (except one special case)

No IP fragment reassembly, no TCP segment reassembly, no desegmentation. The only reassembly in the codebase
is `capture-agent/src/http2.rs`, and it only runs inside the decrypted-TLS path.

Why it matters: without reassembly, any PDU spanning segments decodes wrong or not at all, and "show me this
conversation as readable text" — the baseline's Follow Stream, the most-used feature for the security-analyst
and app-developer personas — is impossible. Note the honest constraint: with the default 65535 snap length we
*have* the bytes today; with F2's snap length set low, we will not, and the UI must say so.

Scope: a reassembly module keyed on the existing `FlowKey`, with per-flow byte caps and eviction reusing
`flow.rs`'s stale-flow logic; then a Follow Stream view with direction colouring, text/hex/raw modes.
Explicitly deferred: export-objects (pulling files out of HTTP/SMB), which is a separate, larger, and
much more sensitive feature.

### F9. Expert info — **M**, improvement

Anomalies are computed and then thrown away. `flow.rs` tracks retransmits (`flow.rs:262-267`) but only ever
publishes them as a `packetLoss` percentage; `parse_packet` returns `None` on malformed input
(`parse.rs:51`) and the frame vanishes with no record that it was malformed.

Why it matters: this is the cheapest credibility feature we have — the data is already in hand. The baseline
document is careful that Expert Info "flags anomalies; it does not conclude", which is the right posture for us
too: annotate, never verdict.

Scope: a severity-tagged findings stream (error/warning/note/chat) carrying retransmits, RSTs, zero-window,
dup-ACKs, malformed-frame counts and capture drops (F3); a findings panel, and per-row markers in the packet
and connection views, each clickable to the offending frame.

### F10. Time-series and TCP graphs — **L**, improvement

The UI has 20-sample sparklines per flow and per layer (`sparkline: Vec<u32>` in `wire.rs`) and a bar history
on the dashboard. There is no time axis, no zoom, no selectable Y-axis measure, and no sequence-number view.

Scope, in value order: (a) an IO graph — filter-defined series over time with selectable measure
(packets, bits, or SUM/AVG of a numeric field once F4 lands); (b) a TCP time-sequence plot per flow, which is
what actually distinguishes "the network is slow" from "the server is slow"; (c) RTT and throughput plots.
`docs/superpowers` process applies — this one deserves its own spec for the data-retention question alone
(graphs need history that F5 currently discards).

### F11. Request/response matching and service response time — **M**, missing entirely

No dissector links a response to its request. `l7.rs` reads HTTP request lines and DNS *query* names only —
DNS responses and HTTP status codes are not parsed at all, so `statusOrCode` in `Layer7Json` is structurally
present and never populated for live traffic.

Scope: match DNS query/response by transaction ID and HTTP request/response by flow ordering, compute service
time as a first-class field, and show per-protocol latency distributions. This is what makes the app useful for
the application-developer persona, and it pairs naturally with F7.

### F12. Flow / sequence diagram — **S–M**, missing entirely

No sequence-diagram view of exchanges between hosts. Given the terminal aesthetic, an ASCII/box-drawing ladder
diagram of a handshake is both cheap and genuinely on-brand — and it is the clearest teaching surface in the
product for the instructor/student persona the baseline document names.

### F13. Packet detail: field tree with byte cross-linking — **M**, improvement

`PacketStreamView` shows a fixed five-layer summary plus an undifferentiated hex blob
(`PacketStreamView.tsx:237`). Selecting a field does not highlight its bytes, nothing is collapsible beyond
what is hard-coded, and there is no copy-out.

Why it matters: the baseline document's three-pane cross-linked view is the core inspection idiom of the whole
category, and the hex pane is the protocol-developer persona's main tool. Blocked on F4's field model for the
byte-offset metadata.

Scope: per-field byte offsets and lengths in the wire event, a collapsible tree, bidirectional
field↔bytes highlighting, and copy-as-hex / copy-as-field-path.

### F14. Export — **S–M**, missing entirely

No CSV, no JSON, no hex-dump export, nothing. The baseline document calls PDML/JSON export "the integration
surface" — the thing that lets other pipelines consume a decode.

Scope: export the current (filtered) connection table as CSV, the packet buffer as JSON carrying the full
field tree, and a single packet as a hex dump. Sensitivity note: an export is a file of network contents
leaving the tool's own security boundary, so it belongs in `docs/security.md` and should honour the same
redaction rules as `capture-agent/src/redact.rs`.

## Tier 3 — breadth and platform

### F15. Dissector coverage — **L**, improvement

`l7.rs` recognises exactly three things: HTTP request lines, DNS query names, and TLS ClientHello (SNI + JA3).
Everything else lands as a port-name guess from `flow.rs:104`'s `well_known_protocol` table.

Highest-value additions for a home network, roughly in order: DNS responses (answers, rcode, TTL) — the
single most informative protocol on a home segment; QUIC/HTTP-3, now a large share of real traffic and
currently near-invisible; DHCP, mDNS/SSDP/Bonjour, and ARP, which are what make a *home* network legible;
ICMP type/code detail (currently `TransportProtocol::Icmp` carries no payload at all, `parse.rs:106`);
HTTP response status; NTP; SSH version exchange.

### F16. Link-layer and tunnel coverage — **M**, improvement plus one latent bug

Three specific gaps:

- **Non-Ethernet link types are dropped entirely.** `parse_packet` returns `None` for anything that is not
  `LinkSlice::Ethernet2` (`parse.rs:54-59`). Loopback/null and raw-IP link types therefore produce zero
  packets — worth confirming against the loopback capture path the baseline document lists as a first-class source.
- **VLAN tags are advertised but never populated.** `Layer2Json.vlan_tag` is hard-coded `None`
  (`wire.rs:219`), `lib/types.ts:89` carries `vlanTag?`, and `LayerDetailView.tsx:50` tells the user we handle
  "802.1Q VLAN Tag ID". Either parse it or stop advertising it; today the UI overstates the product.
- **No tunnel decapsulation.** GRE, VXLAN, WireGuard and IPsec payloads are opaque. Lower priority for a home
  network, but VPN traffic is common enough that "this is a tunnel, and here is the outer flow" beats "Other".

### F17. Heuristic dissection and Decode As — **M**, missing entirely

Protocol identification is port-based (`flow.rs:104`) with no payload-shape heuristics and no manual override.
Anything on a non-standard port is mislabelled with no way for the operator to correct it. A `decode-as`
command-bar verb pinning a flow to a chosen L7 sniffer is a small, high-satisfaction addition once F15 gives
us more than three sniffers to choose between.

### F18. Name resolution — **S**, improvement

Reverse DNS exists but only inside the opt-in enrichment subsystem (`lib/enrichment/reverse-dns.ts`), and
there is no MAC OUI vendor lookup — so every device on the LAN shows as a raw MAC. An offline OUI table is a
few hundred KB and turns `a4:83:e7:…` into "Apple, Inc.", which is the difference between a list of hex and a
map of the house. Keep it offline-only: no new network dependency, no change to the enrichment opt-in posture.

### F19. Decryption breadth — **M–L**, improvement

Today: TLS 1.3 only, for a single PID launched via `bin/osi-inspect.js`. Gaps worth taking, in order:
TLS 1.2 (still present in the wild, and the key-log mechanism is identical); QUIC/HTTP-3 keys, which will
matter more each quarter; importing an existing `SSLKEYLOGFILE` rather than only launching through our
wrapper; and pcapng Decryption Secrets Blocks once F1 lands. Everything here inherits the existing opt-in,
in-memory, never-on-disk model from `docs/superpowers/specs/2026-08-29-tls-interception-design.md` — no
broadening of the trust model.

Explicitly out of reach, per the baseline: WPA3/SAE. Explicitly declined: WPA/WPA2 passphrase decryption and
IPsec SA configuration — both are LAN-wide surveillance capabilities, which is a different product.

### F20. Interface selection and multi-interface capture — **S**, improvement

`CAPTURE_INTERFACE` (`main.rs:243`) is env-only and requires an agent restart; there is no interface list in
the UI and no multi-interface merge. Exposing the device list over the control channel and letting the
operator switch interfaces live is small and removes a genuine papercut.

### F21. Headless query CLI — **M**, missing entirely

`bin/osi-inspect.js` is the only CLI and it only opts a process into decryption. There is no equivalent of the
baseline's extraction pattern — filter a capture, print selected fields, pipe to something else — which the
document identifies as "the basis for most scripted use".

Scope: a thin CLI over the same relay/agent APIs: `osi-query --filter '<display filter>' --fields tcp.flags,ip.src
--json`. Cheap once F4 exists, and it makes the capture pipeline testable in CI against fixture captures from F1.

### F22. Extensibility and profiles — **M**, missing entirely

Configuration today is ten themes (`THEMES` in `lib/osi-engine.ts`). None of the baseline's configuration
surfaces exist: no profiles (bundles of columns, colouring rules, saved filters), no per-protocol preferences
(reassembly on/off, port ranges, checksum validation), no filter buttons or macros, no custom columns, no
colouring rules.

Recommendation: do **not** build a plugin or Lua host. That is the right answer for a 3,000-protocol project
with an ecosystem, and the wrong answer here — it is a large sandboxing and security problem for a tool with
one operator. Build the declarative subset instead: saved filters, colouring rules, custom columns, protocol
toggles, persisted as a profile. All of it is downstream of F4.

### F23. Live system stats — **S**, improvement

`SystemStats` (`lib/types.ts:138`) is seeded at zero/placeholder values and `DashboardView` renders them as if
live — interface name, speed, duplex, CPU, memory, uptime, aggregate throughput. `CLAUDE.md` already flags this;
the dashboard is the first screen anyone sees, so placeholder values there cost more credibility than their
size suggests. Needs one new wire event and a small host-stats module in the agent.

### F24. Platform reach — **L**, improvement

The agent is macOS-in-practice: `access_bpf` setup in `capture-agent/README.md`, the ping-socket traceroute
in `traceroute.rs` is macOS-specific, `keylog.rs`/`ring_buffer.rs` use `mlock`, and `macos-app/` is the native
viewer. Linux support is mostly a privilege-model and traceroute question (libpcap plus `CAP_NET_RAW`). Worth
a spike before committing — it is a real epic, not a flag.

## Security and process gaps

These track the baseline's section 14 and are, in my read, the most under-weighted items in this analysis
relative to their risk.

### F25. Parser privilege separation — **L**, architectural improvement

The baseline's central security decision is that the privileged capture binary (`dumpcap`) does no dissection,
and the 3,000 parsers run unprivileged. We have the opposite shape: `capture-agent` holds the BPF handle *and*
runs `parse_packet`, `l7.rs`, `http2.rs` and `tls_decrypt.rs` on attacker-controlled bytes in the same process.

Mitigating facts, in fairness: our parser surface is a few hundred lines rather than millions, `parse_packet`
is fuzzed, and the agent is not root once `access_bpf` is configured. But the trend line is wrong — F15's
dissector breadth adds hostile-input parsers to the privileged process, so the split gets more valuable exactly
as we grow. Worth a design spike (capture child process + unprivileged parser over a pipe) before F15, not after.

### F26. Fuzzing in CI — **S**, improvement

`.github/workflows/ci.yml` runs `cargo build`, `cargo test`, `cargo clippy -D warnings`, `tsc --noEmit`,
`npm run lint` and `vitest`. It does **not** run either fuzz target, even though `CONTRIBUTING.md` asks
contributors to run them by hand when touching `parse.rs` or `http2.rs`. The baseline lists "fuzzing in CI" as
a primary mitigation for the dissector-vulnerability class. A 30-second `cargo fuzz` run per target on PRs
touching those files is nearly free.

### F27. Capture-handling guidance — **S**, improvement

`docs/security.md` covers the transport and opt-in posture well. It does not yet say what the baseline says
plainly: a capture is a high-sensitivity artefact, captures of a shared segment contain other people's traffic,
and packet capture on networks you do not administer is unlawful in many jurisdictions. This becomes a
hard prerequisite the moment F1 (files) and F14 (export) let captures leave the machine.

## Deliberate non-goals

Adopting the baseline's non-goals, plus ours. Recording these matters as much as the gap list: the document's
closing warning is that teams get into trouble trying to make an inspection tool the whole visibility stack.

| Non-goal | Rationale |
| --- | --- |
| Real-time alerting, IDS/IPS, threat verdicts | Annotate, never conclude. F9's Expert Info is the boundary. |
| Long-term retention at scale | No index, no storage tier. F5's rolling window is the boundary. |
| Traffic generation or replay | Different tool, different risk profile. |
| Inline deployment | Passive observer only; there is no forwarding path and there should not be. |
| Protocol parity with Wireshark | Depth where a home network benefits (F15), not 3,000 dissectors. |
| Lua/plugin host | Sandboxing cost outweighs the benefit for a single-operator tool (see F22). |
| MITM proxy, CA install, traffic redirection | Settled in epic #25 and still settled. Key-log opt-in only. |
| LAN-wide WPA/WPA2 or IPsec decryption | Surveillance of other people's traffic, not inspection of your own. |
| Multi-user collaboration | Single-operator by design; F1's shareable files are the collaboration story. |

## Suggested sequencing

Six epics, in dependency order. This is a recommendation, not a decision.

| # | Epic | Contents | Size | Why here |
| --- | --- | --- | --- | --- |
| A | Capture fidelity and control | F2, F3, F20, F23 | M | Small, independent, fixes the two places the UI currently overstates what it knows. Best first epic. |
| B | Capture files and offline analysis | F1, F5, F14, F27 | XL | Unblocks Tier 2 and makes everything testable against fixtures. |
| C | Field model and display filters | F4, F13, F9 | XL | The keystone. Every later surface gets cheaper; F22 is impossible without it. |
| D | Analysis surfaces | F7, F6, F11, F8, F10, F12 | XL | The visible payoff of B and C. Ship F7 first — best value per week in the whole list. |
| E | Dissector breadth | F15, F16, F17, F18, F19 | L | Gated on F25's spike: do not grow the hostile-parser surface inside the privileged process first. |
| F | Headless and configuration | F21, F22, F24 | L | Last; both depend on C. |
| — | Security hardening (continuous) | F25 spike, F26 | S–L | F26 lands this week; F25's spike belongs before epic E. |

If only one thing gets picked up: **epic A**, then **F7** out of order. A is days of work and removes two
honesty problems (invisible drops, placeholder dashboard stats); F7 is the feature that makes the product
answer the question its users actually have.

## Open questions for the product owner

1. **Is offline analysis in scope at all?** Epic B is the largest single item here and the whole Tier 2 case
   leans on it. If this stays a live-only glanceable monitor, B drops out, D shrinks, and the roadmap is
   A → C → D-lite. This is the one answer that reshapes everything else.
2. **Who is the primary persona?** The baseline names five. Our feature set currently straddles the
   instructor/student persona (OSI layer framing, encapsulation view, themes) and the network-engineer persona
   (live flows, RTT, loss). D's ordering changes materially depending on which one wins.
3. **What is the retention appetite?** F5 and F10 both need history; history means either RAM (bounded, lossy)
   or disk (F1, and a data-sensitivity conversation).
4. **Does Linux support matter this year?** F24 is a real epic and is cheaper to design for now than to retrofit
   after E adds more platform-specific parsing.
