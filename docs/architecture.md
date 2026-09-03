# Architecture

## Overview

The app has three pieces, split by trust level: a privileged capture agent, an unprivileged relay, and a browser UI. Nothing in the web tier ever needs elevated permissions — only the agent does, and it's a small, narrowly-scoped process.

```
┌───────────────────────┐             ┌────────────────────────┐             ┌─────────────────┐
│  capture-agent (Rust)   │             │  Next.js app             │             │  Browser          │
│  ────────────────────   │             │  ──────────────────      │             │  app/page.tsx      │
│  opens en0 via pcap,     │   TCP       │  lib/agent-client.ts      │   SSE       │  EventSource(...)   │
│  parses every packet     │◄──────────►│  (reconnecting client)    │────────────►│  React state →       │
│  itself, tracks flow     │  :9990      │                            │  GET /api/  │  components/         │
│  state, streams NDJSON   │  loopback   │  app/api/stream/route.ts  │  stream     │                      │
│  back only               │  only       │  app/api/control/route.ts │◄────────────│  fetch() POST for    │
│                          │             │  loopback only            │  POST /api/ │  pause/resume, NOT   │
└───────────────────────┘             │                            │  control    │  part of the SSE conn │
                                        └────────────────────────┘             └─────────────────┘
```

The SSE connection is one-way, server → browser only. `pause`/`resume` from the browser go over a separate plain `fetch('/api/control', ...)` POST request, not back over the SSE stream.

Both the agent and the Next.js server bind to `127.0.0.1` only, and neither authenticates anything by itself. LAN access, when you opt into it, is a fourth piece in front of them: a Caddy reverse proxy (`deploy/`) that terminates TLS and requires a client certificate signed by a local mkcert CA before proxying to `127.0.0.1:3000`. It ships bound to loopback (`bind 127.0.0.1`, site address `localhost:8443`); exposing it to the LAN is a manual, documented switch (`deploy/README.md` step 5). `macos-app/` is a native macOS viewer for that endpoint — a `WKWebView` locked to one origin with a Secure-Enclave-backed client certificate. See [security.md](security.md) for the posture and its residual risks, and `deploy/README.md` for setup.

## The three pieces

### 1. `capture-agent/` — the privileged process

A standalone Rust binary, run separately from the web app. It:

- Detects the interface actually carrying your default route (`route -n get default`, cross-referenced against `pcap::Device::list()` — not just `pcap::Device::lookup()`, which on macOS can pick a near-idle virtual interface like `ap1` instead of your real Wi-Fi/Ethernet interface)
- Opens that interface via `pcap` in promiscuous + immediate mode
- Parses every packet itself — Ethernet/IP/TCP/UDP headers (`src/parse.rs`), plaintext HTTP/DNS/TLS-SNI (`src/l7.rs`) — never trusting a black-box dissector, and never panicking on malformed bytes (fuzzed via `cargo-fuzz`, since this code runs on untrusted, attacker-reachable network data)
- Aggregates packets into a flow table (`src/flow.rs`): byte counters, TCP-state-derived status, RTT (SYN→SYN-ACK timing), and a retransmission-based loss estimate
- Attributes each flow to a local process name/PID via `lsof` (`src/process_lookup.rs`)
- Streams the result as newline-delimited JSON (`src/wire.rs`) over a TCP socket bound to `127.0.0.1:9990`

**Privilege model:** the agent runs as your normal user, in the macOS `access_bpf` group (one-time setup, see `capture-agent/README.md`) — never `sudo`, never root, at runtime.

Three later sub-projects extended the agent in place, each opt-in and each with its own design spec under `docs/superpowers/specs/`:

- **TLS visibility** (epic #25): `src/ja3.rs` fingerprints each observed TLS ClientHello (informational only — never treat it as an auth signal, it's trivially spoofable). Separately, `src/keylog.rs`'s `KeyLogWatcher` tails an ephemeral `SSLKEYLOGFILE` for one specific opted-in PID, `src/tls_decrypt.rs` decrypts that connection's TLS 1.3 records, `src/http2.rs` reassembles HTTP/2 streams and decodes HPACK, `src/redact.rs` strips sensitive headers, and `src/ring_buffer.rs` holds the resulting decrypted content in a capped, `mlock`'d, zeroed-on-evict buffer — never written to disk. Nothing decrypts unless a process was explicitly launched through `bin/osi-inspect.js` (a Node CLI, not part of the agent itself, that sets `SSLKEYLOGFILE` and registers the child PID as decrypt-eligible over the existing control channel). This is a per-process opt-in, not a blanket MITM proxy — no CA install, no traffic redirection.
- **Network path visualization** (epic #24): `src/traceroute.rs` runs a bounded, on-demand ICMP traceroute using an unprivileged macOS ping-socket (`SOCK_DGRAM`/`IPPROTO_ICMP` — no raw-socket privilege needed, confirmed working; see `docs/superpowers/specs/2026-09-01-path-visualization-privilege-spike-result.md`), capped at 30 hops with per-hop retry/timeout and a 45s total-trace ceiling enforced agent-side.

See [wire-protocol.md](wire-protocol.md) for the `decrypted_payload` and `traceroute_hop` event shapes these produce.

### 2. The Next.js relay — unprivileged

- `lib/agent-client.ts` — a Node `net.Socket` client that connects to the agent, parses its NDJSON stream (handling TCP chunk boundaries splitting a JSON object across reads), and re-emits `'event'`/`'status'` on an `EventEmitter`. Reconnects automatically if the agent isn't running or drops, with a guard against the classic "both `error` and `close` fire, doubling reconnect attempts" bug.
- `app/api/stream/route.ts` — a Server-Sent Events route. The browser opens one `EventSource` connection here; every agent event gets forwarded as an SSE `data:` line.
- `app/api/control/route.ts` — a POST endpoint the browser uses to send `pause`/`resume` back to the agent.

Both routes share one `AgentClient` singleton (`global.__agentClient`) — there's one TCP connection to the agent regardless of how many browser tabs are watching.

Sibling routes handle the three sub-projects: `app/api/enrichment/control/route.ts` + `app/api/enrichment/lookup/route.ts` (ownership enrichment, below), `app/api/traceroute/start/route.ts` + `app/api/geoip/control/route.ts` (path visualization, above).

### 3. `app/page.tsx` and `components/` — the browser UI

`app/page.tsx` is the entire application (one client component). It opens `new EventSource('/api/stream')` in a `useEffect` and folds incoming events into React state:

| Event type | Effect |
|---|---|
| `connection_status` | drives the "agent not connected" banner |
| `connection_update` | upserts into the `connections` list (now also carries `ja3Fingerprint`/`ja3Label`, see below) |
| `packet` | prepends into a capped `packets` buffer (keeps the newest ~100: `[packet, ...prev.slice(0, 100)]`) |
| `layer_update` | merges into `liveLayers`; `layers` is *derived* from it via `useMemo` |
| `decrypted_payload` | mapped via `lib/decrypted-mapping.ts`, gated by `lib/decrypted-payload-gate.ts` to loopback/mTLS-authenticated transport, rendered in `PacketStreamView` |
| `traceroute_hop` / `geo_hop_update` | intended to fold into `lib/traceroute-state.ts` and render as a per-hop table in `ConnectionsView` — **currently broken**: `app/page.tsx`'s handler passes the raw `traceroute_hop` event straight to `mapTracerouteHopEvent` instead of unwrapping its nested `hop` field, so the mapper throws on every event and it's silently dropped; the hop table never populates ([issue #46](https://github.com/usjbro/network_monitor/issues/46)) |

There is no simulation code anywhere in this path — but that's not quite the same as "every number displayed originates from the capture agent": the header bar's CPU%, memory%, hostname, and uptime are still static invented values from the original scaffold, not wired to anything (see "Known, deliberate gaps" below). `components/` holds one file per view (`DashboardView`, `LayerDetailView`, `ConnectionsView`, `PacketStreamView`, `ProtocolMatrixView`), plus chrome (`HeaderBar`, `CommandLineBar`, `InstallModal`). All are presentational — they receive `theme` and view-specific data as props; there's no separate client-side data-fetching layer.

## Supporting files

- `lib/agent-mapping.ts` — pure functions (`mapConnectionEvent`, `mapPacketEvent`, `mergeLayerStats`) translating the agent's wire JSON into the app's domain types. This is the one place that has to agree field-for-field with `capture-agent/src/wire.rs` — see [wire-protocol.md](wire-protocol.md).
- `lib/types.ts` — all domain types (`OSILayerInfo`, `NetworkConnection`, `PacketFrame`, `SystemStats`, `ThemeConfig`).
- `lib/osi-engine.ts` — `THEMES` (10 color schemes), `STATIC_LAYER_INFO` (per-layer *descriptive* metadata — name, PDU, protocol list, badge colors; not live values), and formatting helpers (`formatSpeed`, `formatBytes`).
- `lib/enrichment.ts` + `lib/enrichment/` (`bootstrap.ts`, `cache.ts`, `query-log.ts`, `rdap-client.ts`, `referral-allowlist.ts`, `request-queue.ts`, `reverse-dns.ts`, `scope-filter.ts`, `whois-client.ts`, `types.ts`) + `lib/enrichment-mapping.ts` — **ownership enrichment** (epic #23): opt-in-only (`enrich on` in the command bar, never persisted across a relay restart) WHOIS/RDAP lookups attributing a remote IP/domain to an owning organization. Cache-first, rate-limited, SSRF-hardened against a reviewed RDAP/registrar host allowlist. See [enrichment-protocol.md](enrichment-protocol.md).
- `lib/decrypted-mapping.ts` + `lib/decrypted-payload-gate.ts` — map and transport-gate the TLS-visibility sub-project's `decrypted_payload` event (see above).
- `lib/geoip.ts` + `lib/geoip-mapping.ts` + `lib/traceroute-state.ts` — client-side state for the path-visualization sub-project (see above). See [geoip-protocol.md](geoip-protocol.md).
- `bin/osi-inspect.js` — the standalone CLI (published via `package.json`'s `bin` field) that is the *only* way TLS decryption (above) ever turns on for a process.

## Why this shape

- **Privilege isolation**: only the agent touches raw sockets; a bug in the (much larger, much more frequently changed) web tier can't escalate to packet-capture privilege.
- **One clock, one source of truth**: the agent computes all derived metrics (speed, RTT, loss, per-layer aggregates) once, server-side; the relay and UI just forward and render.
- **No polling**: SSE + a persistent agent connection means the UI updates as events happen, not on a fixed interval.

## Known, deliberate gaps

These aren't oversights — they're scoped out of the current increment and tracked as GitHub issues in [usjbro/network_monitor](https://github.com/usjbro/network_monitor):

- **`SystemStats`** (hostname, CPU/mem, aggregate interface throughput) has no wire event yet. Only `rxTotalMbps`/`txTotalMbps` and the RX/TX history arrays were zeroed out (and the dashboard's "LIVE" badge removed for that section) as a deliberate honesty fix — the rest of `SystemStats` (`hostname`, `cpuUsagePct`, `memUsagePct`, `uptimeSeconds`, MAC/IP, `totalPacketsCaptured`, etc., seeded in `app/page.tsx`) is still the original scaffold's hardcoded fake values, not yet touched. Don't trust anything in the header bar's stats beyond throughput as real.
- **`headerBreakdown`** (per-layer packet detail: MACs, TLS SNI, HTTP method/path, DNS query name) is parsed by the agent but never reaches the wire — issue #29.
- **The packet-event stream is uncapped** — no sampling/rate limit yet, issue #27.
- **Flows never expire** — the flow table grows unbounded for the life of the process, issue #28.
- **The app has no application-layer auth of its own** — epic #22 landed mTLS at the Caddy layer (`deploy/`) plus a native viewer (`macos-app/`), so LAN access is gated on a client certificate, but the relay still can't distinguish one authenticated client from another and every one of them has full access. That layer also carries known residual risks (an unencrypted local CA key, long-lived certs with no revocation, and an App Sandbox limitation in the native app's cert provisioning) — see [security.md](security.md).

See [troubleshooting.md](troubleshooting.md) for what these look like in practice, and [security.md](security.md) for the full security posture.
