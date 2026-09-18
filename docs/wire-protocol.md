# Wire Protocol Reference

The contract between `capture-agent` (Rust, producer) and the Next.js relay (TypeScript, consumer). There is no compiler check across this boundary — if you change one side, you must change the other. Source of truth: `capture-agent/src/wire.rs` (Rust) and `lib/agent-mapping.ts` / `lib/types.ts` (TypeScript).

## Transport

- Newline-delimited JSON (NDJSON) over a plain TCP socket, `127.0.0.1:9990`.
- **Agent → relay**: one JSON object per line, each tagged with a `"type"` field.
- **Relay → agent**: control messages, same NDJSON framing, on the same connection.
- All field names are `camelCase` on the wire (Rust uses `#[serde(rename_all = "camelCase")]`), matching the TypeScript field names exactly — no translation layer.

## Agent → relay events

Tagged by `"type"` (snake_case: `#[serde(tag = "type", rename_all = "snake_case")]`).

### `connection_update`

Sent once per active flow, every ~1 second (the periodic emitter's tick).

```json
{
  "type": "connection_update",
  "connection": {
    "id": "Tcp-192.168.1.10:51000-93.184.216.34:443",
    "protocol": "HTTPS/TLS",
    "appLayerProtocol": "HTTPS/TLS",
    "transportProtocol": "TCP",
    "osiStack": "L4:Tcp -> L3:IP",
    "localAddr": "192.168.1.10",
    "localPort": 51000,
    "remoteAddr": "93.184.216.34",
    "remotePort": 443,
    "processName": "Safari",
    "pid": 1234,
    "rxSpeed": 1024.0,
    "txSpeed": 512.0,
    "rxBytesTotal": 4096,
    "txBytesTotal": 2048,
    "latencyMs": 20.0,
    "packetLoss": 0.0,
    "status": "ESTABLISHED",
    "encryption": "TLS",
    "sparkline": [],
    "ja3Fingerprint": "e7d705a3286e19ea42f587b344ee6865",
    "ja3Label": "matches Chrome 12x"
  }
}
```

Maps to `NetworkConnection` (`lib/types.ts`) via `mapConnectionEvent` (`lib/agent-mapping.ts`), which throws if any required field is missing — a malformed event is a loud failure, not a silent `undefined`.

Field notes:
- `status` — one of `ESTABLISHED` / `SYN_SENT` / `TIME_WAIT` / `CLOSE_WAIT`, derived from observed TCP flags. Non-TCP flows (UDP, ICMP) report `ESTABLISHED` — there's no TCP-style closing state for a connectionless protocol.
- `packetLoss` — a retransmission-based *approximation*, not a precise measurement. See [troubleshooting.md](troubleshooting.md#what-does-retransmit-anomaly-mean).
- `latencyMs` — SYN→SYN-ACK round-trip time, `0` if the handshake wasn't observed (e.g. the connection predates the agent starting).
- `remoteHostname` (optional in the TS type) is never populated by the current agent — reverse-DNS/WHOIS enrichment is a separate, not-yet-built sub-project.
- `ja3Fingerprint`/`ja3Label` (both optional) — present once the agent has observed this flow's TLS ClientHello; absent for flows without an observed handshake (e.g. non-TLS, or the connection predates the agent starting). `ja3Label` is best-effort and informational only — never treat it as an authenticated client identity, it is trivially spoofable by any TLS client (see `docs/superpowers/specs/2026-08-29-tls-interception-design.md`, Security model).

### `packet`

Sent once per captured packet, immediately (not batched).

```json
{
  "type": "packet",
  "packet": {
    "id": "pkt-1787799628962-37",
    "timestamp": "1787799628962",
    "relativeTimeMs": 2243,
    "layer": 4,
    "protocol": "TCP",
    "src": "192.168.1.10:51000",
    "dst": "93.184.216.34:443",
    "length": 60,
    "summary": "Tcp 192.168.1.10 -> 93.184.216.34",
    "hexDump": "00 01 02 ...",
    "headerBreakdown": {
      "layer4": { "transport": "TCP", "srcPort": 51000, "dstPort": 443, "flags": "SYN", "windowSize": 65535, "seqAck": "seq=1000 ack=0" },
      "layer3": { "ipVersion": "IPv4", "srcIp": "192.168.1.10", "dstIp": "93.184.216.34", "ttl": 64, "protocolNum": 6, "checksum": "0xbeef" },
      "layer2": { "srcMac": "00:01:02:03:04:05", "dstMac": "06:07:08:09:0a:0b", "ethType": "IPv4" }
    }
  }
}
```

Maps to `PacketFrame` via `mapPacketEvent`, which throws if `headerBreakdown` is missing entirely rather than defaulting it to `{}` — see [issue #29](https://github.com/usjbro/network_monitor/issues/29) (closed): `PacketJson` (`capture-agent/src/wire.rs`) does carry a `header_breakdown` field, built by `wire::build_header_breakdown` from `ParsedPacket` + `L7Info` at the point each `Packet` event is constructed in `main.rs`'s capture loop. `layer2`/`layer3`/`layer4` are always present (every captured packet has an Ethernet/IP/transport header by construction); `layer7` is present only when the payload matched a recognized application protocol; `layer1`/`layer5`/`layer6` are never present — no PHY, session, or TLS-version/cipher data is extracted anywhere in this agent, and fabricating it would contradict the rest of this document's "report zero/absent rather than invent a number" convention. `layer2.vlanTag` (optional) is present only for an 802.1Q-tagged frame — see `parse.rs`'s `vlan_tag` field and [issue #62](https://github.com/usjbro/network_monitor/issues/62); a double-tagged (QinQ) frame reports only its outermost tag. `timestamp` is epoch milliseconds as a string, not ISO-8601.

**No rate limiting yet** — every captured packet gets its own event ([issue #27](https://github.com/usjbro/network_monitor/issues/27)). On a busy interface this can mean thousands of these per second.

### `layer_update`

Sent once per tick (~1 second), one entry per independently-measurable layer.

```json
{
  "type": "layer_update",
  "layers": [
    { "layer": 3, "rxSpeed": 585.0, "txSpeed": 462.0, "rxPacketsPerSec": 0, "txPacketsPerSec": 0, "totalBytes": 2061, "errorRate": 0.0, "activeSockets": 5, "sparkline": [] },
    { "layer": 4, "rxSpeed": 585.0, "txSpeed": 462.0, "rxPacketsPerSec": 0, "txPacketsPerSec": 0, "totalBytes": 2061, "errorRate": 0.0, "activeSockets": 5, "sparkline": [] },
    { "layer": 7, "rxSpeed": 585.0, "txSpeed": 462.0, "rxPacketsPerSec": 0, "txPacketsPerSec": 0, "totalBytes": 1647, "errorRate": 0.0, "activeSockets": 5, "sparkline": [] }
  ]
}
```

Only layers 3, 4, and 7 are ever present — the agent has no independent way to measure 1, 2, 5, or 6 separately from the IP/transport byte counts it already has. `mergeLayerStats` (`lib/agent-mapping.ts`) fills the missing layers in with zeroed values merged onto `STATIC_LAYER_INFO`'s descriptive metadata, and sorts the result descending (7→1) to match the UI's expected display order.

`rxPacketsPerSec`/`txPacketsPerSec` are always `0` currently — not implemented.

### `capture_stats`

Sent once per tick (~1 second), immediately after that tick's `layer_update`. Reports capture health — issue #61.

```json
{
  "type": "capture_stats",
  "stats": {
    "received": 40213,
    "dropped": 0,
    "ifDropped": 0,
    "relayLaggedEvents": 0
  }
}
```

Note the nesting: fields sit under a `stats` key, not flat on the event — same shape as `traceroute_hop`'s `hop` key (`capture-agent/src/wire.rs`'s `CaptureStats { stats: CaptureStatsJson }`). `mapCaptureStatsEvent` (`lib/agent-mapping.ts`) owns this unwrap; pass it the full event, not `event.stats`.

Field notes:
- `received`, `dropped`, `if_dropped` come straight from `pcap::Capture::stats()` (`ps_recv`/`ps_drop`/`ps_ifdrop`) — cumulative since the capture handle opened, not per-tick deltas. `dropped` is the kernel/driver's capture buffer filling up before the agent could read from it; `if_dropped` is the network interface driver dropping frames upstream of that buffer (`0` on platforms that don't report it separately). Both are `0` until the capture thread's first successful poll (roughly one second after the agent starts).
- `relayLaggedEvents` is unrelated to the three fields above: it's this relay process's own outbound backlog — a cumulative count (since agent start, not per-tick) of discrete `packet`/`decrypted_payload` events silently dropped for an SSE client that fell behind the broadcast channel (see `RecvError::Lagged` in `main.rs`). A capture can have `dropped: 0` and still have a nonzero `relayLaggedEvents` if the browser tab itself is slow to consume events.
- All four counters are monotonically non-decreasing for the life of the agent process (never reset mid-run, even across a `pause`/`resume`).

Any connection's `packetLoss` (in `connection_update`) is derived purely from observed TCP retransmits — it has no way to know about packets the kernel or the relay itself lost before ever reaching that computation. A nonzero `dropped`/`ifDropped`/`relayLaggedEvents` here means `packetLoss` figures elsewhere in this same tick may under-report actual loss; the UI treats these two as independent signals (see `app/page.tsx`'s capture-degraded banner and `ConnectionsView`'s loss-column caveat) rather than trying to merge them into one number.

### `system_stats`

Sent once per tick (~1 second), immediately after that tick's `capture_stats`. Host/interface identity and aggregate throughput — issue #64. Replaces the placeholder `SystemStats` values the UI used to seed itself with client-side; every field here is a real measurement.

```json
{
  "type": "system_stats",
  "stats": {
    "hostname": "osi-gw-01",
    "interfaceName": "en0",
    "ipAddress": "192.168.1.104",
    "rxTotalMbps": 4.68,
    "txTotalMbps": 3.7,
    "rxPpsTotal": 480.0,
    "txPpsTotal": 220.0,
    "totalPacketsCaptured": 184200
  }
}
```

Note the nesting: fields sit under a `stats` key, same shape as `capture_stats`'s `stats` and `traceroute_hop`'s `hop` — not flat on the event.

Field notes:
- `hostname` — from `gethostname(2)`, read once at agent startup (not re-read per tick). Empty string if the syscall failed, never fabricated.
- `interfaceName`, `ipAddress` — the interface `detect_interface()` resolved at startup and its first assigned address; both fixed for the life of the process (restart the agent, e.g. after `CAPTURE_INTERFACE` changes, to pick up a different value). `ipAddress` is empty if the interface has no assigned address.
- `rxTotalMbps`/`txTotalMbps`/`rxPpsTotal`/`txPpsTotal` — aggregate interface throughput, computed from a **cumulative byte/packet counter delta between ticks**, divided by the tick's *actual* elapsed wall time (not assumed to be exactly 1s — a delayed tick still reports an honest rate). Deliberately not a sum over currently-live flows the way `layer_update`'s L3/L4 aggregates are: summing live flows moves when a flow evicts from the table even though nothing about the wire traffic changed, which would show as a throughput drop that never happened.
- `totalPacketsCaptured` — the same cumulative `pcap::Stat::received` count as `capture_stats.received` (see above), repeated here so this event is self-contained; not a separate counter.

What this event does **not** carry, and why: the placeholder `SystemStats` shape this replaces also had `interfaceSpeedMbps`, `duplexMode`, `macAddress`, `cpuUsagePct`, `memUsagePct`, and `uptimeSeconds`. None of these are measurable from this agent today — interface speed/duplex and the NIC's own hardware MAC would need additional, fiddlier platform-specific lookups; host CPU/memory/uptime are host-monitoring, not network-monitoring, and out of this agent's scope. Per issue #64's resolution, these are omitted entirely rather than wired up or faked — the UI renders an explicit "not wired" state for anything this event doesn't carry, never a zero formatted as a measurement.

### `agent_status`

Defined in the wire protocol (`interface: String, capturing: bool`) but **never actually sent** by the current agent — the relay synthesizes its own `connection_status` event from the TCP connection state instead (see below). This is dead wire protocol surface; a future task should either wire it up (so the UI can display which interface is active) or remove it.

### `decrypted_payload`

Tier B only (opt-in, per-process decrypted TLS content via `osi-inspect` / `SSLKEYLOGFILE` — see `docs/superpowers/specs/2026-08-29-tls-interception-design.md`, Components §2–§5). Sent per HTTP/2 frame successfully decrypted and reassembled for a decrypt-eligible connection; rate-capped at the same 100/sec discrete-event budget as `packet`.

```json
{
  "type": "decrypted_payload",
  "payload": {
    "connectionId": "Tcp-192.168.1.10:51000-93.184.216.34:443",
    "streamId": 3,
    "redacted": false,
    "dataBase64": "OmF1dGhvcml0eTogZXhhbXBsZS5jb20="
  }
}
```

Field notes:
- `connectionId` — matches `connection_update`'s `id`, so the browser can associate decrypted content with the connection/packet stream it belongs to.
- `streamId` (optional) — the HTTP/2 stream ID this frame belongs to; absent for content the agent couldn't attribute to a specific stream.
- `redacted` — `true` if this event's `dataBase64` decodes to a `[REDACTED]` placeholder (sensitive header name or bearer-token-shaped value; see `capture-agent/src/redact.rs`). The redaction pass runs on parsed HTTP/2 headers only — body content is never redacted (named limitation, not a bug).
- `dataBase64` — base64-encoded UTF-8 text: either a decrypted HTTP/2 header block (`Name: value` pairs joined by `\n`, after redaction) or a decrypted HTTP/2 DATA frame body.

**Refused outright over any non-loopback listener; once served through the LAN-access Caddy mTLS proxy (`deploy/`), requires the `X-Mtls-Verified: true` upstream header** — see `lib/decrypted-payload-gate.ts`'s `isDecryptedPayloadAllowed` (used by `app/api/stream/route.ts`; kept in its own module rather than exported from the route file because Next.js's typed-routes build step rejects non-standard exports from `route.ts`). A request with no such header at all (direct loopback, no Caddy in front) is allowed; a request proxied through Caddy without a verified client cert is refused. This is the same event type in both cases — the gating happens relay-side, per-connection, not by the agent withholding the event.

Only ever produced for a captured TCP payload that itself begins with a TLS `application_data` record (`0x17`) — a record split across multiple TCP segments, or any record after the first one sent under a given logged secret (this module has no per-record sequence-number tracking), is silently not decrypted rather than partially/incorrectly shown. See `capture-agent/src/main.rs`'s `try_decrypt_and_emit` doc comment for the full list of named limitations.

### `traceroute_hop`

Sent once per resolved hop, progressively, as a `trace_route` control message's trace runs — never automatically, and never more than once per hop (see the `trace_route` control message below for what triggers a trace at all).

```json
{
  "type": "traceroute_hop",
  "hop": {
    "targetIp": "93.184.216.34",
    "hopNumber": 4,
    "hopIp": "12.122.1.1",
    "rttMs": 18.4
  }
}
```

Note the nesting: hop fields sit under a `hop` key, not flat on the event — this matches `capture-agent/src/wire.rs`'s `TracerouteHop { hop: Box<TracerouteHopJson> }` (an internally-tagged enum variant holding a single named struct field, which serde nests rather than flattens). This doc previously showed a flat shape here, which two independent call sites each copied — see [issue #46](https://github.com/usjbro/network_monitor/issues/46).

Maps to `TracerouteHop` (`lib/types.ts`) via `mapTracerouteHopEvent` (`lib/agent-mapping.ts`), which owns this unwrap — pass it the full event, not `event.hop`.

Field notes:
- `hopIp`/`rttMs` are both **omitted from the JSON entirely** (not `null`) when that hop got no reply within its retry budget — this is expected, real trace data ("no response at this hop"), not an error. See the design spec's Error handling & lifecycle section.
- `hopNumber` never exceeds the hop ceiling (30); a trace stops early once `hopIp` equals `targetIp` (destination reached) or the total-trace timeout (45s) elapses.
- `targetIp` is repeated on every hop of a given trace so the relay/browser can correlate hops to the trace that produced them without tracking a separate trace-id — see `docs/geoip-protocol.md` for how the relay uses this same field to attach geoIP results.

## Relay → browser (SSE, not the raw agent protocol)

`app/api/stream/route.ts` re-wraps agent events as Server-Sent Events (`data: <json>\n\n`) and adds one synthetic event type the agent itself never sends:

```json
{"type": "connection_status", "connected": true}
```

Emitted immediately on a fresh browser connection (so the UI doesn't have to wait for the next real status change), and whenever the relay's TCP connection to the agent connects or disconnects.

## Relay → agent (control messages)

Tagged by `"type"` (snake_case).

```json
{"type": "pause"}
{"type": "resume"}
{"type": "register_decrypt_eligible", "pid": 4242, "keylogPath": "/Users/you/project/.data/keylogs/ab12cd34.keylog"}
{"type": "unregister_decrypt_eligible", "pid": 4242}
```

Sent by `app/api/control/route.ts` (POST endpoint, called by the UI's `pause`/`resume` command-bar commands and the header pause button) over the same TCP socket the agent uses to send events. `pause` stops the capture loop from processing new packets (existing flow state is retained, not cleared); `resume` restarts it.

`register_decrypt_eligible`/`unregister_decrypt_eligible` (Tier B) add/remove a PID from the agent's in-memory `KeyLogWatcher` (`capture-agent/src/keylog.rs`) — `bin/osi-inspect.js` sends these itself: `register_decrypt_eligible` as soon as the wrapped process's PID is known (right after spawn), `unregister_decrypt_eligible` when that process exits, for whatever reason. `keylogPath` must point at a key-log file the agent can read (normally the one `bin/osi-inspect.js` created). Decrypt-eligibility state is in-memory only and never persists across an agent restart. If the relay is unreachable when `osi-inspect` tries to register, it warns to stderr and still runs the wrapped process — decryption just won't be active for that run.

### `trace_route`

```json
{"type": "trace_route", "targetIp": "93.184.216.34"}
```

Sent by `app/api/traceroute/start/route.ts` (POST endpoint, called by `ConnectionsView`'s "Trace Route" button — see `docs/geoip-protocol.md` and this repo's `CLAUDE.md` for the rest of the UI wiring). On-demand only; the agent never starts a trace on its own. Triggers `traceroute::run_traceroute` (`capture-agent/src/traceroute.rs`) on a dedicated task per trace, bounded by a 30-hop ceiling, a 1s-per-hop-attempt timeout with up to 3 retries per hop, and a 45s total-trace timeout — these bounds are enforced agent-side regardless of what the relay sends. Each resolved hop streams back as its own `traceroute_hop` event (above) as soon as it's known, not batched until the trace completes.

## Adding a new field or event type

1. Add the field to the relevant `*Json` struct in `capture-agent/src/wire.rs`, or a new `AgentEvent` variant.
2. Populate it in `capture-agent/src/main.rs` where that event gets constructed.
3. Add the matching field to `lib/types.ts`.
4. Update the mapping function in `lib/agent-mapping.ts` to read it.
5. Update this document.

Field name mismatches between steps 1 and 4 are the single most common way this pipeline breaks silently — there's no compiler to catch it.
