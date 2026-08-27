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
    "sparkline": []
  }
}
```

Maps to `NetworkConnection` (`lib/types.ts`) via `mapConnectionEvent` (`lib/agent-mapping.ts`), which throws if any required field is missing — a malformed event is a loud failure, not a silent `undefined`.

Field notes:
- `status` — one of `ESTABLISHED` / `SYN_SENT` / `TIME_WAIT` / `CLOSE_WAIT`, derived from observed TCP flags. Non-TCP flows (UDP, ICMP) report `ESTABLISHED` — there's no TCP-style closing state for a connectionless protocol.
- `packetLoss` — a retransmission-based *approximation*, not a precise measurement. See [troubleshooting.md](troubleshooting.md#what-does-retransmit-anomaly-mean).
- `latencyMs` — SYN→SYN-ACK round-trip time, `0` if the handshake wasn't observed (e.g. the connection predates the agent starting).
- `remoteHostname` (optional in the TS type) is never populated by the current agent — reverse-DNS/WHOIS enrichment is a separate, not-yet-built sub-project.

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
    "hexDump": "00 01 02 ..."
  }
}
```

Maps to `PacketFrame` via `mapPacketEvent`. `headerBreakdown` always arrives as `{}` currently ([issue #29](https://github.com/usjbro/network_monitor/issues/29) — the agent parses this data internally but doesn't put it on the wire yet). `timestamp` is epoch milliseconds as a string, not ISO-8601.

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

### `agent_status`

Defined in the wire protocol (`interface: String, capturing: bool`) but **never actually sent** by the current agent — the relay synthesizes its own `connection_status` event from the TCP connection state instead (see below). This is dead wire protocol surface; a future task should either wire it up (so the UI can display which interface is active) or remove it.

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
```

Sent by `app/api/control/route.ts` (POST endpoint, called by the UI's `pause`/`resume` command-bar commands and the header pause button) over the same TCP socket the agent uses to send events. `pause` stops the capture loop from processing new packets (existing flow state is retained, not cleared); `resume` restarts it.

## Adding a new field or event type

1. Add the field to the relevant `*Json` struct in `capture-agent/src/wire.rs`, or a new `AgentEvent` variant.
2. Populate it in `capture-agent/src/main.rs` where that event gets constructed.
3. Add the matching field to `lib/types.ts`.
4. Update the mapping function in `lib/agent-mapping.ts` to read it.
5. Update this document.

Field name mismatches between steps 1 and 4 are the single most common way this pipeline breaks silently — there's no compiler to catch it.
