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
    "hexDump": "00 01 02 ..."
  }
}
```

Maps to `PacketFrame` via `mapPacketEvent`. Note `PacketJson` (`capture-agent/src/wire.rs`) has **no `header_breakdown` field at all** — it isn't sent on the wire in any form, empty or otherwise. The `{}` you see on the TypeScript side is `mapPacketEvent`'s own fallback (`lib/agent-mapping.ts`, `?? {}`) for a key that's simply absent from the JSON. The underlying per-layer detail (parsed MACs/TTL/flags in `parse.rs`, TLS SNI/HTTP method+path/DNS query name in `l7.rs`) does exist transiently inside the agent's capture loop, but is discarded before `PacketJson` gets constructed — nothing currently threads it through. See [issue #29](https://github.com/usjbro/network_monitor/issues/29). `timestamp` is epoch milliseconds as a string, not ISO-8601.

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

`register_decrypt_eligible`/`unregister_decrypt_eligible` (Tier B) add/remove a PID from the agent's in-memory `KeyLogWatcher` (`capture-agent/src/keylog.rs`) — nothing currently on the relay side sends these automatically; they're the intended trigger point for a future UI/CLI integration that watches an `osi-inspect`-wrapped process's lifetime, not yet wired up end-to-end in this plan. `keylogPath` must point at a key-log file the agent can read (normally the one `bin/osi-inspect.js` created). Decrypt-eligibility state is in-memory only and never persists across an agent restart.

## Adding a new field or event type

1. Add the field to the relevant `*Json` struct in `capture-agent/src/wire.rs`, or a new `AgentEvent` variant.
2. Populate it in `capture-agent/src/main.rs` where that event gets constructed.
3. Add the matching field to `lib/types.ts`.
4. Update the mapping function in `lib/agent-mapping.ts` to read it.
5. Update this document.

Field name mismatches between steps 1 and 4 are the single most common way this pipeline breaks silently — there's no compiler to catch it.
