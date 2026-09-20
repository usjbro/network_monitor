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

Maps to `PacketFrame` via `mapPacketEvent`, which throws if `headerBreakdown` is missing entirely rather than defaulting it to `{}` — see [issue #29](https://github.com/usjbro/network_monitor/issues/29) (closed): `PacketJson` (`capture-agent/src/wire.rs`) does carry a `header_breakdown` field, built by `wire::build_header_breakdown` from `ParsedPacket` + `L7Info` at the point each `Packet` event is constructed in `main.rs`'s capture loop. `layer2`/`layer3`/`layer4` are always present (every captured packet has an Ethernet/IP/transport header by construction); `layer7` is present only when the payload matched a recognized application protocol; `layer1`/`layer5`/`layer6` are never present — no PHY, session, or TLS-version/cipher data is extracted anywhere in this agent, and fabricating it would contradict the rest of this document's "report zero/absent rather than invent a number" convention. `layer2.vlanTag` (optional) is present only for an 802.1Q-tagged frame — see `parse.rs`'s `vlan_tag` field and [issue #62](https://github.com/usjbro/network_monitor/issues/62); a double-tagged (QinQ) frame reports only its outermost tag. `layer7.statusOrCode` (optional) is present only for a recognized HTTP response status line (`HTTP/<version> <3-digit code> <reason>`) — `l7::sniff_http_response`, see [issue #65](https://github.com/usjbro/network_monitor/issues/65). When present, `methodOrType` reads `"RESPONSE"` and `pathOrQuery` is empty (a response has neither a method nor a path). This is a decode only: nothing correlates a response to the request it answers, or computes service time — that is out of scope here and belongs to the request/response-matching work under epic #57. DNS responses are not decoded at all yet (`L7Info::Dns` still models the query only), so `statusOrCode` is never populated for DNS. `timestamp` is epoch milliseconds as a string, not ISO-8601.

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
    "relayLaggedEvents": 0,
    "unparseableFrames": 0,
    "totalConnectionsObserved": 812,
    "capacityEvictions": 0,
    "idleEvictions": 47
  }
}
```

Note the nesting: fields sit under a `stats` key, not flat on the event — same shape as `traceroute_hop`'s `hop` key (`capture-agent/src/wire.rs`'s `CaptureStats { stats: CaptureStatsJson }`). `mapCaptureStatsEvent` (`lib/agent-mapping.ts`) owns this unwrap; pass it the full event, not `event.stats`.

Field notes:
- `received`, `dropped`, `if_dropped` come straight from `pcap::Capture::stats()` (`ps_recv`/`ps_drop`/`ps_ifdrop`) — cumulative since the capture handle opened, not per-tick deltas. `dropped` is the kernel/driver's capture buffer filling up before the agent could read from it; `if_dropped` is the network interface driver dropping frames upstream of that buffer (`0` on platforms that don't report it separately). Both are `0` until the capture thread's first successful poll (roughly one second after the agent starts).
- `relayLaggedEvents` is unrelated to the three fields above: it's this relay process's own outbound backlog — a cumulative count (since agent start, not per-tick) of discrete `packet`/`decrypted_payload` events silently dropped for an SSE client that fell behind the broadcast channel (see `RecvError::Lagged` in `main.rs`). A capture can have `dropped: 0` and still have a nonzero `relayLaggedEvents` if the browser tab itself is slow to consume events.
- `unparseableFrames` is a fourth, independent signal: a cumulative count of frames the agent *did* receive from the capture handle but `parse::parse_packet` couldn't decode at all (an unsupported or malformed link-layer/network-layer shape — see issue #63 and `capture-agent/src/parse.rs`'s `LinkType`). Unlike `dropped`/`if_dropped`, these frames did reach this process; unlike `relayLaggedEvents`, this has nothing to do with the relay's outbound side.
- `totalConnectionsObserved` — the "N" half of an honest "showing N of M" horizon (JAM-6/GitHub #73): a cumulative count of every distinct flow this session's `FlowTable` has ever observed. A repeat packet on an already-tracked flow never inflates this, so it climbs only as genuinely new connections appear.
- `capacityEvictions`/`idleEvictions` — two independent reasons a flow can leave the table. `capacityEvictions` counts flows dropped because the table exceeded its capacity ceiling (`MAX_FLOWS`) — a nonzero, growing value here means this session is losing still-active flows under memory pressure, a materially different health signal from ordinary churn. `idleEvictions` counts flows evicted for going idle past their status-appropriate threshold — normal connection turnover, not a capacity concern.
- All eight counters are monotonically non-decreasing for the life of the agent process (never reset mid-run, even across a `pause`/`resume`).

Any connection's `packetLoss` (in `connection_update`) is derived purely from observed TCP retransmits — it has no way to know about packets the kernel or the relay itself lost before ever reaching that computation. A nonzero `dropped`/`ifDropped`/`relayLaggedEvents`/`unparseableFrames` here means `packetLoss` figures elsewhere in this same tick may under-report actual loss; the UI treats these two as independent signals (see `app/page.tsx`'s capture-degraded banner and `ConnectionsView`'s loss-column caveat) rather than trying to merge them into one number.

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

Sent once per tick (~1 second), alongside `capture_stats`/`system_stats`/`capture_config` — previously defined but never sent (the relay's `connection_status` event, below, is a separate, TCP-connection-derived signal and still exists independently). Revived by epic #55 (JAM-125) to carry the live/replay mode indicator file-replay needs.

```json
{
  "type": "agent_status",
  "interface": "lo",
  "capturing": true,
  "mode": "replay",
  "replaySource": "/Users/me/captures/incident.pcapng",
  "directionAttributionUnavailable": false
}
```

Flat (no nested envelope), unlike `capture_stats`/`system_stats`/`capture_config` above. Maps to `AgentStatus` (`lib/types.ts`) via `mapAgentStatusEvent` (`lib/agent-mapping.ts`).

Field notes:
- `interface` — the same interface name reported by `system_stats.interfaceName`; repeated here so this event is self-contained.
- `capturing` — `true` whenever the capture loop is actively processing frames; `false` while `pause`d. Distinct from `mode`: pausing doesn't change live vs. replay.
- `mode` — `"live"` or `"replay"`, fixed for the life of the agent process (see `REPLAY_FILE` in [troubleshooting.md](troubleshooting.md#replaying-a-capture-file-instead-of-live-traffic)) — never changes mid-session; there is no runtime live↔replay switch.
- `replaySource` — present only when `mode` is `"replay"`; the file path passed via `REPLAY_FILE`.
- `directionAttributionUnavailable` — `true` for the whole session when replay had no derivable local-address information (`REPLAY_LOCAL_ADDRS` unset and the file's own Interface Description block carried no address option). Every connection in that session used a positional fallback (the packet's source treated as local by convention) rather than a real determination — see `capture-agent/src/flow.rs`'s `key_for`. Always `false` in live mode.

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

### `capture_config`

Sent once per tick (~1 second), reporting the capture-time controls currently in effect — issue #68. Unlike `traceroute_hop`, this isn't triggered by a control message arriving; it's a persistent snapshot, resent every tick regardless of whether anything changed, so a browser tab that only just (re)connected sees the current values immediately rather than only a tab that happened to be connected at the moment a `set_capture_filter`/`set_snaplen` control message was applied.

```json
{
  "type": "capture_config",
  "config": {
    "filter": "tcp port 443",
    "snaplen": 96
  }
}
```

Note the nesting: fields sit under a `config` key, same shape as `capture_stats`'s `stats`/`traceroute_hop`'s `hop` — not flat on the event. `mapCaptureConfigEvent` (`lib/agent-mapping.ts`) owns this unwrap.

Field notes:
- `filter` — the active BPF capture filter expression, or **explicit `null`** (not omitted) when no filter is active, the default. `requireField`'s undefined-only check lets `null` through as a real, present value rather than throwing.
- `snaplen` — bytes retained per captured frame; anything beyond this is truncated by the kernel before the agent ever sees it. `65535` (`DEFAULT_SNAPLEN` in `capture-agent/src/main.rs`) at startup — effectively "full frame" for any real interface's MTU.

### `capture_config_error`

Sent once, immediately, when a `set_capture_filter`/`set_snaplen` control message is rejected — an invalid BPF expression, an oversized filter, an out-of-range snap length, or a reopen failure. Unlike `capture_config` above, this is a one-off signal, not a per-tick snapshot: it carries no nested envelope.

```json
{"type": "capture_config_error", "message": "invalid capture filter: syntax error"}
```

The rejected change never takes effect — the previous, still-active `filter`/`snaplen` keeps running, and the *next* `capture_config` tick reports that unchanged previous state, not anything derived from the rejected request. The UI (`app/page.tsx`) treats this as a dismissible banner rather than auto-clearing it on the next `capture_config` tick, since that tick re-sending the same still-unchanged config isn't evidence the rejection was resolved.

### `capture_file_status`

Sent once per tick (~1 second), reporting whether the agent is currently writing captured traffic to a pcapng file on disk — capture-to-file (epic #55/JAM-132/GitHub #70), ring rotation (JAM-5/GitHub #72). Like `capture_config`, this is a persistent snapshot resent every tick, not triggered by the `start_capture_file`/`stop_capture_file` control messages (below) arriving.

```json
{
  "type": "capture_file_status",
  "status": {
    "writing": true,
    "path": "/Users/me/captures/incident-0002.pcapng",
    "bytesWritten": 1048576,
    "ringFile": 2,
    "backpressureDrops": 0
  }
}
```

Note the nesting: fields sit under a `status` key, same shape as `capture_stats`'s `stats`/`traceroute_hop`'s `hop` — not flat on the event. `mapCaptureFileStatusEvent` (`lib/agent-mapping.ts`) owns this unwrap.

Field notes:
- `writing` — `true` while a capture-to-file run is active. `false` both before the first `start_capture_file` of the process's life and after a run stops (operator-requested or autostop) — the fields below keep reporting that run's last known values in the `false` case too (see next bullet), rather than resetting.
- `path`/`bytesWritten` — the currently (or, if `writing` is `false`, most recently) active file's path and cumulative bytes written. Present starting with the first successful `start_capture_file`; absent (`path`) or `0` (`bytesWritten`) before that. Only reset by the *next* successful `start_capture_file`, so a client sees the run's actual end state rather than the fields just disappearing the moment it stops.
- `ringFile` — present only while `ring` was configured on the active/most-recent `start_capture_file` request; a plain, non-rotating capture never has a ring file number at all. Counts up from `1` each time the writer rotates to a new file.
- `ringTotal` — reserved for a future fixed-size ring (wraps after N files); every ring mode this agent implements today (`size`/`duration`/`count`) rotates indefinitely rather than wrapping, so this is always absent.
- `autostopReason` — present only on the one tick a run just stopped itself: `"duration"`/`"totalSize"` (an autostop condition configured on `start_capture_file` fired) or `"lowDisk"` (the disk-space guard fired — free space on the target volume dropped below its floor, default 500MB). Absent while still actively writing, and absent again on an operator-requested `stop_capture_file` (that's not an *auto*-stop).
- `backpressureDrops` — cumulative count of packets the writer's bounded internal queue couldn't accept because the writer thread was falling behind (e.g. a slow disk) — never silently dropped from the operator's view even though the frame itself is gone. Distinct from `capture_stats`'s `dropped`/`unparseableFrames` counters above, which are about the kernel and the parser respectively, not this writer.

### `capture_file_error`

Sent once, immediately, when a `start_capture_file` control message is rejected — an invalid or unsafe path, a ring/autostop configuration with an invalid mode or a zero threshold, a capture already active (the operator must `stop` first), or free space already below the disk-space-guard floor. Same flat, one-off shape as `capture_config_error`/`interface_error`.

```json
{"type": "capture_file_error", "message": "a capture is already active — stop it first"}
```

The rejected request never takes effect — if a capture was already running, it keeps running unchanged; if none was, none starts. The *next* `capture_file_status` tick reports that unchanged state, same "rejection doesn't imply a state change" posture as `capture_config_error`.

### `interface_list`

Sent on-demand, once, in response to a `list_interfaces` control message (below) — issue #69. Unlike `capture_config`/`system_stats`, this is not a per-tick snapshot; the header's interface picker requests it lazily (when opened), not automatically.

```json
{
  "type": "interface_list",
  "interfaces": [
    { "name": "en0", "addresses": ["192.168.1.104"] },
    { "name": "lo0", "addresses": ["127.0.0.1", "::1"] }
  ]
}
```

Only interfaces `is_capturable` accepts (at least one assigned address) are ever included — an addressless interface can't be attributed as local/remote by `FlowTable` and would silently capture nothing if selected, so it's filtered out before the browser ever sees it as a choice, same principle as the `CAPTURE_INTERFACE` startup override's own rejection of one. `interfaces` can be an empty array (no capturable interfaces found) — that's reported honestly, not treated as an error.

### `interface_changed`

Sent once, immediately, on a successful `set_interface` — an ack for UI responsiveness (e.g. closing the picker, clearing an earlier `interface_error`) rather than waiting for the next `system_stats` tick, which also carries the same `interfaceName`/`ipAddress` every tick thereafter as the enduring source of truth.

```json
{"type": "interface_changed", "interface": {"name": "lo0", "ipAddress": "127.0.0.1"}}
```

Note the nesting: fields sit under an `interface` key, same shape as `capture_config`'s `config`/`traceroute_hop`'s `hop` — not flat on the event.

### `interface_error`

Sent once, immediately, when a `set_interface` control message is rejected — an oversized name, no matching interface, an addressless (uncapturable) interface, a device-list/open failure, or an unsupported link type on the target interface. Same flat, one-off shape as `capture_config_error`.

```json
{"type": "interface_error", "message": "no such interface: en9"}
```

The rejected switch never takes effect: the previous capture handle, link type, local-address list, and `FlowTable` all keep running exactly as they were — nothing is torn down speculatively before the new interface is confirmed to actually work. Unlike `capture_config_error`, the UI clears this banner automatically once `interface_changed` arrives, since that event only ever fires on a *successful* switch — real evidence the rejection was resolved, not just an unrelated periodic re-send.

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

### `set_capture_filter` / `set_snaplen`

```json
{"type": "set_capture_filter", "filter": "tcp port 443"}
{"type": "set_snaplen", "bytes": 96}
```

Sent by `app/api/control/route.ts` (same POST endpoint as `pause`/`resume`), called by the command bar's `filter <bpf expression>` / `filter clear` / `snaplen <bytes>` / `snaplen full` commands — issue #68. `filter clear` sends `{"filter": ""}`; an empty string is not a separate variant, it's the same request as any other filter, and compiles (via `pcap_compile`) to an unconditional-match BPF program, which is exactly "no filter."

Both are queued from the async connection-handling task into the capture thread (the only place the open `pcap::Capture` handle lives) via an in-process channel — `CaptureConfigRequest` in `capture-agent/src/main.rs`. `set_capture_filter` is applied live (`Capture::filter` recompiles and installs a new BPF program on the already-open handle, no capture interruption). `set_snaplen` has no live equivalent in libpcap: applying it closes and reopens the capture handle entirely (a brief, expected gap — logged, not hidden), then reapplies whatever filter was already active, since filter state doesn't survive a reopen. If that reapply itself fails, the whole snap length change is rejected — the agent never silently swaps in a reopened-but-unfiltered handle, since that would widen what gets captured as an unannounced side effect of a request that only asked to change the snap length.

Validation happens both relay-side (`app/api/control/route.ts` rejects a non-string/oversized filter or a non-positive-integer snap length with `400` before ever reaching the agent) and agent-side (the authoritative check: `MAX_CAPTURE_FILTER_LEN` = 1024 bytes, `validate_snaplen` rejects `0` and anything not representable as a positive `i32`). Either layer rejecting a request emits `capture_config_error` (above) and leaves the previous capture configuration running unchanged — never a half-applied state.

A BPF filter expression is new attacker-reachable input to this privileged process (it arrives from the browser and is compiled by libpcap in the agent), even though it's not a shell string and libpcap's own compiler is what parses it — see `docs/security.md`.

### `list_interfaces` / `set_interface`

```json
{"type": "list_interfaces"}
{"type": "set_interface", "name": "en1"}
```

Sent by `app/api/control/route.ts` (same POST endpoint as `pause`/`resume`/`set_capture_filter`), called by the command bar's `iface list` / `iface <name>` commands and the header's interface picker — issue #69. `list_interfaces` triggers an `interface_list` response; it doesn't touch the open capture handle at all, so it's handled directly in the async connection-handling task rather than round-tripping through the capture thread.

`set_interface` is queued into the capture thread the same way `set_capture_filter`/`set_snaplen` are (the open `pcap::Capture` handle only ever lives there) via `apply_interface_switch_request` (`capture-agent/src/main.rs`). A successful switch:

1. Looks up the named device via `pcap::Device::list()`, rejecting (via `interface_error`) if it doesn't exist or has no assigned address — same validation `CAPTURE_INTERFACE` already applies at startup.
2. Opens a new capture handle on it (at the default snap length — a filter/snaplen tuned for the previous interface may not even be meaningful on this one, so both reset to their defaults rather than carrying forward silently) and re-resolves its link type, since a different interface can use an entirely different one (e.g. switching from `en0`, Ethernet, to `lo0`, loopback). An unsupported link type is rejected the same way `resolve_link_type` would reject it at startup, except non-fatally here — `datalink_to_link_type` (the non-panicking primitive `resolve_link_type` wraps) — a bad interface choice at runtime must never crash the whole agent.
3. Resets `FlowTable` entirely (`FlowTable::reset`, `capture-agent/src/flow.rs`) — every previously-tracked flow belonged to the interface that just stopped being captured, and leaving one behind with a now-wrong local-address frame of reference is exactly the silent-direction-flip bug this issue calls out as the error-prone part of switching interfaces. Each flow discarded this way emits its own `connection_closed` event, same as normal idle eviction.
4. Only once all of the above succeeds does it replace the live capture handle, link type, local-address list, and `capture_config`/`system_stats`-reported identity — a failure at any step leaves every one of those exactly as it was.

`CAPTURE_INTERFACE` still wins at startup and is unaffected by any of this — it's read once, before the TCP listener even binds; `set_interface` only ever changes the *runtime* selection made after that.

### `start_capture_file` / `stop_capture_file`

```json
{"type": "start_capture_file", "path": "/Users/me/captures/incident.pcapng"}
{"type": "start_capture_file", "path": "/Users/me/captures/incident.pcapng", "ring": {"mode": "size", "threshold": 104857600}, "autostop": {"mode": "duration", "threshold": 3600}}
{"type": "stop_capture_file"}
```

Sent by `app/api/control/route.ts` (same POST endpoint as `pause`/`resume`/`set_capture_filter`), called by the command bar's `capture <path> [ring <mode> <n>] [autostop <mode> <n>]` / `capture stop` commands — capture-to-file (epic #55/JAM-132/GitHub #70, ring rotation JAM-5/GitHub #72).

`ring`/`autostop` are both optional and independent of each other — a `start_capture_file` with neither writes one plain, non-rotating file until stopped. `ring.mode` is one of `"size"` (rotate after `threshold` bytes), `"duration"` (rotate after `threshold` seconds), or `"count"` (rotate after `threshold` packets); `autostop.mode` is one of `"duration"` (stop after `threshold` seconds) or `"totalSize"` (stop after `threshold` bytes written across every file in the run, not just the current one) — there is no `"lowDisk"` autostop mode to request; the disk-space guard below is a separate, always-active mechanism, not something `autostop` configures. An invalid mode string or a zero `threshold` on either `ring` or `autostop` is rejected via `capture_file_error` — same validation posture as `set_capture_filter`'s BPF expression checks.

Queued from the async connection-handling task into the dedicated writer thread (the only place the open `pcapng::Writer`/`ring::RingState` lives) via an in-process channel, the same pattern `set_capture_filter`/`set_snaplen`/`set_interface` use for the capture thread. Rejected via `capture_file_error` rather than silently switching files out from under an in-flight write or writing somewhere unsafe: `start_capture_file` while one is already active; an empty path; a path containing a `.data/` component; or a path that resolves *inside* the agent's own working directory (`validate_capture_file_path` in `capture-agent/src/main.rs` — capture files must be written somewhere outside the agent's own project checkout, not inside it). `stop_capture_file` with no capture active is a no-op, reported success — same idempotent tolerance `pause`/`resume` already have for a redundant call.

Refuses to begin at all if free space on the target volume is already below a fixed 500MB floor (`DEFAULT_LOW_DISK_FLOOR_BYTES` in `capture-agent/src/ring.rs` — not operator-configurable; `start_capture_file`'s wire shape has no field for it); while running, the writer thread checks free space each rotation tick and stops cleanly (same clean-stop path as autostop, reported via `capture_file_status`'s `autostopReason: "lowDisk"`) rather than running the volume to zero.

## Adding a new field or event type

1. Add the field to the relevant `*Json` struct in `capture-agent/src/wire.rs`, or a new `AgentEvent` variant.
2. Populate it in `capture-agent/src/main.rs` where that event gets constructed.
3. Add the matching field to `lib/types.ts`.
4. Update the mapping function in `lib/agent-mapping.ts` to read it.
5. Update this document.

Field name mismatches between steps 1 and 4 are the single most common way this pipeline breaks silently — there's no compiler to catch it.
