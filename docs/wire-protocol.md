# Wire Protocol Reference

The contract between `capture-agent` (Rust, producer) and the Next.js relay (TypeScript, consumer). There is no compiler check across this boundary — if you change one side, you must change the other. Source of truth: `capture-agent/src/wire.rs` (Rust) and `lib/agent-mapping.ts` / `lib/types.ts` (TypeScript).

## Transport

- Newline-delimited JSON (NDJSON) over a plain TCP socket, `127.0.0.1:9990`.
- **Agent → relay**: one JSON object per line, each tagged with a `"type"` field.
- **Relay → agent**: authentication followed by control messages, same NDJSON framing, on the same connection.
- **Strict framing after authentication (JAM-175)**: the agent closes the connection on the first relay → agent line that is not a JSON object. Blank lines and JSON objects it can't decode (unknown `type`, missing or mistyped field) are skipped, and the connection stays open. The strict rule blocks cross-protocol requests: a browser `fetch` POST to `127.0.0.1:9990` sends an HTTP request line first, so the agent hangs up before reading the JSON body lines that would otherwise run as control messages. See `wire::classify_control_line`.
- All field names are `camelCase` on the wire (Rust uses `#[serde(rename_all = "camelCase")]`), matching the TypeScript field names exactly — no translation layer.

## Socket authentication (JAM-184)

Both the feed and controls require possession of a fresh per-launch credential. This Unix-only handoff uses `$HOME/.network-monitor/agent-control-token` by default; set the same absolute `AGENT_TOKEN_FILE` path in both processes to override it. The agent generates 32 random bytes each launch and atomically publishes 64 lowercase hex characters plus LF only after binding successfully. Its immediate parent must be a real, current-UID directory with mode 0700; the credential must be a current-UID regular file with mode 0600 and exactly one hard link. Immediate-parent/final-file symlinks are rejected; platform ancestor aliases such as macOS `/var` are resolved. Agent publication is directory-FD anchored; relay validation and reading use one no-follow file FD.

The first client line is `{"type":"authenticate","token":"<64 lowercase hex characters>"}`. No extra fields are accepted. The first line, including LF, is bounded to 256 bytes and an absolute 5-second deadline. Missing/wrong credentials, a control-first message, non-JSON input, EOF or timeout close the connection before any feed subscription or control processing. Successful authentication produces `{"type":"authenticated"}` plus LF, written within a further 5 seconds before feed/control access. Coalesced bytes after the first LF remain available to normal parsing; the 256-byte cap does not apply to the larger following command/event. Strict framing below applies to controls after authentication.

There are separate budgets of 16 pending and 64 authenticated connections. Excess peers close; existing authenticated sessions remain served when pending admission fills. These limits do not guarantee admission of a new relay during a local flood. The relay reads the credential afresh on every attempt, sends authentication first, and reports connected/allows controls only after the exact acknowledgement. Pre-auth controls are dropped. Handshake messages never enter browser/SSE events. A rotated/stale credential may briefly cause a generic handshake failure during restart; normal reconnect loads the replacement.

Publication failure exits non-zero before entering the accept loop, with a credential-path diagnostic. Missing/unsafe relay credentials or handshake failure produce deduplicated server-side reasons and disconnected UI state. When the credential guard is dropped it removes only its own file identity. The agent does not install a signal handler: normal Ctrl-C/SIGTERM, abrupt termination or a crash can leave a stale private file, replaced on the next successful launch. Do not print or copy tokens into command arguments. Direct socket consumers must implement this handshake; `bin/osi-inspect.js` continues to use relay HTTP routes.

This protects the direct agent socket. Same-UID programs can read the credential, the ACK is not cryptographic server authentication, and the relay HTTP routes still lack caller authentication (JAM-196). See [security.md](security.md).

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
- `latencyMs` (optional) — SYN→SYN-ACK round-trip time. Absent when no RTT was measured: every non-TCP flow, and any TCP flow whose handshake wasn't observed (e.g. the connection predates the agent starting). Never sent as a placeholder `0` (JAM-156); the Connections view shows `—` for an absent value.
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
    "headerHexDump": "06 07 08 09 0a 0b 00 01 02 03 04 05 08 00 45 00 ...",
    "fields": [
      {"path":"eth","label":"Ethernet II","type":"group","region":"header","offset":0,"len":14},
      {"path":"eth.dst","label":"Destination MAC","type":"addr","group":"eth","region":"header","value":"06:07:08:09:0a:0b","offset":0,"len":6},
      {"path":"eth.src","label":"Source MAC","type":"addr","group":"eth","region":"header","value":"00:01:02:03:04:05","offset":6,"len":6},
      {"path":"eth.type","label":"EtherType","type":"str","group":"eth","region":"header","value":"IPv4","offset":12,"len":2},
      {"path":"ip","label":"Internet Protocol Version 4","type":"group","region":"header","offset":14,"len":20},
      {"path":"ip.src","label":"Source Address","type":"addr","group":"ip","region":"header","value":"192.168.1.10","offset":26,"len":4},
      {"path":"ip.dst","label":"Destination Address","type":"addr","group":"ip","region":"header","value":"93.184.216.34","offset":30,"len":4},
      {"path":"ip.ttl","label":"Time to Live","type":"uint","group":"ip","region":"header","value":64,"offset":22,"len":1},
      {"path":"ip.protocol_num","label":"Protocol","type":"uint","group":"ip","region":"header","value":6,"offset":23,"len":1},
      {"path":"ip.checksum","label":"Header Checksum","type":"str","group":"ip","region":"header","value":"0xbeef","offset":24,"len":2},
      {"path":"tcp","label":"Transmission Control Protocol","type":"group","region":"header","offset":34,"len":20},
      {"path":"tcp.src_port","label":"Source Port","type":"uint","group":"tcp","region":"header","value":51000,"offset":34,"len":2},
      {"path":"tcp.dst_port","label":"Destination Port","type":"uint","group":"tcp","region":"header","value":443,"offset":36,"len":2},
      {"path":"tcp.seq","label":"Sequence Number","type":"uint","group":"tcp","region":"header","value":1000,"offset":38,"len":4},
      {"path":"tcp.ack_number","label":"Acknowledgment Number","type":"uint","group":"tcp","region":"header","value":0,"offset":42,"len":4},
      {"path":"tcp.flags","label":"Flags","type":"group","group":"tcp","region":"header","offset":47,"len":1},
      {"path":"tcp.flags.syn","label":"SYN","type":"bool","group":"tcp.flags","region":"header","value":true,"offset":47,"len":1},
      {"path":"tcp.flags.ack","label":"ACK","type":"bool","group":"tcp.flags","region":"header","value":false,"offset":47,"len":1},
      {"path":"tcp.flags.fin","label":"FIN","type":"bool","group":"tcp.flags","region":"header","value":false,"offset":47,"len":1},
      {"path":"tcp.flags.rst","label":"RST","type":"bool","group":"tcp.flags","region":"header","value":false,"offset":47,"len":1},
      {"path":"tcp.window_size","label":"Window Size","type":"uint","group":"tcp","region":"header","value":65535,"offset":48,"len":2}
    ]
  }
}
```

Maps to `PacketFrame` via `mapPacketEvent`, which requires `fields` to be present (including when empty). `PacketJson` (`capture-agent/src/wire.rs`) carries `fields: Vec<Field>` from `fields::build_fields` and `headerHexDump` from `ParsedPacket.header_bytes`. `timestamp` is epoch milliseconds as a string, not ISO-8601. It is the packet's capture timestamp: the live capture clock in live mode, and the timestamp recorded in the file during replay. `relativeTimeMs` remains elapsed agent time, so replay speed affects that relative value but not `timestamp`.

`layer`, `protocol`, `src`, and `dst` describe the captured physical frame. An IPv4 fragment stays at layer 3 with its parsed protocol and addresses (and `:0` endpoints when its own frame has no decoded ports), even when completing the fragment group lets the agent decode application data from the reconstructed datagram. Reassembled application fields are also omitted from that physical frame's byte fields because their offsets refer to bytes across multiple frames.

`hexDump` contains at most the first 64 payload bytes. `headerHexDump` contains all parsed Ethernet/IP/transport header bytes and has no artificial cap. Field `offset` and `len` are relative to the pane named by `region`: `"header"` for `headerHexDump`, `"payload"` for `hexDump`. A payload field can extend beyond the 64 visible bytes; its full range is retained for data consumers while the UI highlights only visible bytes.

`path` is the stable dotted abbreviation used by filters; `label` is display text. `group` names the immediate parent path and is omitted for top-level fields. `type` is `group`, `bool`, `uint`, `str`, `addr`, or `bytes`. Group entries omit `value` entirely. Sibling TCP flag fields share one byte, so their ranges legitimately overlap. Header field offsets account for variable-length IP headers and extension headers when present; leaf offsets within TCP/UDP's fixed portion remain RFC-defined. Text and derived application fields span the payload range, while `tls.handshake.sni` identifies the precise server-name bytes.

Top-level groups describe only protocols actually decoded: `eth` appears for Ethernet framing, `ip` or `ip6` for the network layer, `tcp` or `udp` for decoded transport, and `http`, `dns`, or `tls` when application decoding succeeds. Loopback and raw-IP framing have no `eth` group. An 802.1Q tag appears as `eth.vlan` with child `eth.vlan.id`. ICMP and unrecognized transports have no transport group because no fields are decoded for them today.

**DNS fields (JAM-15).** A DNS message over UDP decodes as a query (`dns.flags.response` false) or a response (true); before JAM-15 a response's echoed question was reported as though it were a query. Both carry `dns.id` (transaction ID), `dns.qry.name` and `dns.qry.type` (a mnemonic such as `"A"`/`"AAAA"`, or `"TYPE<n>"` for an unknown type). A response adds `dns.flags.rcode` (`"NOERROR"`, `"NXDOMAIN"`, ... or `"RCODE<n>"`), `dns.count.answers` (the header's ANCOUNT as sent), and an `dns.answers` group holding one `dns.answer.<i>` group per decoded record, each with `.name`, `.type`, `.ttl` (seconds) and, for A/AAAA (type `addr`) and CNAME/NS/PTR (type `str`), `.data`. At most 16 records are decoded (`l7::MAX_DNS_ANSWERS`), so `dns.count.answers` can exceed the number of `dns.answer.<i>` groups; a truncated message keeps the records decoded before the cut. Answer paths are indexed rather than repeated because a path is unique within a packet.

**Service-time fields (JAM-15).** A response matched to its request (`capture-agent/src/transaction.rs`) gets derived fields with `offset` 0 and `len` 0 (they come from the match, not from this packet's bytes):

- `dns.time_us` / `http.time_us` (`uint`): microseconds from the request's capture timestamp to the response's. Microseconds because display filters compare integers only, and milliseconds would round a cached sub-millisecond DNS answer to 0. Measured on the frames' own capture timestamps, in replay as well as live.
- `dns.response_to` / `http.response_to` (`str`): the request's `packet` event `id`. Present only when the request was itself sent as a `packet` event; a request the packet-event limiter skipped gets a matched response with a time but no link, so the UI is never pointed at a frame it never received.
- `dns.response.duplicate` (`bool`, always `true`): a second response to a DNS transaction answered within the last 5 s. It carries no time.

Matching rules: DNS matches on flow, transaction ID and the echoed question name (case-insensitive), and only for unicast DNS over UDP port 53. mDNS/LLMNR are answered on other flows, and DNS over TCP isn't decoded. HTTP/1.x matches a final response to the oldest outstanding request on the connection. A `1xx` other than `101` is interim and doesn't consume it. A response must travel the opposite way to its request, or nothing is consumed. A TCP-retransmitted request segment is not queued twice. Repeating a DNS query while the first is pending keeps the first send time.

**Rate-limited event sampling, not every packet.** `packet` events are throttled by `PacketEventLimiter::new(100, 1000)` (`capture-agent/src/rate_limit.rs`, applied in the capture loop in `capture-agent/src/main.rs`). It is a minimum-interval throttle: at most one `packet` event every 10 ms (100 per second), spaced evenly across each second. There is no burst allowance, so a busy second doesn't front-load 100 events and then go quiet. A packet that arrives before the next slot gets no `packet` event, and nothing records that it was skipped. This samples the *event stream* only. What the limiter does **not** affect:

- **Flow accounting.** `FlowTable::observe` runs on every successfully parsed IP frame before the limiter, so each `connection_update`'s byte and packet totals are complete for that flow. Frames that match no tracked flow (e.g. broadcast or multicast seen in promiscuous mode) aren't attributed to any connection. Frames that fail decoding never reach `observe` and count in `capture_stats.unparseableFrames`. Successfully framed non-IP Ethernet traffic is outside IP flow analysis and is excluded from that failure counter. `layer_update` carries no packet counts.
- **Capture files.** Every successfully parsed frame is handed to the pcapng writer before the limiter, subject only to the writer's own backpressure (`capture_file_status.backpressureDrops`). Frames that fail to parse are not written.
- **Kernel totals.** In a live capture, `capture_stats.received` (repeated as `system_stats.totalPacketsCaptured`) is the OS capture driver's count of every frame it delivered. It is not polled during a file replay, so it reads 0 there.

`finding` events are throttled per code, not as one stream:
- **`malformed-frame`** has its own limiter at 20 per second.
- **`connection-reset`** isn't throttled.
- **`retransmission`** is only evaluated for packets that pass the `packet` limiter, so it shares that budget (see the note under `finding`).
- **`unanswered-request`** shares the `malformed-frame` limiter's 20 per second. A finding it drops is still counted in `service_time_update`'s `unanswered`.

`decrypted_payload` has its own 100-per-second limiter. The browser keeps only the most recent `buffer packets <n>` events (default 100; see `docs/usage.md`). Use them for inspection, not for counting. Historical note: before issue #27 (fixed in PR #34), every captured packet produced its own event.

### `finding`

Sent immediately (like `packet`, not batched) — Expert Info (JAM-12): an annotated observation, never a verdict. No finding's `summary` may assert intent, cause, or maliciousness ("attack", "suspicious", "malicious") — only what was observed.

```json
{
  "type": "finding",
  "finding": {
    "id": "finding-1790400000000-1",
    "timestamp": "1790400000000",
    "severity": "warning",
    "code": "retransmission",
    "summary": "retransmitted segment",
    "frameId": "pkt-1790400000000-1"
  }
}
```

Maps to `Finding` via `mapFindingEvent` (`lib/agent-mapping.ts`), which owns the `finding` envelope unwrap the same way `mapCaptureStatsEvent`/`mapTracerouteHopEvent` do.

`timestamp` is epoch milliseconds as a string. A packet-triggered finding uses the triggering frame's capture timestamp, including during replay. An `unanswered-request` finding has no triggering packet; its timestamp is the capture/live time when the request expires. Replay expiry is evaluated as packets advance through capture time, while live idle expiry continues on wall time.

Field notes:
- `severity` is advisory display metadata (`error` / `warning` / `note` / `chat`, mirroring Wireshark's own Expert Info severity vocabulary), not a verdict derived from "how bad is this" — a `connection-reset` finding is `note`, not `error`, because a reset is a normal TCP closing mechanism as often as an abnormal one.
- `code` is a small, closed, stable set, additive-only once shipped, like a field registry `path`. Three codes ship in JAM-12: `retransmission`, `connection-reset`, `malformed-frame`. JAM-15 adds `unanswered-request`.
- `frameId`/`flowId` are each independently optional, and a finding may carry neither. `retransmission` carries `frameId` only; `connection-reset` carries `flowId` only; `malformed-frame` carries **neither** — `parse::parse_packet` failing means no `ParsedPacket`, and therefore no `packet` event or flow, was ever produced for that frame, so there is nothing to navigate to. This is by design, not a gap to fix later (see `docs/superpowers/specs/2026-09-26-expert-info-findings-design.md`).
- `retransmission`'s `frameId` always corresponds to a `packet` event the UI actually received: both are gated by the same capture-loop rate limiter and generated from the same `pkt-<epoch_ms>-<seq>` id, so a rate-limited-out retransmission simply produces no finding, consistent with producing no `packet` event either.
- `unanswered-request` (severity `warning`) fires once per DNS query or HTTP/1.x request with no response within 5 s (DNS) or 30 s (HTTP) of capture time, e.g. `no DNS response to "example.com" A within 5 s`. It always carries `flowId`, and carries `frameId` when the request was sent as a `packet` event. The request text in `summary` is display-safe: anything other than printable ASCII is escaped as `\u{..}`, and it is cut at 120 characters. HTTP's 30 s is exceeded by long-poll requests, which is why the summary says no response was *seen*, not that the request failed. Pending requests are bounded (4,096 overall, 32 per HTTP connection). A request past those bounds is counted as `untracked`, not matched. A runtime interface switch discards pending requests without reporting them.
- `connection-reset` fires once per flow, on the transition into `rst_seen`, not on every subsequent RST-flagged packet on an already-reset flow (e.g. a retransmitted RST).
- `malformed-frame`'s `summary` names the active link type and the frame's byte length (e.g. "58-byte frame did not decode as Ethernet framing") — not a per-parse-stage failure reason. The capture loop uses `parse_packet_result` to distinguish decoder failures from unsupported non-IP Ethernet traffic. ARP, VLAN-tagged ARP, and unknown non-IP EtherTypes whose framing decoded successfully produce neither this finding nor a parse-failure count. Truncated ARP/VLAN/IP headers, inconsistent known ARP address sizes, and undecoded known encapsulation at the decoder nesting limit still count as parse failures. Unknown protocol payloads are not validated or decoded; successful framing does not certify their contents. The legacy `parse_packet` API remains Option-returning for existing consumers and fuzz coverage.

Not yet implemented (deferred, not silently dropped — see the design spec's "Deferred to a later task"): duplicate-ACK and zero-window findings (need new detection state, not just surfacing something already computed), and `capture-drop`/`relay-lag` findings (already covered by the existing capture-degraded banner driven by `capture_stats`).

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

### `protocol_hierarchy_update`

Sent once per tick (~1 second), immediately after that tick's `layer_update`. Measured protocol hierarchy (JAM-13/GitHub #80): cumulative bytes/packets since capture start, nested by the layers a frame actually traversed — replaces the static, always-the-same protocol lists `ProtocolMatrixView` used to render regardless of real traffic.

```json
{
  "type": "protocol_hierarchy_update",
  "hierarchy": {
    "name": "Capture",
    "bytes": 214300,
    "packets": 940,
    "children": [
      {
        "name": "Ethernet",
        "bytes": 214300,
        "packets": 940,
        "children": [
          {
            "name": "IP",
            "bytes": 214300,
            "packets": 940,
            "children": [
              {
                "name": "TCP",
                "bytes": 198100,
                "packets": 810,
                "children": [
                  { "name": "HTTPS/TLS", "bytes": 150200, "packets": 520, "children": [] },
                  { "name": "HTTP", "bytes": 30100, "packets": 180, "children": [] },
                  { "name": "Unknown", "bytes": 17800, "packets": 110, "children": [] }
                ]
              },
              {
                "name": "UDP",
                "bytes": 16200,
                "packets": 130,
                "children": [
                  { "name": "DNS", "bytes": 16200, "packets": 130, "children": [] }
                ]
              }
            ]
          }
        ]
      }
    ]
  }
}
```

Note the nesting: fields sit under a `hierarchy` key, same convention as `traceroute_hop`'s `hop` key (`capture-agent/src/wire.rs`'s `ProtocolHierarchyUpdate { hierarchy: Box<ProtocolNodeJson> }`). `mapProtocolHierarchyEvent` (`lib/agent-mapping.ts`) owns this unwrap and the recursive conversion; pass it the full event, not `event.hierarchy`.

Field notes:
- Every node's `bytes`/`packets` equal the sum of its own `children`'s, by construction — a percentage at any level is `child.bytes / parent.bytes`. This is cumulative since capture start and, unlike `layer_update`'s L3/L4 aggregates, is never derived from currently-live flows: a closed or capacity-evicted connection's already-observed traffic still counts, permanently (see `flow::ProtocolNode`'s doc comment in `capture-agent/src/flow.rs`).
- `children` is `[]` at a leaf, never omitted — same convention as `sparkline: []` elsewhere in this document.
- `Ethernet` and `IP` are always the entire capture's totals (100% of `bytes`) — every currently-decoded frame that reaches `FlowTable::observe` has already been parsed at both layers. The transport level (`TCP`/`UDP`/`ICMP`/`Other`) is where real variation first appears.
- An app-protocol child (`HTTP`, `DNS`, `HTTPS/TLS`, or a well-known-port guess) only nests under `TCP`/`UDP` — `ICMP`/`Other` have no app-layer concept in this model, so their path stops at the transport label.
- `Unknown` under a transport node is real, unidentified traffic — deliberately visible rather than rounded away, per the task's "identify unknown traffic honestly" requirement. Its size is a useful signal for prioritizing future dissector work (epic JAM-128/GitHub #58).

### `endpoint_update` / `conversation_update`

Sent once per tick (~1 second), immediately after that tick's `protocol_hierarchy_update`. Per-remote-host (`endpoint_update`) and per-(local,remote)-pair (`conversation_update`) traffic rollups (JAM-14/GitHub #81): "Conversations and Endpoints — per-pair and per-host byte, packet and duration totals." Same permanence contract as `protocol_hierarchy_update` — cumulative since capture start, never derived from currently-live flows, so a host's total survives every one of its flows closing or being evicted (see `flow::RollupState`'s doc comment in `capture-agent/src/flow.rs`). Each event is a full replacement list, not incremental — the agent's own rollups only ever grow, so a client just replaces its whole table on every event rather than diffing.

```json
{
  "type": "endpoint_update",
  "endpoints": [
    {
      "host": "93.184.216.34",
      "rxBytesTotal": 40960,
      "txBytesTotal": 20480,
      "rxPacketsTotal": 120,
      "txPacketsTotal": 80,
      "rxSpeed": 1024.0,
      "txSpeed": 512.0,
      "flowCount": 50,
      "firstSeenMs": 1200,
      "lastSeenMs": 61200,
      "processName": "Safari",
      "pid": 1234,
      "ja3Label": "matches Chrome 12x"
    }
  ]
}
```

```json
{
  "type": "conversation_update",
  "conversations": [
    {
      "localAddr": "192.168.1.10",
      "remoteAddr": "93.184.216.34",
      "rxBytesTotal": 40960,
      "txBytesTotal": 20480,
      "rxPacketsTotal": 120,
      "txPacketsTotal": 80,
      "rxSpeed": 1024.0,
      "txSpeed": 512.0,
      "flowCount": 50,
      "firstSeenMs": 1200,
      "lastSeenMs": 61200,
      "durationMs": 60000,
      "processName": "Safari",
      "pid": 1234,
      "ja3Label": "matches Chrome 12x"
    }
  ]
}
```

Both are flat arrays under their own key (`mapEndpointUpdateEvent`/`mapConversationUpdateEvent` in `lib/agent-mapping.ts` own the unwrap, same convention as `mapInterfaceListEvent`'s `interfaces` key) — not nested under a singular envelope key the way `protocol_hierarchy_update`'s `hierarchy` is.

Field notes:
- `host` (endpoint) is always the flow's *remote* address — the local side is "this machine" and isn't itself an interesting dimension to break `endpoint_update` down by. `localAddr`/`remoteAddr` (conversation) keep both: two local addresses talking to the same remote host are two separate conversations but one combined endpoint.
- A host that opened many short-lived flows (e.g. a browser opening 50 connections to one CDN endpoint) always collapses to exactly one row — `flowCount` is the number of distinct flows that ever contributed, not a count of currently-live ones.
- `rxSpeed`/`txSpeed` are this-tick-only rates (same tick-elapsed/drain contract as `connection_update`'s own `rxSpeed`/`txSpeed`) — every other numeric field is a running cumulative total.
- `processName`/`pid` reflect whichever of this tick's currently-*live* flows contributing to that host/pair was most recently active (largest `last_seen_ms`) — a host with zero currently-live flows (every contributing flow evicted, only the cumulative rollup surviving) reports `"unknown"`/`0`, the same fallback `connection_update` uses for an unrecognized local port.
- `ja3Label` is the most recently observed non-empty label across every flow contributing to that host/pair — deliberately not "first ClientHello wins" the way a single connection's own `ja3Label` is, since a host with many short-lived TLS flows should show its current fingerprint. Omitted (not `null`) when no flow contributing to that host/pair has ever completed a TLS handshake.
- `durationMs` (conversation only) is `lastSeenMs - firstSeenMs`.
- Reverse-DNS/ownership and geoIP enrichment are not part of this wire event at all — they're looked up client-side, opt-in, exactly as `connection_update`'s own `enrichment` already is, just triggered once per `host` row instead of once per flow.

### `service_time_update`

Sent once per tick (~1 second), right after `endpoint_update`. Service response time per protocol (JAM-15), from `transaction::ServiceTimeStats`. Always one entry per protocol (`DNS`, then `HTTP`), so a client can show "0 answered" rather than guess why one is missing.

```json
{
  "type": "service_time_update",
  "summaries": [
    {"protocol": "DNS", "answered": 42, "unanswered": 1, "untracked": 0,
     "minUs": 310, "maxUs": 240000, "sampleCount": 42, "medianUs": 11200, "p95Us": 95000},
    {"protocol": "HTTP", "answered": 0, "unanswered": 0, "untracked": 0, "sampleCount": 0}
  ]
}
```

Maps to `ServiceTimeSummary[]` via `mapServiceTimeUpdateEvent` (`lib/agent-mapping.ts`).

Field notes:
- `answered`, `unanswered`, `untracked`, `minUs` and `maxUs` cover the whole run of the agent process. They are not reset by an interface switch, like `protocol_hierarchy_update`.
- `medianUs`/`p95Us` are nearest-rank percentiles (always an observed value, never interpolated) over the most recent `sampleCount` answered requests, at most 1,024 (`transaction::RECENT_SAMPLES`).
- `minUs`, `maxUs`, `medianUs` and `p95Us` are omitted, not zero, until a response has been matched.
- Times are measured at the capture point: server processing plus one network round trip from where the capture runs.

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
- `unparseableFrames` is a fourth, independent signal: a cumulative count of frames the agent *did* receive from the capture handle but couldn't decode (e.g. malformed/truncated input or known encapsulation beyond the decoder nesting limit or opaque MACsec). Successfully framed non-IP Ethernet traffic (including ARP and unknown non-IP EtherTypes) is intentionally excluded: it is outside IP flow analysis, not evidence of degraded capture. Unlike `dropped`/`if_dropped`, counted frames did reach this process; unlike `relayLaggedEvents`, this has nothing to do with the relay's outbound side. The dashboard labels these as "frame(s) could not be parsed (non-IP traffic excluded)". The wire field name and shape are unchanged.

  Visibility trade-off: excluded ARP, LLDP, and 802.3/LLC traffic (such as STP) produces no packet/flow events and has no dedicated wire counter. This fixes misleading capture-health warnings without expanding the Rust/TypeScript contract; it does not provide non-IP traffic visibility. Ethernet padding on an otherwise decodable ARP frame does not change its classification. Unknown EtherType and LLC payload contents are not validated or certified valid. Encrypted/modified MACsec remains a decode failure because its opaque payload could contain IP; decodable cleartext MACsec follows its inner protocol.

  Capture truncation and decode failure are separate decisions. The existing capture-length check runs before classification and still reports when captured length is less than original length. A cut non-IP frame remains excluded from `unparseableFrames` if the available framing/known headers decode successfully; a cut Ethernet, VLAN, or ARP header that fails decoding still increments the counter and emits a malformed-frame finding. An authenticated replay regression covers cut LLDP framing with the truncation warning preserved and no added parse-failure count.
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
  "status": {
    "interface": "lo",
    "capturing": true,
    "mode": "replay",
    "replaySource": "/Users/me/captures/incident.pcapng",
    "directionAttributionUnavailable": false
  }
}
```

Note the nesting: fields sit under a `status` key, same shape as `capture_stats`'s `stats`/`capture_file_status`'s own `status` — not flat on the event. `mapAgentStatusEvent` (`lib/agent-mapping.ts`) owns this unwrap, mapping to `AgentStatus` (`lib/types.ts`).

This section previously documented the event as flat, and `mapAgentStatusEvent` was written to match the doc rather than the agent (JAM-150). It never worked against a real agent: every tick threw `missing required field "interface"` into the SSE handler's catch, so the live/replaying/disconnected banner never left its default state. Corrected to what `capture-agent/src/wire.rs`'s `AgentStatus { status: AgentStatusJson }` has always emitted.

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
    "direction": "client_to_server",
    "streamId": 3,
    "redacted": false,
    "dataBase64": "OmF1dGhvcml0eTogZXhhbXBsZS5jb20="
  }
}
```

Field notes:
- `connectionId` — matches `connection_update`'s `id`, so the browser can associate decrypted content with the connection/packet stream it belongs to.
- `direction` — `client_to_server` or `server_to_client`, derived from the endpoint that sent ClientHello.
- `streamId` (optional) — the HTTP/2 stream ID this frame belongs to; absent for content the agent couldn't attribute to a specific stream.
- `redacted` — `true` if this event's `dataBase64` decodes to a `[REDACTED]` placeholder (sensitive header name or bearer-token-shaped value; see `capture-agent/src/redact.rs`). The redaction pass runs on parsed HTTP/2 headers only — body content is never redacted (named limitation, not a bug).
- `dataBase64` — base64-encoded UTF-8 text: either a decrypted HTTP/2 header block (`Name: value` pairs joined by `\n`, after redaction) or a decrypted HTTP/2 DATA frame body.

**Refused outright over any non-loopback listener; once served through the LAN-access Caddy mTLS proxy (`deploy/`), requires the `X-Mtls-Verified: true` upstream header** — see `lib/decrypted-payload-gate.ts`'s `isDecryptedPayloadAllowed` (used by `app/api/stream/route.ts`; kept in its own module rather than exported from the route file because Next.js's typed-routes build step rejects non-standard exports from `route.ts`). A request with no such header at all (direct loopback, no Caddy in front) is allowed; a request proxied through Caddy without a verified client cert is refused. This is the same event type in both cases — the gating happens relay-side, per-connection, not by the agent withholding the event.

TLS records are reconstructed from in-order TCP bytes per direction. Each direction has its own traffic secret, record sequence, and HTTP/2/HPACK decoder. Unsupported suites and missing keys produce `decryption_status`; a TCP gap or authentication failure ends decryption for that direction so unauthenticated or misordered content is never emitted.

### `decryption_status`

This additive event reports why opted-in traffic cannot be decrypted. It contains no ciphertext, plaintext, or key material and is not subject to the `decrypted_payload` rendering gate.

```json
{
  "type": "decryption_status",
  "status": {
    "connectionId": "Tcp-192.168.1.10:51000-93.184.216.34:443",
    "direction": "server_to_client",
    "status": "desynchronized",
    "reason": "tcp_gap"
  }
}
```

`status` is `unavailable` for a missing key, unsupported cipher, unobserved handshake, or budget eviction; it is `desynchronized` when record boundaries or authentication can no longer be trusted. Reasons are bounded agent values (`no_key`, `unsupported_cipher`, `handshake_not_observed`, `evicted_budget`, `early_data_unresolved`, `tcp_gap`, `capture_truncated`, `overlap_conflict`, `record_invalid`, `record_overflow`). Consumers should tolerate future reason strings.

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

For a new packet field, register it in `capture-agent/src/fields.rs` (`eth_fields`, `ip_fields`, `transport_fields`, or `app_fields`) instead of adding a new wire struct. `WireField` in `lib/types.ts` and `mapPacketEvent` in `lib/agent-mapping.ts` already accept any registered path with an existing field type. Check that its byte range points into the correct hex pane and document the new stable path here.

Live capture omits TCP traffic between loopback peers involving the agent's `127.0.0.1:9990` endpoint before reassembly, packet/flow output and raw recording, so the plaintext authentication credential cannot escape as captured payload. IPv4 TCP fragments involving `127.0.0.1` and another loopback address lack reliable port attribution; these rare live fragments are conservatively omitted too. Other unfragmented loopback traffic, non-TCP fragments, non-loopback traffic and all replay frames retain their existing handling. Kernel capture counters may include omitted transport frames. This does not prevent a separately privileged packet sniffer from observing the plaintext loopback handshake.
