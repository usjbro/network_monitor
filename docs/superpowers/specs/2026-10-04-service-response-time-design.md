# Request/Response Matching and Service Response Time — Design Spec

**Issue:** JAM-15 (GitHub #82): "Request/response matching and service response time (DNS, HTTP)". Closes #65.
**Epic:** JAM-127 (Analysis surfaces)
**Builds on:** JAM-16 stream reassembly (a request line split across segments resolves), JAM-12 findings, JAM-9 field registry, JAM-10 display filters.

## Problem

The only timing the product measures is the TCP handshake RTT (`flow.rs`, SYN to SYN-ACK). That measures the network, not the service. Nothing links a response to its request, so the tool can't distinguish "the network is slow" from "the DNS resolver is slow". DNS responses weren't decoded at all: a response's echoed question was reported as though it were a query.

## What ships

1. **DNS response decoding** (`l7.rs`). A new `L7Info::DnsResponse` carries the transaction ID, RCODE, ANCOUNT and up to 16 decoded answer records (A, AAAA, CNAME/NS/PTR data; other types by name and TTL only). `L7Info::Dns` gains `id` and `qtype`. Names follow compression pointers, with a hop cap (16) and the RFC 1035 255-octet length cap, so a pointer loop ends the decode rather than the thread.
2. **A request/response matcher** (`transaction.rs`, `TransactionTracker`):
   - DNS: keyed on (flow, transaction ID). A response must travel the opposite way to its query and echo its question name (case-insensitive). Only unicast DNS over UDP port 53 is tracked.
   - HTTP/1.x: a FIFO per connection (RFC 9112 §9.3.2: responses come back in request order). A final response answers the oldest outstanding request and must travel the opposite way. Interim `1xx` responses (other than `101`) don't consume it.
   - Duplicate DNS responses within the timeout window are recognized as duplicates. A repeated query keeps the first attempt's send time. A TCP-retransmitted request segment is not queued again.
3. **Service time as filterable fields**: `dns.time_us`/`http.time_us` (uint, microseconds), `dns.response_to`/`http.response_to` (the request's packet-event id), and `dns.response.duplicate`.
4. **Unanswered requests are a finding**: `unanswered-request`, once per request, after 5 s (DNS) or 30 s (HTTP) of capture time. Then the request is forgotten.
5. **A per-protocol latency summary**: a `service_time_update` tick event with answered/unanswered/untracked counts, exact min and max, and nearest-rank median and p95 over the most recent 1,024 answers. Shown as a table under the protocol view (F5).
6. **The visible link**: matched response rows in the packet list carry a `↩ <time>` badge. The inspector links a response to its request and a request to its response, either way round, and says so when the other side is no longer buffered or is hidden by the current filter.

## Clock

Service time and timeouts both run on the frames' own capture timestamps (pcap's per-frame time), not the agent's wall clock:

- In replay, `REPLAY_SPEED=fast` would otherwise compress every service time toward zero. Recorded times are the traffic's real times.
- Live, pcap timestamps are taken in the kernel at receive, which is closer to the wire than the moment the capture thread got to the frame.
- A quiet live capture still times requests out: the capture loop's 1 s read timeout sweeps on wall-clock time, which is the same timeline as live pcap timestamps. Replay never hits that timeout, so a request still pending when the file ends is never reported. Its timeout hadn't elapsed inside the capture.

## Bounds

| What | Bound | At the bound |
| --- | --- | --- |
| Pending requests, all flows | 4,096 | New request counted `untracked`, not stored |
| Outstanding requests per HTTP connection | 32 | Same |
| Remembered answered DNS transactions (duplicate detection) | 4,096, each for 5 s | Not remembered; a later duplicate reads as unmatched |
| Decoded answers per DNS response | 16 | `dns.count.answers` still reports the header's count |
| Samples kept for percentiles, per protocol | 1,024 | Oldest dropped; count, min, max stay exact |
| Timeout sweep | at most every 500 ms of capture time | — |

Refusing a new request at a bound, rather than evicting an old one, is deliberate: the old ones expire on their own schedule. Eviction would turn a flood into a stream of false "unanswered" findings for requests that were really just dropped from memory.

## Security

- Every byte decoded is attacker-shaped. The DNS decoder indexes only through `get` and checked slices. A dedicated fuzz target (`l7_transactions`) drives the decoder and the matcher with arbitrary message sequences and asserts the pending bound holds.
- Request text that reaches a finding's `summary` (a DNS name, an HTTP method and path) is display-safe: anything other than printable ASCII is escaped as `\u{..}`, and it is cut at 120 characters. An ANSI sequence or a bidi override in a captured path arrives as visible text, never as instructions to a terminal.
- The UI renders every new value as React text. Nothing is interpreted as markup.
- No new path to decrypted content. Matching runs on the same `L7Info` cleartext sniffing already produced, and TLS flows are not matched.
- A spoofed "response" must match flow, direction, transaction ID and question name before it can claim a query. A spoofed response that does all four is indistinguishable on the wire from a real one. That is out of scope for a passive monitor.

## Deliberate deviations from the issue text

- **Pending state lives in a capture-thread tracker, not in `FlowState`** (the issue's scope item 3). `FlowTable` is shared with the periodic emitter behind a mutex, and its flow eviction would silently drop pending requests instead of reporting them. The tracker follows `StreamReassembler`'s pattern: owned by the capture thread, keyed on `FlowTable::key_for`, reset on a runtime interface switch (JAM-183).
- **Service time is `*.time_us` in microseconds**, not seconds. The display filter language compares integers only.
- **Only HTTP/1.x and UDP DNS.** HTTP/2 streams, DNS over TCP and mDNS/LLMNR are excluded, for the reasons above. HTTP/2 needs per-stream matching through `http2.rs` and is its own follow-up.
- **The request isn't annotated with its response.** Its packet event has already been sent when the response arrives, and the wire has no way to amend a sent packet. The UI derives the forward link from the buffered response's `response_to` instead.

## Not done here

- Per-host service-time breakdown (for example, which resolver is slow). The summary is per protocol.
- An HTTP/2 matcher.
