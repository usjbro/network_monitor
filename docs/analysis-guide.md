# Analyse packets and connections

Use this guide to answer questions with the implemented UI. [Usage](usage.md) is the command and filter reference; [Getting Started](getting-started.md) covers installation and permissions. Commands in `text` blocks go in the **browser command bar**, not a terminal. Commands in `bash` blocks go in a terminal. Example addresses, process names and domains must be replaced with ones in your capture.

## Start live capture on the right interface

**Prerequisites:** complete the macOS `access_bpf` setup in [Getting Started](getting-started.md#one-time-setup), build the agent, and run agent and relay as the same Unix user for credential handoff. Linux loopback capture is exercised by CI with explicit capture capabilities; the macOS setup commands do not configure Linux, and there is no Windows setup here. Capture only traffic you are authorised to inspect; read [capture storage and sensitivity](security.md#capture-sensitivity-storage-and-legal-guidance).

1. From the repository root, start the agent in one terminal:

   ```bash
   cd capture-agent
   cargo run --release
   ```

2. In a second terminal at the repository root, start the relay:

   ```bash
   npm run dev
   ```

3. Open <http://127.0.0.1:3000>. Confirm the agent log names an interface and `127.0.0.1:9990`, and the disconnected banner clears. Generate ordinary traffic, then enter:

   ```text
   iface list
   ```

   Use the header interface picker to select the interface carrying the traffic of interest. For an interface actually listed as `en0`, the equivalent command is:

   ```text
   iface en0
   ```

**Read the result:** packets and connection rows should appear. Startup auto-selection follows the default route where possible; a VPN may select a tunnel instead of Wi-Fi/Ethernet. To select an interface at startup, run `CAPTURE_INTERFACE=en0 cargo run --release` from `capture-agent/` instead of the first command above. This environment variable and runtime `iface` switching are distinct mechanisms.

**If it fails:** check permissions, token handoff, traffic on the selected interface, and [wrong-interface troubleshooting](troubleshooting.md#wrong-interface-detected). Runtime switching rejects addressless/unsupported-link interfaces and retains the old interface on failure. A successful switch clears tracked flows and resets BPF/snap length; reapply those controls if needed. Both services stay on loopback; use the existing [mTLS deployment](../deploy/README.md) for LAN access.

## Which process is talking to this destination?

**Prerequisite:** live traffic visible on the selected interface. Enter:

```text
conn
display connection.process contains "curl"
```

Read **Process (PID)**, **Local Socket**, and **Remote Host / Socket**, then click a row for its OSI stack, encryption and JA3 details. The table contains observed TCP/UDP flows, not a complete operating-system socket inventory. Process attribution uses local process lookup; missing ownership can remain `unknown`, especially for short-lived processes. Replay always reports `unknown` / PID `0`.

To investigate one remote host instead, replace the filter:

```text
display connection.remote_addr == "93.184.216.34"
```

Connections quick search also matches protocol, process, IP and available hostname. Clear quick search and protocol buttons if a display-filter match count is positive but no rows appear. Use a display filter for ports; the quick-search placeholder mentions ports, but its current predicate does not search them.

For optional ownership information:

```text
enrich on
```

Then use the selected row's **Ownership** lookup. This is a relay-wide, session-only opt-in: WHOIS/RDAP queries send the remote IP/domain off-box to public services and may fail or be rate-limited. Cached results are attribution clues, not proof of who controls a connection. `enrich off` disables queries; `enrich clear` clears the cache and query log. GeoIP is a separate opt-in (`geoip enable`) for newly requested traceroute hops and also sends addresses off-box. **Trace Route** actively sends bounded probes; ordinary packet/flow analysis is passive. See [Security](security.md) before enabling either lookup.

## Narrow by port, transport or domain

**Prerequisite:** retained packet or connection rows. For connection ports/transport:

```text
conn
display connection.transport == "TCP" and connection.remote_port in {80, 443}
```

For packets in either direction on TCP port 443:

```text
pcap
display tcp.src_port == 443 or tcp.dst_port == 443
```

For UDP packets, use the decoded group:

```text
display udp
```

To find observed TLS ClientHello packets naming a domain:

```text
display tls.handshake.sni contains "example.com"
```

**Read the result:** only matching retained records are visible. The SNI example is substring matching, not a domain-boundary test, and identifies ClientHello metadata, not every packet in that TLS conversation. Note its endpoints, then filter by those addresses/ports to follow the flow. JA3 in connection details fingerprints ClientHello parameters; it is spoofable, shared across clients and not an authenticated process, user or destination identity.

**If nothing matches:** a handshake may predate capture, be outside the sampled buffer, be truncated, or have no decoded SNI. TLS ciphertext does not expose HTTP URLs. Packet-only fields have no value on connection rows; `connection.*` has no value on packets. One expression is shared by both views, so clear it when changing tasks:

```text
display clear
```

`display` runs in this browser tab, preserves buffered records and is reversible until those records age out. Invalid syntax leaves the last valid expression active. To reduce what reaches the agent pipeline and recording **from now on**, use BPF instead:

```text
filter tcp port 443
filter clear
```

BPF uses a different grammar. A rejected BPF expression leaves the previous filter running and shows an error banner. Clearing BPF cannot recover excluded traffic. Replay rejects live BPF/interface/snap-length changes; use display filters there.

## Inspect one packet and its protocol details

**Prerequisite:** a matching frame in **F4: LIVE PCAP** (`pcap`). Click the frame, then expand **HEADER FIELDS** and, when present, **APPLICATION FIELDS**. Select or hover a field to highlight its bytes; copy its abbreviation/value to construct a display expression. Read **HEADER BYTES** alongside **RAW HEX PAYLOAD DUMP**.

The header pane contains parsed link/IP/transport bytes. The raw payload pane contains at most the first **64 payload bytes**, not a full frame. Application fields can describe a range beyond those visible bytes. Derived timing fields have no corresponding byte range. See the authoritative [Packet field contract](wire-protocol.md#packet) for paths, types, offsets and decoding limits.

| Question | Packet field | Connection field |
| --- | --- | --- |
| Address | `ip.src`, `ip.dst`, `ip6.src`, `ip6.dst` | `connection.local_addr`, `connection.remote_addr` |
| TCP/UDP port | `tcp.src_port`, `tcp.dst_port`, `udp.src_port`, `udp.dst_port` | `connection.local_port`, `connection.remote_port` |
| TCP SYN observed? | `tcp.flags.syn` | No flag field |
| TLS hostname | `tls.handshake.sni` | No SNI display-filter field |
| DNS question | `dns.qry.name` | No DNS-question field |
| HTTP request | `http.request.method`, `http.request.uri` | No URL field |
| Frame length / process | `frame.len` / no process field | No frame length / `connection.process` |

For example:

```text
display tcp.flags.syn == true
display frame.len >= 100
```

**If fields are absent:** only actually decoded protocols contribute fields. Short snap length, fragments, unsupported protocols and encrypted content limit detail. Unknown paths parse but match no comparison, so copy a real field abbreviation rather than assuming Wireshark aliases exist. Packet quick search matches protocol, source, destination and summary; the layer selector narrows rows further.

To stop capture while inspecting, use `pause`, then `resume` when finished. Pausing also stops observation/recording during that interval; it is not a way to preserve a continuous capture. The packet view's **FREEZE** label currently only toggles its local status, so use the agent controls when you need capture to pause.

## Diagnose connection problems without inventing measurements

**Prerequisite:** use `conn`, clear any packet-only display filter, and reproduce the problem while capturing its beginning. Read the actual **Latency**, **Status**, **RX Speed** and **TX Speed** columns. Click **F6: FINDINGS** for grouped observations; frame/flow markers identify related observations. Clicking a navigable finding switches views; it does not automatically select the target row.

- **Latency** is the observed outbound TCP SYN-to-inbound-SYN-ACK interval at this capture point. It is not continuous RTT, ping latency or server processing time. UDP and unseen handshakes show `—`: missing is not zero.
- The UI says **`% loss`**, but the value is flagged retransmissions divided by observed payload-bearing TCP segments. Pure ACKs are excluded; repeated/older sequence numbers can also reflect duplicates or reordering. It is **not measured end-to-end packet loss**, and `0.00%` does not establish a loss-free path. The capture-degraded asterisk/tooltip does not convert it into a loss measurement. Active loss measurement is tracked separately in [JAM-70](https://linear.app/shmishmorshin/issue/JAM-70/packet-loss-measurement).
- **Capture drops** are missing observations at the kernel/driver, relay or writer, not evidence that the network lost those packets. Check the degradation banner and file-write status separately. A small denominator or one-sided capture makes retransmission percentages particularly unreliable.
- **SYN_SENT** without progress suggests no completing handshake was observed; check interface, direction, filtering and missing frames before blaming the remote host. **CLOSE_WAIT** accumulation indicates observed half-closes worth investigating, not a confirmed application leak. States are inferred from packets, not polled from the OS. Idle and capacity eviction remove old flows; default agent capacity is 10,000 (`MAX_FLOWS` at startup).
- **RX/TX Speed** counts observed traffic per interval relative to the chosen local side. It is not link capacity, application goodput or an active speed test. Replay pacing and capture visibility affect interpretation. Missing direction attribution makes RX/TX labels unreliable.

Findings such as retransmissions, resets and unanswered requests are diagnostic clues, not statements of cause or intent. No findings does not prove a healthy network. Dashboard **Protocol Health** is a retransmission heuristic, including the static “99.8% Efficiency” text; it is not a measured availability/efficiency percentage. OSI descriptions are static. Layers 1/2/5/6 show zero because the agent does not independently measure them; those zeros do not prove no traffic exists at those layers.

## Find top talkers and TCP/UDP conversations

**Prerequisite:** traffic has accumulated. Click **F7: HOSTS**, then choose **Endpoints** for hosts or **Conversations** for address pairs. The initial order is total bytes descending; click the Bytes/Packets/rate columns to sort and use the search box for an address, hostname or process. A selected row exposes ownership and available JA3 information.

**Read the result:** compare byte totals, packet totals, flow count and first/last seen; Conversations also shows duration. These are traffic rollups across TCP/UDP flows, not reassembled conversation text or an application transaction list. Rollups can outlive individual flow eviction. To inspect a particular socket, return to `conn` and apply address/port filters.

**If totals differ from visible rows:** the Hosts rollup and sampled/retained packet list cover different horizons. Display filters affect Packets and Connections, not Hosts. Capture/BPF/decoder omissions still limit rollups.

## Inspect DNS/HTTP metadata and response time

**Prerequisite:** observe both directions of unicast UDP DNS on port 53 or recognised plaintext HTTP/1.x. Click **F5: TOPOLOGY** (`matrix`) and read **SERVICE RESPONSE TIME** below the protocol matrix. It shows Answered, Unanswered, Untracked, Min, Median, p95 and Max.

For individual DNS responses or HTTP requests in `pcap`:

```text
display dns.flags.response == true
display http.request.method == "GET"
```

Expand application fields for DNS names, response codes/decoded answers, or HTTP method/path/status. Matched responses gain timing fields and request links:

```text
display dns.time_us >= 100000
display http.time_us >= 500000
```

**Read the result:** the examples select DNS responses taking at least 100 ms and HTTP responses taking at least 500 ms. Values are integer microseconds from request to response capture timestamps: service work plus the network path visible at the observer, not isolated server processing time. Median/p95 use the latest 1,024 answered samples per protocol; counts/min/max cover the capture's accumulated transactions. `—` / **Not measured yet** means unavailable, not zero. **Unanswered** means the matcher timed out (DNS 5 s, HTTP 30 s); **Untracked** means its bounded matching capacity was exceeded.

**If no timing appears:** DNS over TCP, mDNS/LLMNR, HTTP/2 and encrypted TLS are outside this transaction matcher. Missing requests, truncation, asymmetric capture and matching bounds also prevent timing. **Show request/response** can report that the peer is outside the buffer/current filter or was not emitted by the packet sampler. Clear display/quick filters first; increasing retention cannot recover already discarded packets.

## Record, open and replay a capture

**Prerequisites:** a running live agent, a writable directory outside the repository, and at least 500 MiB free. The path is on the **agent machine**, not the viewing device. In a terminal on that machine, create the example directory (inspect an existing directory's ownership/permissions before reuse):

```bash
umask 077
mkdir -p /tmp/network-monitor-captures
```

Then in the browser command bar:

```text
capture /tmp/network-monitor-captures/incident.pcapng
```

Generate traffic and confirm the header shows an active capture file with increasing bytes. While writing, the disk name is `incident.pcapng.partial`. Stop explicitly:

```text
capture stop
```

Wait for the active status to end and the final `incident.pcapng` file to appear. The file is created owner-only (`0600`). Use a fresh filename for each run: a pre-existing partial file prevents creation, and final rename may replace a pre-existing final file. `/tmp` is temporary storage; move captures to an operator-managed location if they must survive cleanup/reboot.

**Path rules:** this command bar is not a shell. It expands neither `~` nor `$HOME`, and splits capture arguments on whitespace without interpreting quotes or backslash escapes. Use an absolute path **without spaces**, exactly as above. Parent directories must exist. The agent rejects `..`, `.data/`, and paths resolving inside its own working directory, including symlink aliases. Do not quote the command-bar path; terminal paths in environment assignments below *can* be quoted because a shell handles them. [Usage](usage.md#capture-files-and-offline-replay) covers rotation/autostop.

**If recording fails:** read the capture-file error banner and agent log; check the directory, permissions, disk floor, existing partial files, and whether another recording is active. Confirm status rather than assuming a submitted command succeeded. Ring rotation keeps every numbered member; it never prunes old files. Stop/clean up captures yourself.

To open the file in this application, stop the live agent (Ctrl-C) and restart from `capture-agent/` with environment variables, substituting addresses that really were local in the recording:

```bash
REPLAY_FILE="/tmp/network-monitor-captures/incident.pcapng" \
REPLAY_LOCAL_ADDRS="192.168.1.10" \
REPLAY_SPEED=realtime cargo run --release
```

Unset any inherited `CAPTURE_INTERFACE` first: nonblank `CAPTURE_INTERFACE` and `REPLAY_FILE` conflict. The UI has no file-open dialog or runtime replay command. The replay banner identifies the file, and the same packet/connection recipes apply; process-based filters do not, because replay ownership is unknown. Without `REPLAY_LOCAL_ADDRS`, endpoints use stable canonical ordering and RX/TX direction is unavailable. Default `fast` playback can finish before a browser attaches; attach the relay/browser beforehand and use `realtime` for interactive inspection. Even realtime can finish quickly for a short capture.

Replay accepts supported pcapng and classic pcap on Ethernet, BSD loopback or raw-IP link types. See [replay formats and limits](../capture-agent/README.md#replaying-a-capture-file-instead-of-live-traffic). Simple/obsolete pcapng packet blocks and unsupported link types fail; embedded decryption secrets are not imported. The terminal says `replay finished` at EOF or `replay failed` for a read error. The connected/capturing indicator alone does not establish that replay is still reading. Restart to replay again/change files; restart without replay variables to return to live capture. [Troubleshooting](troubleshooting.md#replaying-a-capture-file-instead-of-live-traffic) explains pacing and attribution.

## Export the current analysis

**Prerequisite:** matching rows are visible after display filters and local search/refinements. In Connections, click **EXPORT CSV** for those displayed connection rows. In Packets, click **EXPORT JSON** for displayed frames and decoded fields. Select a frame and click **COPY HEX** to copy its available raw payload bytes; this is not the complete capture file. Browser download/clipboard failures require browser permission or retry.

**Read the result:** downloads contain the current retained subset, not the whole recording or a fresh server query. Connections CSV includes the observed/visible count comment, endpoints, process/PID, byte totals and status. JSON contains packet metadata, field trees and available hex bytes. Export excludes the separate opt-in decrypted TLS segments by construction. Decryption requires an explicitly wrapped process via `osi-inspect`; decrypted payloads stay in memory and are never written to capture files or exports. This does not remove ordinary plaintext HTTP/DNS or sensitive metadata from raw captures/exports. Review [Security](security.md#capture-files-epic-55) before sharing them.

## Understand the observation window

Packet events are sampled at most once per 10 ms (100/second); the browser initially retains 100 packets, 200 connections and 100 decrypted segments. `buffer packets 1000` or `buffer connections 1000` increases future retention, without restoring discarded data. Read the retained/observed counts and capacity warnings. `reset` clears this tab's connection, packet, decrypted and finding buffers; it does not reset agent counters, Hosts rollups or service-time statistics.

Recording occurs before packet-event sampling and preserves raw bytes up to the active snap length for eligible parsed frames. It is more complete than the dashboard feed, **not a guarantee of every wire frame**: BPF, pauses, kernel drops, writer queue drops, malformed/unsupported frames and live control-channel exclusions can omit data. `snaplen 96` truncates future frames and can prevent protocol decoding; `snaplen full` restores 65,535 bytes. Raw recording never adds the opt-in decrypted TLS stream. Watch capture-file drop counters as well as capture degradation. See [wire sampling and diagnostics](wire-protocol.md#packet).

Headless query CLI and saved filter/profile management are not yet available (JAM-29 and JAM-28). For permission/configuration problems, missing rows, unsupported links and capture failures, use [Troubleshooting](troubleshooting.md); a planned feature or a UI label alone is not evidence that a measurement exists.
