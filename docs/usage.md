# Usage

## Views

Switch between views with the tab bar, or the command bar (see below).

### Dashboard (`dash`)

The landing view: per-OSI-layer throughput sparklines and a "Protocol Health" indicator.

- **Protocol Health** shows "99.8% Efficiency" (NOMINAL) when the current average retransmission-based error rate across layers 3/4/7 is under 0.2%, or "Retransmit Anomaly" (ATTENTION) above that. This is a heuristic, not a precise measurement — see [troubleshooting.md#retransmit-anomaly](troubleshooting.md#what-does-retransmit-anomaly-mean) before treating it as a real network problem.
- "Open streams" reflects the transport-layer (L4) active connection count.

### Layer detail (`layer <1-7>`)

Drill into one of the 7 OSI layers (1 = Physical, 7 = Application) for its protocol list, throughput, and health status. Layers the agent can independently measure (3, 4, 7) show real numbers; layers 1, 2, 5, 6 show zero, honestly, rather than a fabricated value — this agent doesn't have a way to separately measure link-layer, session-layer, or presentation-layer volume distinct from the IP/transport bytes it already counts.

### Connections (`conn` / `sockets` / `connections`)

The live socket table: every active flow the agent has observed, with local/remote address and port, the owning process (name + PID, via `lsof`), transport protocol, throughput, RTT, retransmission-based loss %, and status (`ESTABLISHED`, `SYN_SENT`, `TIME_WAIT`, `CLOSE_WAIT`).

Note: flows currently never expire from this list for the lifetime of the agent process (tracked as [issue #28](https://github.com/usjbro/network_monitor/issues/28)) — a long-running agent will accumulate stale entries.

Three additional pieces of detail live here, all read-only until you interact with them:

- **JA3 fingerprint** — a short label next to a connection's encryption info once the agent has observed that flow's TLS ClientHello. Informational only; treat it as "roughly what TLS client made this connection," never as an authenticated identity (JA3 is trivially spoofable by any TLS client).
- **Ownership lookup** — trigger a WHOIS/RDAP lookup for a connection's remote IP/domain to see the owning organization. Off by default; turn it on with `enrich on` in the command bar first (see below) — the trigger does nothing while enrichment is off.
- **Trace Route button** — runs an on-demand ICMP traceroute to that connection's remote address and renders the result as a per-hop table (RTT, and — if you also enable it — a rough geographic location per hop). Bounded agent-side to 30 hops / 45s total; a trace that doesn't complete within that window just stops, it doesn't hang the UI. Per-hop location is a **separate** opt-in from ownership enrichment — every hop shows "location unavailable" until you run `geoip enable` in the command bar. Note this only affects *new* hop events: enabling it doesn't retroactively backfill locations for a trace that already finished, so click Trace Route again after enabling.

### Packet stream (`pcap` / `packets`)

A scrolling feed of the last 100 captured packets, with a hex dump of the first 64 bytes of payload. Per-layer header breakdown (parsed MACs, TLS SNI, HTTP method/path, DNS query name) is captured internally by the agent but not yet wired to this view — see [issue #29](https://github.com/usjbro/network_monitor/issues/29).

**Decrypted content**: normally TLS payloads only ever show as ciphertext. If you launched the process generating this traffic through the bundled `osi-inspect` CLI (see [getting-started.md](getting-started.md#optional-features)), packets for that process's connections render their actual decrypted HTTP/HTTP2 content here instead, behind a persistent "decrypting" banner so it's always obvious when you're looking at plaintext rather than the normal ciphertext view.

### Protocol matrix (`matrix` / `topology`)

A cross-tab of layers vs. protocols currently in use.

## Command bar

Type a command and press enter. Available commands:

| Command | Effect |
|---|---|
| `dash` / `dashboard` | Switch to the Dashboard view |
| `layer <1-7>` | Switch to the Layer Detail view for the given layer |
| `conn` / `sockets` / `connections` | Switch to the Connections view |
| `pcap` / `packets` | Switch to the Packet Stream view |
| `matrix` / `topology` | Switch to the Protocol Matrix view |
| `theme <name>` | Switch color theme (see theme list below) |
| `pause` | Tell the agent to pause capture (also available as a button in the header) |
| `resume` | Tell the agent to resume capture |
| `reset` | Clear the local connections/packets buffers (does not affect the agent) |
| `enrich on` / `enrich off` / `enrich clear` | Turn on-demand ownership (WHOIS/RDAP) lookups on/off for the current relay session (never persisted — off again after every relay restart), or wipe the local enrichment cache and query log |
| `enrich background on` / `enrich background off` | Turn whole-table background ownership lookups on/off, instead of only on-demand per-connection |
| `geoip enable` / `geoip disable` / `geoip clear` | Turn per-hop geoIP location lookups on/off for Trace Route (separate opt-in from `enrich`, also session-only), or wipe the on-disk geoIP cache |
| `filter <bpf expression>` / `filter clear` | Set (or clear) a BPF capture filter at the agent, e.g. `filter tcp port 443` — narrows what's captured at the source, applied live with no interruption. An invalid expression is rejected with libpcap's own error shown in a dismissible banner; the previous filter keeps running. Active filter always shown in the header. |
| `snaplen <bytes>` / `snaplen full` | Set (or restore, via `full`) the capture snap length in bytes, e.g. `snaplen 96` — truncates each captured frame past this many bytes, keeping headers while discarding payload. Applying this briefly reopens the capture (logged, expected). Active snap length always shown in the header. |
| `iface list` / `iface <name>` | List capturable interfaces (also available from the header's interface picker, which lazily loads the same list), or switch capture to one at runtime — no agent restart needed. Switching resets the active filter/snap length to their defaults and clears tracked connections (every existing flow belonged to the interface that just stopped being captured). An interface with no assigned address, or one this agent can't parse the link type of, is rejected rather than silently accepted. |
| `capture <path> [ring <mode> <n>] [autostop <mode> <n>]` / `capture stop` | Start (or stop) writing captured traffic to a pcapng file on disk at the agent, e.g. `capture ~/captures/incident.pcapng ring size 104857600 autostop duration 3600`. The path keeps its case exactly as typed. `ring` rotates to a new file after `<n>` bytes (`size`), seconds (`duration`), or packets (`count`); `autostop` ends the whole run after `<n>` seconds (`duration`) or bytes written (`totalSize`) — both optional and independent, and a bare `capture <path>` just writes one file until stopped. The agent refuses an unsafe path (anything under `.data/`, or inside its own working directory), a run started while one is already active, or a start with free space already below its 500MB floor. Active capture file always shown in the header. |
| `buffer packets <n>` / `buffer connections <n>` / `buffer decrypted <n>` | Adjust how many recent items *this browser tab* keeps for each view (defaults: 100 / 200 / 100). Purely client-side — nothing is sent to the agent, and the agent's own flow-table ceiling is the separate `MAX_FLOWS` environment variable below. Lowering a limit discards the excess immediately rather than waiting for the next event. Each view shows a "showing N of M observed" line so a capped list never silently stands in for far more traffic than it lists. |
| `install` / `macos` / `brew` / `curl` / `sw_vers` | Open the Install modal (see below) |

## Themes

10 terminal color themes, switchable via `theme <name>` or the header picker:

`sophisticated`, `macos_pro`, `macos_homebrew`, `iterm_snazzy`, `matrix`, `dracula`, `amber`, `cyberpunk`, `catppuccin`, `nord`

Example: `theme dracula`

## Install as an app

The header's install button offers two options:

- **PWA install** — uses the browser's native "install as app" prompt (Chrome/Edge/Safari support varies).
- **Standalone CLI script** — downloads a bash installer that writes a self-contained Node script mimicking the terminal UI, for use outside the browser. This is a separate, self-contained feature (`app/api/install/route.ts`) — it does not share state with the live-capture pipeline described in this doc; it's a cosmetic terminal-UI mimic, not a real capture client.
