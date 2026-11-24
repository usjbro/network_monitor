# capture-agent

Real packet capture agent for the OSI Traffic Terminal Monitor. Runs as
your normal user — no `sudo` needed at runtime — once you've done the
one-time setup below.

## One-time setup

Add your user to macOS's `access_bpf` group so this binary can open
`/dev/bpf*` without elevated privileges:

    sudo dseditgroup -o edit -a $(whoami) -t user access_bpf

Log out and back in (or reboot) for the group membership to take effect.

## Agent credential handoff

Run the agent and Next.js relay under the same Unix user. The agent publishes a fresh private credential at `$HOME/.network-monitor/agent-control-token` each launch; the relay reads it automatically on each reconnect. No manual token copying is needed. For a custom location, configure the same absolute `AGENT_TOKEN_FILE` in both processes and create its immediate parent with mode 0700 under that user's ownership. The final credential is a regular, owner-only 0600 file, with no symlink or hard-link handoff. macOS ancestor aliases such as `/var` are supported. Unsafe credential locations prevent startup; missing/unsafe credentials leave the relay disconnected. Do not print the token or pass its contents in command arguments.

## Running

    cargo run --release

Listens on `127.0.0.1:9990` for the Next.js relay to connect to. Auto-detects
the interface carrying your default route (via `route -n get default`,
cross-referenced against `pcap::Device::list()`) — check the startup log
line ("using interface en0") to confirm it picked the right one; see
[../docs/troubleshooting.md](../docs/troubleshooting.md#wrong-interface-detected)
if not (a VPN client is a common cause — it becomes your default route but
usually isn't visible to packet capture).

To force a specific interface instead of auto-detecting, set
`CAPTURE_INTERFACE` (an empty/blank value is treated as unset):

    CAPTURE_INTERFACE=en0 cargo run --release

This wins over auto-detection, and fails loudly rather than silently
falling back to it — including if the name doesn't match any interface
pcap can see, or matches one with no assigned address (which would
otherwise silently capture nothing: see `flow.rs`'s `FlowTable::is_local`).
The error lists what pcap actually found, except when listing itself is
what failed. Note `pcap::Device::list()` is the authority here, not
`ifconfig -l` — they're usually the same set, but `access_bpf` scoping can
make them differ.

## Flow-table capacity (`MAX_FLOWS`)

The flow table tracks at most 10,000 concurrent flows by default, which
bounds memory under a SYN flood, port scan, or spoofed-UDP burst — each
distinct (local, remote) pair would otherwise hold a `FlowState` for up to
30 minutes regardless of intent. Override it for a genuinely busy link, or
lower it on a memory-constrained box, with `MAX_FLOWS`:

    MAX_FLOWS=50000 cargo run --release

An empty/blank value is treated as unset, same as `CAPTURE_INTERFACE`. A
value that's set but unusable — not a number, negative, or `0` (a
zero-capacity table evicts every flow the instant it's inserted, which
looks like a total capture failure rather than a setting) — fails loudly at
startup rather than silently falling back to the default.

When the ceiling is actually reached, the UI says so: the Connections view
surfaces the agent's capacity-eviction count separately from ordinary idle
turnover, since the former means the flow table may be missing recent
activity.

## Rollup limits (`MAX_ENDPOINTS`, `MAX_CONVERSATIONS`, `ROLLUP_TOP_N`)

The Hosts view's totals come from two tables, 50,000 remote hosts and 50,000
local/remote pairs by default. At its cap a table evicts the key whose last
packet arrived longest ago. Each second the agent sends the union of the top
200 keys by bytes, packets, rate and most recent activity, plus counts of
what that leaves out. The caps accept 1 to 500,000 and `ROLLUP_TOP_N` 1 to
1,000; blank is the default, and anything else fails startup naming the
variable. A cap reserves no memory up front. An interface switch clears both
tables. The counts' meaning is in
[../docs/wire-protocol.md](../docs/wire-protocol.md).

Measured on one Apple M3 laptop, with both tables full at 50,000, N=200 and
IPv6 remotes: the two snapshot calls took 1.1 ms (median) under the flow-table
lock on mixed traffic and 2.6 to 2.7 ms on scan traffic, against 7.5 ms and
4.7 to 7.2 ms for the unbounded code in the same runs. Both tables held about
25 MiB of live requested bytes after churn, measured before the final
selection change and excluding the snapshot's temporary buffers. Linux, live
traffic, resident memory and the rest of the per-tick work are not measured,
and no traffic shape is proved to be the worst. Higher caps cost more: at
500,000 the same calls took 4.2 ms on mixed traffic and the tables about
268 MiB. Method and limits:
`docs/superpowers/specs/2026-11-23-rollup-bounds-design.md`.

See [../docs/wire-protocol.md](../docs/wire-protocol.md) for the full JSON
event contract this binary produces.

## Follow Stream (`FOLLOW_STREAM`, `RELAY_PORT`, `FRONT_DOOR_PORT`)

Follow Stream (KAN-110, in progress) retains a selected TCP flow's bytes so
the UI can show the conversation. It is off unless the agent starts with
exactly `FOLLOW_STREAM=1`; unset, empty or any other value leaves it off.
With it on, the agent keeps the start of each TCP conversation in a bounded
in-memory store (at most 256 flows and 16 MiB, credentials masked on every
copy out), dropping a flow's bytes when the flow table drops the flow and
emptying the store on an interface switch. The agent answers `get_stream`
on its authenticated control connection only (`docs/wire-protocol.md`); no
relay route asks yet, so the UI cannot show a stream until a later task.

With it on, the relay's own HTTP traffic would carry retained content back
over loopback, so live capture drops it before reassembly, flow events and
raw recording. `RELAY_PORT` names the port the Next.js relay serves on
(default 3000). It selects traffic to exclude; it never changes what the
agent binds. Only the agent reads it. To run the relay on another port,
start both with the same port:

    cd capture-agent && RELAY_PORT=3100 FOLLOW_STREAM=1 cargo run --release --locked
    npm run dev -- -p 3100          # from the repo root; production: PORT=3100 npm run start

If `next dev` moves to 3001 because 3000 is taken, the agent still excludes
3000; relaunch it with `RELAY_PORT=3001`. A later task makes the agent
refuse stream requests from a relay on a port it does not exclude, instead
of trusting that the two settings agree. Two other components assume 3000
and do not read `RELAY_PORT`: the mTLS front door's `reverse_proxy
127.0.0.1:3000` in `deploy/Caddyfile` (change it by hand, following
`deploy/README.md`), and `npx osi-inspect`, which posts to
`OSI_INSPECT_RELAY_URL` (default `http://127.0.0.1:3000`).

The mTLS front door re-serves the same content, encrypted, on its own port,
so live capture also drops `FRONT_DOOR_PORT` (KAN-294; default 8443, the
port in `deploy/Caddyfile`). That covers a browser on this host reaching the
front door over loopback or by this host's own LAN address (both ends the
same address). Another LAN client's session with the front door is kept:
it is not this host's own content, and its keys never reach the agent.
Caddy also serves HTTP/3 on that port over UDP, which is dropped too.

The front door's port is a separate setting from Caddy's, and nothing checks
they agree; the agent logs the two ports it excludes at startup. After
`deploy/README.md` step 5 (site address `:443`) start the agent with
`FRONT_DOOR_PORT=443`, and match any other `CADDY_LISTEN_ADDR` port the same
way.

Costs: with Follow Stream on and no front door running, a loopback app of
your own on 8443 is hidden; set `FRONT_DOOR_PORT` to an unused port. The
same-address rule trusts the packet's addresses, so a forged packet from
one address to itself on a follow port is hidden too, and so are that
pair's fragments.

With Follow Stream on, `RELAY_PORT` and `FRONT_DOOR_PORT` must each be a
plain decimal port from 1 to 65535 (no sign or spaces), or startup fails
naming the variable. With it off, neither is read, so a bad value cannot
stop the agent and a loopback app on port 3000 or 8443 stays visible. The
check also runs in replay, which excludes nothing, so a replay started with
`FOLLOW_STREAM=1` and a bad port fails too.

Visibility cost: a fragmented IP packet's later fragments carry no ports,
so with Follow Stream on, live capture drops every loopback TCP fragment
(IPv4 and IPv6) and every loopback packet whose transport could not be
decoded (which includes IPv6 fragments and IPv4 fragments carrying AH).
Loopback TCP, UDP and ICMP on other ports stays visible. Replay is never
filtered.

## Replaying a capture file instead of live traffic

Set `REPLAY_FILE` to a path before starting the agent to read a previously
captured file through the same pipeline live traffic uses — same wire
events, same UI, no special cases. Accepts this agent's own pcapng output,
another tool's pcapng, or classic pcap/`tcpdump`:

The pcapng reader supports Enhanced Packet Blocks on Ethernet, loopback and
raw-IP interfaces, including multiple interfaces and concatenated sections
with either byte order. Unknown non-packet blocks are skipped after framing
validation; embedded decryption secrets are never imported. Simple Packet
and obsolete Packet blocks report an explicit unsupported-format error.
Malformed replay data reports `replay failed` on stderr rather than a clean
`replay finished` message. Each block is limited to 16 MiB; each section to
4096 interfaces and 16 MiB of retained interface names.

Timestamp offsets, recorded FCS lengths and interface-address options are
not yet applied. The session's interface label comes from the first
supported interface description; packet decoding uses each packet's own
interface.

    REPLAY_FILE="/tmp/network-monitor-captures/incident.pcapng" cargo run --release

Record that file first using the [analysis guide](../docs/analysis-guide.md#record-open-and-replay-a-capture), or substitute an existing capture. This environment assignment runs in a shell, unlike browser command-bar capture paths; shell quoting supports spaces here.

`REPLAY_FILE` is mutually exclusive with `CAPTURE_INTERFACE`; setting both
is a startup error naming both values rather than a silent precedence rule.

Two companions, both optional:

- `REPLAY_LOCAL_ADDRS` — a comma-separated list of addresses to treat as
  local, so rx/tx direction can be attributed. Without it the agent
  falls back to positional attribution and says so: `agent_status` carries
  `directionAttributionUnavailable: true` for the whole session, and the UI
  captions the replay banner accordingly.
- `REPLAY_SPEED` — `realtime` paces frames by their recorded timestamps;
  anything else (the default) replays as fast as the pipeline accepts.

Replay is a startup-only choice. There is no runtime switch between live
and replay, deliberately — see `docs/superpowers/specs/`.

Note that process attribution is meaningless for a replayed file: the
processes that owned those flows may never have run on this machine. The
agent doesn't guess, so every connection reports `processName: "unknown"`
with `pid: 0`.

## Environment variables

| Variable | Effect | When read |
| --- | --- | --- |
| `CAPTURE_INTERFACE` | Force a specific capture interface instead of auto-detecting | Startup |
| `REPLAY_FILE` | Replay this capture file instead of capturing live (mutually exclusive with `CAPTURE_INTERFACE`) | Startup |
| `REPLAY_LOCAL_ADDRS` | Comma-separated local addresses, so replay can attribute rx/tx direction | Startup |
| `REPLAY_SPEED` | `realtime` to pace by recorded timestamps; otherwise as fast as possible | Startup |
| `MAX_FLOWS` | Flow-table capacity ceiling (default 10,000) | Startup |
| `MAX_OBSERVED_DNS_NAMES` | Observed DNS name table capacity (default 16,384) | Startup |
| `MAX_ENDPOINTS` | Remote hosts tracked (default 50,000, 1 to 500,000) | Startup |
| `MAX_CONVERSATIONS` | Local/remote pairs tracked (default 50,000, 1 to 500,000) | Startup |
| `ROLLUP_TOP_N` | Top-N sent per ranking (default 200, 1 to 1,000) | Startup |
| `FOLLOW_STREAM` | `1` turns on Follow Stream; anything else leaves it off | Startup |
| `RELAY_PORT` | The relay's port, excluded from live capture (default 3000); read only with `FOLLOW_STREAM=1` | Startup |
| `FRONT_DOOR_PORT` | The mTLS front door's port, excluded from live capture (default 8443); read only with `FOLLOW_STREAM=1` | Startup |

All twelve are read at most once, at startup (`RELAY_PORT` and
`FRONT_DOOR_PORT` only with `FOLLOW_STREAM=1`). Invalid `CAPTURE_INTERFACE` and nonpositive/non-numeric
`MAX_FLOWS` or `MAX_OBSERVED_DNS_NAMES` fail startup, as does a
non-numeric or out-of-range `MAX_ENDPOINTS`, `MAX_CONVERSATIONS` or
`ROLLUP_TOP_N`; blank values are unset, except the two ports: with `FOLLOW_STREAM=1`, unset is the default,
and blank or invalid fails startup. `REPLAY_FILE` must name a readable supported file.
`REPLAY_LOCAL_ADDRS` only splits/trims strings, and only exact
`REPLAY_SPEED=realtime` selects pacing; other speed values select fast mode.
See [../docs/architecture.md](../docs/architecture.md)'s
Resource limits table for every cap in the system, not just the
configurable ones.

## Beyond the base flow table

This binary also does three further things, each documented in more depth
elsewhere:

- **JA3 fingerprinting** (`src/ja3.rs`) — informational, computed from
  observed TLS ClientHellos, always on (no opt-in needed since it's derived
  from data already being parsed).
- **Opt-in TLS decryption** (`src/keylog.rs`, `src/tls_decrypt.rs`,
  `src/http2.rs`, `src/redact.rs`, `src/ring_buffer.rs`) — decrypts one
  process's TLS traffic at a time, only once that process is registered as
  decrypt-eligible over the control channel. Registration is driven
  externally by `../bin/osi-inspect.js`, not by this binary directly — see
  [../docs/getting-started.md](../docs/getting-started.md#optional-features)
  and [../docs/superpowers/specs/2026-08-29-tls-interception-design.md](../docs/superpowers/specs/2026-08-29-tls-interception-design.md).
- **On-demand ICMP traceroute** (`src/traceroute.rs`) — a bounded,
  unprivileged-ping-socket traceroute, triggered per-connection from the UI,
  never started by the agent on its own. See
  [../docs/geoip-protocol.md](../docs/geoip-protocol.md).
