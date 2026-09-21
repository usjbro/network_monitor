# capture-agent

Real packet capture agent for the OSI Traffic Terminal Monitor. Runs as
your normal user — no `sudo` needed at runtime — once you've done the
one-time setup below.

## One-time setup

Add your user to macOS's `access_bpf` group so this binary can open
`/dev/bpf*` without elevated privileges:

    sudo dseditgroup -o edit -a $(whoami) -t user access_bpf

Log out and back in (or reboot) for the group membership to take effect.

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

See [../docs/wire-protocol.md](../docs/wire-protocol.md) for the full JSON
event contract this binary produces.

## Replaying a capture file instead of live traffic

Set `REPLAY_FILE` to a path before starting the agent to read a previously
captured file through the same pipeline live traffic uses — same wire
events, same UI, no special cases. Accepts this agent's own pcapng output,
another tool's pcapng, or classic pcap/`tcpdump`:

    REPLAY_FILE=~/captures/incident.pcapng cargo run --release

`REPLAY_FILE` is mutually exclusive with `CAPTURE_INTERFACE`; setting both
is a startup error naming both values rather than a silent precedence rule.

Two companions, both optional:

- `REPLAY_LOCAL_ADDRS` — a comma-separated list of addresses to treat as
  local, so rx/tx direction can be attributed. Without it (and without an
  address option in the file's own Interface Description Block) the agent
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

All five are read once, at startup, and fail loudly on a value that is set
but unusable rather than silently falling back. An empty or whitespace-only
value is treated as unset. See [../docs/architecture.md](../docs/architecture.md)'s
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
