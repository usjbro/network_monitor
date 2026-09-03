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

See [../docs/wire-protocol.md](../docs/wire-protocol.md) for the full JSON
event contract this binary produces.

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
