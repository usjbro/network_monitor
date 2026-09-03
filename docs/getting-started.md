# Getting Started

## Prerequisites

- **Node.js** (for the web app)
- **Rust** (for the capture agent) — install via [rustup](https://rustup.rs) if you don't have it: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **macOS**, currently — the capture agent's privilege model (`access_bpf` group) and interface detection (`route -n get default`) are macOS-specific. Linux/Windows support isn't implemented.

## One-time setup

Real packet capture needs access to `/dev/bpf*`. Rather than run the agent as root, add your own user to macOS's `access_bpf` group once:

```bash
sudo dseditgroup -o edit -a $(whoami) -t user access_bpf
```

Log out and back in (or reboot) for the new group membership to take effect. After this, the agent never needs `sudo` again.

**Check if you already have it** (Wireshark's installer sets this up too, so you may already be done):

```bash
dscl . -read /Groups/access_bpf GroupMembership
```

If your username is in the output, skip the setup step above.

## Install and build

```bash
git clone https://github.com/usjbro/network_monitor.git
cd network_monitor
npm install
cd capture-agent && cargo build --release && cd ..
```

## Run it

You need **two processes running at once**, in two terminals.

**Terminal 1 — the capture agent:**

```bash
cd capture-agent
cargo run --release
```

(`capture-agent/README.md` covers the same one-time setup and running steps if you want the source-of-truth version — the in-app "agent not connected" banner links there too.)

You should see:

```
capture-agent: using interface en0
capture-agent: listening on 127.0.0.1:9990
```

Check that the interface it picked is right — it should be your actual Wi-Fi/Ethernet interface (`en0` is typical), not something like `ap1`/`awdl0`. If it picked the wrong one, see [troubleshooting.md](troubleshooting.md#wrong-interface-detected).

**Terminal 2 — the web app:**

```bash
npm run dev
```

Open **http://127.0.0.1:3000**. If the agent from Terminal 1 is running, you should see real connections, packets, and per-layer throughput appear within a second or two — try opening a few websites in another tab to generate visible traffic.

If the agent *isn't* running, the app still loads and shows a red "capture agent not connected" banner instead of failing — that's expected, not a bug.

## Verifying it's really working

A few sanity checks, if you want to confirm this isn't fake data before trusting it:

1. **Watch the Connections view** while you open a new website — a new row should appear with the real remote IP and the process name of your browser.
2. **Stop the agent** (Ctrl-C in Terminal 1) — the "agent not connected" banner should appear within a couple seconds, and reappear-and-clear automatically if you restart the agent (no page reload needed).
3. **Check the raw stream directly**, bypassing the UI entirely:
   ```bash
   curl -N http://127.0.0.1:3000/api/stream
   ```
   You should see a stream of `data: {"type":"connection_update",...}` / `"type":"packet"` / `"type":"layer_update"` lines.

## Optional features

Everything above is the core live-capture pipeline. Three further features exist, all opt-in and off by default:

- **Ownership enrichment** — type `enrich on` in the command bar to turn on WHOIS/RDAP lookups (who owns a remote IP/domain) for the current relay session. This is a runtime-only toggle: it's off again after every relay restart, and it makes outbound queries to public registrar/RIR servers, so only turn it on if you're comfortable with that. `enrich off` turns it back off; `enrich clear` wipes the local lookup cache. See [usage.md](usage.md) and [enrichment-protocol.md](enrichment-protocol.md).
- **Network path visualization** — click "Trace Route" on any connection in the Connections view to run an on-demand ICMP traceroute to it, rendered as a per-hop table. No setup needed: it uses an unprivileged macOS ping-socket, the same mechanism the base capture already relies on for its privilege model, confirmed working without `sudo` (see `docs/superpowers/specs/2026-09-01-path-visualization-privilege-spike-result.md`). Per-hop geoIP (rough location) is a further, separate opt-in on top of that — every hop shows "location unavailable" until you type `geoip enable` in the command bar, and (since it only affects new hop events, not a trace that already finished) you'll need to click Trace Route again afterward. See [geoip-protocol.md](geoip-protocol.md).
- **Decrypted TLS content** — normally the Packet Stream only ever shows ciphertext for HTTPS traffic. To see one process's actual decrypted content, launch that process through the bundled CLI instead of directly, with both the agent and relay already running:

  ```bash
  npx osi-inspect <command> [args...]
  # e.g.: npx osi-inspect curl https://example.com
  ```

  (Launching a browser this way needs an extra `--yes-decrypt-entire-browser` flag, since that decrypts everything the browser does, not just one request.) This sets `SSLKEYLOGFILE` to a fresh, ephemeral file for just that child process and registers it with the agent as decrypt-eligible — nothing else on your machine is affected, no CA is installed, and decrypted content is never written to disk. See [usage.md](usage.md#packet-stream-pcap--packets).

## Stopping

Ctrl-C both processes. Nothing runs in the background or as a system service — there's no persistent install step beyond the one-time `access_bpf` group membership.

## Next steps

- [usage.md](usage.md) — what each view shows, the command bar, themes
- [architecture.md](architecture.md) — how the pieces fit together
- [enrichment-protocol.md](enrichment-protocol.md) / [geoip-protocol.md](geoip-protocol.md) — the wire/control contracts for the two opt-in features above
- [troubleshooting.md](troubleshooting.md) — common problems and what they mean
