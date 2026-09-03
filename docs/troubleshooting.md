# Troubleshooting

## "capture agent not connected" banner won't go away

1. Is the agent actually running? Check Terminal 1 for `capture-agent: listening on 127.0.0.1:9990`. If it crashed or was never started, `cd capture-agent && cargo run --release`.
2. Is anything else listening on port 9990? `lsof -i :9990` should show exactly one `capture-agent` process. If something else is bound to that port, the agent will fail to start.
3. Restart the web app (`npm run dev`) if you started the agent *after* the web app and the banner doesn't clear within a few seconds on its own — this shouldn't normally be necessary (the relay reconnects automatically), but is a reasonable first thing to try if something seems stuck.

## Wrong interface detected

The agent auto-detects the interface carrying your default route. Check the startup log:

```
capture-agent: using interface en0
```

If it says something else — `ap1`, `awdl0`, `lo0`, `utun0`, etc. — that's the wrong interface and you won't see real traffic. Verify what your actual default-route interface is:

```bash
route -n get default
```

Look at the `interface:` line. The agent runs the same command internally and cross-references it against available capture devices (`pcap::Device::list()`), falling back to `pcap::Device::lookup()`'s own guess only if that fails.

**A VPN client is a common, deceptive case of this**: when a VPN is connected, it commonly becomes your actual default-route interface (a `utun*` device) — `route -n get default` genuinely reports it, and the agent picks it up correctly per its own logic, so nothing above looks wrong. But `utun*` tunnel interfaces are typically not visible to packet capture the way a real Wi-Fi/Ethernet interface is: the agent starts and reports "using interface utun8" with no error, then silently captures zero packets — every layer/connection stat stays at 0 indefinitely. Confirm this is what's happening with `curl -N http://127.0.0.1:3000/api/stream` (see [getting-started.md](getting-started.md#verifying-its-really-working)): if you only ever see `layer_update` events with everything zeroed, and no `packet`/`connection_update` events at all, this is almost certainly it.

**Override the auto-detected interface** by setting `CAPTURE_INTERFACE` before starting the agent — this wins over auto-detection, and fails loudly rather than silently falling back: if you name one that doesn't exist, if it has no assigned address (which would otherwise silently capture nothing, the same failure mode as above), or if the value isn't valid UTF-8.

```bash
CAPTURE_INTERFACE=en0 cargo run --release
```

Use the `route -n get default` output from *before* your VPN connected to find your real interface name (or `ifconfig -l` as a starting point — usually the same set `pcap::Device::list()` sees, but not guaranteed).

## No packets/connections appear at all, even though the agent says it's listening

- **Confirm real traffic is happening**: open a new website in a browser tab while watching the Connections view.
- **Confirm the agent can actually see packets**, independent of this app, using `tcpdump` as a baseline:
  ```bash
  sudo tcpdump -i en0 -c 5
  ```
  (substitute your real interface name). If this shows nothing either, the problem is your network/permissions setup, not this app.
- **Check `access_bpf` group membership** — see [getting-started.md](getting-started.md#one-time-setup).
- If you're running the agent inside some kind of sandboxed/virtualized shell environment (a container, a restricted CI runner, certain remote dev environments), raw packet capture may be blocked at that layer regardless of `access_bpf` — this app needs genuine, unsandboxed access to the network interface and to `/dev/bpf*`.

## What does "Retransmit Anomaly" mean?

The Dashboard's "Protocol Health" card shows "Retransmit Anomaly" when the average retransmission-based error rate across layers 3/4/7 crosses 0.2%. **This is a heuristic, not a precise TCP-loss measurement**, and it's normal to see it flicker on, especially on Wi-Fi. Two real reasons this happens even when nothing is actually wrong:

1. **Small sample sizes**: a short-lived connection with only a handful of captured segments turns "1 retransmit" into a large percentage instantly. A flow with 5 segments and 1 flagged retransmit reports 20% loss — that's not a meaningful signal on its own.
2. **Wi-Fi link-layer retries**: Wi-Fi retries frames at the radio layer, below TCP, before TCP ever notices anything was lost. Passive packet capture can see both the original transmission and its Wi-Fi-layer retry as two copies of the same logical segment — the detector (correctly, given what it can observe) counts the second copy as a retransmit, even though the actual TCP stack never experienced loss. This is a well-known limitation of capture-based retransmission detection on Wi-Fi versus wired Ethernet, not a bug specific to this app.

**What to do about it:** generally, nothing — it's informational, not an alarm. If you want to investigate a specific spike, check the Connections view for which flow(s) are driving it; local Apple-services traffic (device sync, push notifications) on short-lived connections is a common, harmless source of high-percentage-but-low-count spikes. If the noise bothers you, the threshold (`0.2%` in `components/DashboardView.tsx`) and the lack of a minimum-segment-count filter are both easy, contained changes — not made by default, since the current behavior is an honest (if noisy) reflection of what was actually captured.

## Build / dependency issues

- **`cargo: command not found`**: your shell's `PATH` doesn't include `~/.cargo/bin`. Either restart your shell after installing Rust (rustup normally handles this), or run `export PATH="$HOME/.cargo/bin:$PATH"` for the current session.
- **npm install fails or behaves unexpectedly**: use `npm ci` instead of `npm install` where possible (matches the committed lockfile exactly), and check you're not running with `ignore-scripts` disabled unexpectedly if a native-dependency build step is failing.
- **`npx tsc --noEmit` or `npm run build` fails after pulling changes**: run `npm install` again — a dependency may have changed.

## The Rust agent panics or crashes

This should not happen under normal operation — the parser is specifically hardened (every function returns `Option`/`Result`, never panics on malformed packet bytes, and is exercised by a `cargo-fuzz` target) because it processes untrusted, attacker-reachable network data. If you do hit a panic:

1. Note the exact panic message and, if possible, what traffic was happening at the time.
2. Please [open an issue](https://github.com/usjbro/network_monitor/issues/new) with the panic output — a genuine agent crash is a real bug (of exactly the kind the fuzz target exists to catch), not expected behavior.

## Numbers seem inflated or too fast

If speeds look wildly unrealistic (many multiples of what your actual connection could sustain), you may be running a build from before the "shared clock" fix — `capture-agent/src/main.rs`'s periodic emitter previously computed elapsed time incorrectly, inflating speed metrics by roughly 1000x. Make sure you're on a current build (`git pull && cd capture-agent && cargo build --release`).

## Ownership enrichment shows nothing, or is very slow

- **Is it actually on?** It's off by default and never persisted — type `enrich on` in the command bar first (see [usage.md](usage.md)). Check that it didn't silently turn back off across a relay restart.
- **First lookup for a given IP/domain is slower than subsequent ones** — results are cache-first with a 14-day TTL, so a repeat lookup should be near-instant; a fresh one goes out over the network and is deliberately rate-limited to one in-flight request with jitter between them, so a burst of lookups queues rather than firing in parallel.
- **Some IPs never resolve an owner** — the SSRF-hardened host allowlist deliberately rejects redirects/referrals pointing at loopback/internal addresses, and private/reserved IP ranges are filtered out before any query is even made (`lib/enrichment/scope-filter.ts`). Both are expected behavior, not bugs — see `docs/superpowers/specs/2026-08-28-ownership-enrichment-design.md` for the full allowlist and threat model.

## JA3 label is missing on a connection

The agent can only compute a JA3 fingerprint from an observed TLS ClientHello. If a connection predates the agent starting, or its handshake happened before the agent's flow table picked it up, there's nothing to fingerprint — this is expected, not a bug. Remember the label is informational and best-effort, never an authenticated client identity (see [security.md](security.md)).

## Trace Route hop table is empty or never finishes

- The agent bounds every trace to 30 hops and a 45s total timeout, enforced agent-side regardless of what the relay sends — if the destination is more than 30 hops away, or a hop along the way silently drops ICMP without ever replying, the trace stops without ever reaching the destination. That's the ceiling doing its job, not a hang.
- Some networks/firewalls rate-limit or drop ICMP Time Exceeded / Echo Reply packets entirely, which looks identical to "no hops appeared" from this app's side — try the same destination with the system `traceroute`/`ping` as an independent baseline.
- Traceroute is on-demand only; the agent never starts one on its own, so nothing appears until you click "Trace Route" on a specific connection.

## Trace Route hop table populates, but every row says "location unavailable"

This is expected, not a bug — per-hop geoIP is a **separate** opt-in from both Trace Route itself and ownership enrichment (`enrich`). Type `geoip enable` in the command bar, then **click Trace Route again** on that connection: enabling geoIP only affects hop events from a trace that runs *after* you enable it, it doesn't retroactively backfill locations onto a trace that already finished. See [usage.md](usage.md) and [geoip-protocol.md](geoip-protocol.md).

## Decrypted content isn't showing in the Packet Stream

- **Did you launch the process through `osi-inspect`?** This is the only way decryption ever turns on for a process — running it normally, even with the agent capturing its traffic, never decrypts anything. See [getting-started.md](getting-started.md#optional-features).
- **Are you on a LAN/mTLS connection rather than loopback?** `lib/decrypted-payload-gate.ts` restricts rendering decrypted content to loopback or mTLS-authenticated transport — if you're seeing this from a browser accessing over plain `http://` on a non-loopback address (which shouldn't be reachable at all per this app's network posture, but worth ruling out), it's expected to stay hidden.
- **Did the target process exit and get relaunched without `osi-inspect`?** Decrypt-eligibility is registered per-PID and unregistered on exit — a process restarted outside the wrapper needs to be relaunched through it again.
