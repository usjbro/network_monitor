# Live Capture Ingestion — Design Spec

**Status:** Approved for implementation planning
**Date:** 2026-08-26
**Sub-project:** 1 of 4 (capture ingestion → ownership enrichment → path visualization → TLS interception)

## Purpose

Replace the OSI Traffic Terminal Monitor's simulated traffic engine with real captured traffic from the Mac it runs on, viewable securely both locally and from other devices on the home network (phone, tablet, other laptop). This is the foundation the later sub-projects (WHOIS/ownership enrichment, traceroute/path visualization, TLS interception for full DPI) build on — none of them are useful without real connection/packet data flowing through the app first.

## Scope

**In scope:**
- Real packet capture on the Mac's active network interface
- A privileged capture agent, an unprivileged relay server, and a secured viewing path (browser on other LAN devices, native app on the Mac)
- Full removal of the simulator (`lib/osi-engine.ts` generators, `ScenarioLabView`, `TrafficScenario` type, sim-only command-bar commands)
- The security model for this pipeline: transport encryption, device authentication, and privilege minimization

**Explicitly out of scope (deferred to later sub-projects):**
- IP/domain ownership lookups (WHOIS/RDAP) — sub-project 2
- Traceroute-based path visualization and geolocation — sub-project 3
- TLS interception / decrypted HTTPS content (MITM proxy) — sub-project 4
- Capturing traffic from devices other than the Mac running the agent (explicitly designed to extend to this later, not built now)

## Architecture

```
Capture Mac                                              Viewing device (phone/laptop)
┌───────────────────────────────────────┐                ┌───────────────────┐
│ Rust capture agent                     │                │ Browser with       │
│ (runs as your user, access_bpf group — │                │ CA-issued client   │
│  no sudo needed after one-time setup)  │                │ cert installed     │
│         │ loopback-only TCP,           │                └─────────┬─────────┘
│         │ newline-delimited JSON       │                          │ HTTPS + mTLS
│         ▼                              │                ┌─────────▼─────────┐
│  Next.js app (`next start`,            │◄───────────────┤ Caddy reverse      │
│  plain HTTP, loopback only)            │───proxies to──►│ proxy, LAN-visible │
│         ▲                              │  loopback      │ port (443)         │
│         │ same HTTPS+mTLS path         │                └────────────────────┘
│  Native Swift/WKWebView app ───────────┘
│  (Keychain-backed client cert,
│   single-origin locked)
└─────────────────────────────────────────┘
```

Only the Caddy port is reachable from the LAN. The agent and the Next.js app both bind to `127.0.0.1` only. The native Mac app is not a separate data path — it loads the same HTTPS+mTLS origin as any other trusted device, just inside a locked-down native shell instead of a general browser.

## Components

### 1. Rust capture agent

- Captures on the primary active interface (auto-detected, e.g. `en0`) via the `pcap` crate (libpcap bindings).
- **Privilege model:** runs as the normal user, added to macOS's `access_bpf` group (one-time `sudo dseditgroup` setup, documented in a README, not automated) so it can open `/dev/bpf*` without `sudo`. No elevated privilege is retained beyond opening the capture handle.
- **Parsing:** does not trust libpcap's higher-level dissection. Parses Ethernet/IP/TCP/UDP headers itself using `etherparse`, reads plaintext L7 protocols where present (HTTP, DNS), and reads the TLS ClientHello's SNI field for encrypted connections. No decryption — that's sub-project 4. Malformed or malicious packet bytes are logged and skipped; the parser must never panic on untrusted input.
- **Hardening:** the packet parser is fuzzed with `cargo-fuzz` before this ships. `cargo audit` does not cover libpcap's own CVE history (it's not in the RustSec advisory database) — libpcap's advisories are tracked separately via `tcpdump.org/public-cve-list.txt` as an ongoing maintenance task, not a one-time check.
- **Data produced:**
  - A flow/connection table (5-tuple aggregation: src/dst IP+port+protocol), mapped to the existing `NetworkConnection` shape in `lib/types.ts`.
  - A capped packet-event stream, mapped to the existing `PacketFrame` shape (including `headerBreakdown` per OSI layer).
- **Wire protocol:** newline-delimited JSON over a loopback-only TCP socket. Two message types (connection-table diffs, packet events) flow agent → server; control messages (pause/resume, change interface) flow server → agent on the same socket.

### 2. Next.js server relay

- Maintains one persistent client connection to the agent, with reconnect/backoff if the agent isn't running or drops.
- `GET /api/stream` — Server-Sent Events route forwarding agent events to the browser. No custom server needed; SSE is natively supported by Next.js Route Handlers.
- `POST /api/control` — forwards pause/resume/interface-selection commands to the agent.
- Surfaces agent connection health through the stream so the UI can show a clear "capture agent not running" banner instead of silently going quiet.
- Runs plain HTTP, loopback only. All TLS/mTLS is handled by Caddy in front of it.

### 3. Caddy reverse proxy

- Terminates TLS and enforces mutual TLS: `client_auth { mode require_and_verify }` against a local CA.
- **Certificate authority:** generated once with `mkcert`. The Mac gets a server cert; each trusted viewing device gets a client cert, installed once (AirDrop/USB/however) and trusted in that device's settings.
- Short-lived client certs, reissued periodically, rather than OCSP (OCSP is skipped entirely — one less moving part and a class of revocation-bypass bugs it avoids).
- **Required verification step (not optional):** a deploy-time/setup-time test that presents an invalid or missing client cert and confirms the connection is actually rejected. "The proxy started successfully" is not evidence mTLS is enforced — this must be checked explicitly, once at setup and again after any Caddy config change.
- Proxies verified requests to the Next.js app over loopback.

### 4. Native macOS app (Swift + WKWebView)

- A thin native shell: a `WKWebView` pointed at the Mac's own HTTPS address, not a reimplementation of the UI.
- **Single-origin lock:** `WKNavigationDelegate.decidePolicyFor` and `WKUIDelegate.createWebViewWith` (for `window.open`/new-window requests) reject any navigation whose origin isn't the app's own trusted origin — main frame *and* subframes. This closes off the delivery vector behind every WebKit exploit examined in the research sweep (all require rendering attacker-reachable web content); a shell that can only ever render one origin you author yourself has nothing else to visit.
- **Client certificate:** stored in the macOS Keychain as a Secure Enclave-backed key (P-256 EC, if the mTLS stack accepts EC certs — non-extractable even under a future memory-disclosure bug), with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (no iCloud sync) and biometric confirmation required per signing use. If the proxy requires RSA instead, the same accessibility/access-control flags apply without the Secure Enclave non-extractability guarantee.
- App Sandbox and hardened runtime enabled, with minimal entitlements (network client only; no JIT entitlement unless something genuinely needs it).
- The web content itself ships a strict CSP (`default-src 'self'`, no `unsafe-eval`) as defense in depth even though the shell already restricts navigation.
- Remote (non-Mac) devices continue to reach the same origin through an ordinary browser with their own installed client cert — the native app is an alternative front door for the Mac specifically, not a second data path.

### 5. Data model changes

- `lib/types.ts`: remove `TrafficScenario` and any fields that only existed to support fabricated data. `NetworkConnection`, `PacketFrame`, `OSILayerInfo`, and `SystemStats` are otherwise reused as-is — they already have the right shape for real captured data (this was deliberate scaffolding from the original simulation).
- `lib/osi-engine.ts`: remove `generateRandomPacket`, `INITIAL_OSI_LAYERS`, `INITIAL_CONNECTIONS`, and other fabrication logic. Replace with mapping functions that convert agent wire-protocol messages into these same types. `THEMES` and formatting helpers (`formatSpeed`, `formatBytes`) are unaffected and stay as-is.

### 6. UI changes (`app/page.tsx` and components)

- Remove `ScenarioLabView`, the `scenario` state, and the `lab`/`scenario` command-bar commands. `pause`/`resume` are repurposed to control real capture (forwarded through `/api/control`) rather than a `setInterval` loop; `reset` clears the local display buffers rather than "resetting" real traffic.
- Replace the `setInterval` simulation loop with an `EventSource` connection to `/api/stream`, updating the same state shapes (`layers`, `connections`, `packets`, `stats`) the views already consume — the presentational components (`DashboardView`, `ConnectionsView`, `PacketStreamView`, etc.) do not need to change, since they already just receive props.
- Add an "agent not connected" banner state, shown whenever the SSE stream reports the agent is unreachable, with the command to start it.
- **Required sanitization:** any string sourced from the network (hostnames, mDNS/Bonjour names, DHCP client names, SSIDs, MAC vendor lookups, DNS query names) must be HTML-encoded before rendering. This is a genuine requirement, not defensive boilerplate — the single-origin lock on the native app protects against external attacker-controlled web content, but not against a hostile device on the same LAN smuggling a rendering-triggering payload through data the app itself displays. React's default JSX text rendering already escapes string children, so this is primarily a matter of auditing for any `dangerouslySetInnerHTML` or non-JSX string interpolation and ensuring there is none for network-sourced values.
- Themes, layer detail view, protocol matrix view, and the rest of the command bar are unaffected.

## Setup & operations

**One-time setup (documented, not automated by the app):**
1. Add your user to the `access_bpf` group (`sudo dseditgroup -o edit -a $(whoami) -t user access_bpf`).
2. Generate a local CA with `mkcert`, issue the Mac a server cert, issue a client cert per trusted viewing device, install/trust each client cert on its device.
3. Verify mTLS actually rejects an invalid/missing client cert (see Caddy section above) before considering setup complete.
4. Build and install the native Swift app (Xcode), or rely on browser + client cert for viewing.

**Runtime (each session):**
1. Start the capture agent (`./capture-agent`, no `sudo` needed after step 1 above).
2. Start `next start` and Caddy.
3. Open the native app, or browse to the Mac's HTTPS address from a device with an installed client cert.

## Security model summary

| Threat | Mitigation |
|---|---|
| Untrusted device on LAN reading captured traffic | mTLS required at the reverse proxy; no cert, no connection |
| Compromised/malicious website exploiting the viewer | Native app's single-origin lock; no arbitrary navigation possible |
| Malicious LAN device smuggling a payload through displayed data | HTML-encoding of all network-sourced strings before rendering |
| Malformed/malicious packet crashing or exploiting the agent | Agent parses defensively (never panics on bad input), fuzzed parser, minimal retained privilege |
| Compromised npm dependency (active supply-chain campaigns) | `npm ci` only, `ignore-scripts=true`, exact version pinning, no same-day upgrades, diff IDE config after dependency churn |
| Theft of the client private key | Secure Enclave-backed, non-extractable, biometric-gated, no iCloud sync |
| Agent running with unnecessary privilege | `access_bpf` group membership instead of `sudo`/root; no elevated access retained after capture handle is opened |

## Error handling & lifecycle

- **Agent not running:** UI shows a clear banner with the start command; no silent "stuck at zero" state.
- **Agent crashes or disconnects mid-session:** Next.js server detects the socket close and retries with backoff; UI reflects a "reconnecting" state. `EventSource` auto-reconnects to the SSE endpoint on its own.
- **Malformed packet:** logged and skipped by the agent; never fatal.
- **Capture permission/interface failure:** surfaced through the control API back to the UI as an explicit error, not a silent empty state.
- **Invalid/expired client certificate:** rejected at the TLS layer by Caddy before any application code runs; the browser/app shows its normal TLS-failure UI (no custom error page needed, and none should synthesize a misleading "try again" that implies the app itself is at fault).

## Dependency hygiene (applies to this repo going forward, not just this feature)

- `npm ci` in CI/deploy, never `npm install`.
- `ignore-scripts=true` in `.npmrc`; re-enable per-package only when a native build step is verified necessary.
- Exact version pinning (`save-exact=true`); no automatic/same-day dependency upgrades.
- After any dependency churn, diff `.vscode/`/`.claude/` config against git — implanted editor/IDE config is this year's specific npm-worm persistence mechanism.

## Testing

- **Rust agent:** `cargo test` unit tests for the header/flow parser against fixture byte sequences, including deliberately malformed ones. `cargo-fuzz` against the packet-parsing entrypoint given it processes untrusted input.
- **Next.js relay:** this repo has no existing test runner; add a minimal one (e.g. Vitest) scoped to the mapping functions (agent message → `NetworkConnection`/`PacketFrame`) and the SSE relay/reconnect logic, since this is real logic-bearing code rather than presentational UI.
- **mTLS enforcement:** an explicit setup-time (and post-config-change) check that an invalid/missing client cert is rejected by Caddy, per the Security model table above.

## Deferred to later sub-projects

- **Sub-project 2 (ownership enrichment):** WHOIS/RDAP lookups for IP org/ASN and domain registrant, layered on top of the real connection data this sub-project produces.
- **Sub-project 3 (path visualization):** on-demand traceroute + geoIP hop mapping for any connection's remote endpoint.
- **Sub-project 4 (TLS interception):** a local CA-based MITM proxy for decrypted HTTPS content, including per-device trust installation and the larger security review that entails.
