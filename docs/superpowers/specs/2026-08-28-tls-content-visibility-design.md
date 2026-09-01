# TLS Content Visibility — Design Spec

**Status:** Draft — competing proposal for issue #25, narrower than the epic's stated goal (see Purpose)
**Date:** 2026-08-28
**Sub-project:** 4 of 4 (capture ingestion → ownership enrichment → path visualization → **this**)

## Purpose

Issue #25 asks for "full deep packet inspection of encrypted (HTTPS/TLS) traffic by running a local intercepting proxy with a self-issued root CA installed on each device you want to inspect — effectively a personal mitmproxy." This spec takes that goal seriously enough to say plainly: **that design should not be built, and not because it's merely hard.** It is a different kind of trust grant than anything this repo has shipped so far, it compounds an already-documented weak point (the unencrypted mkcert CA key in `docs/security.md`), and — as detailed below — it doesn't even reliably deliver on its own promise, because certificate-pinned apps simply break rather than get inspected under it.

This spec instead proposes the narrowest design that still delivers real decrypted-content visibility: **passive TLS key logging (`SSLKEYLOGFILE`) for explicitly-launched, opted-in processes, with zero device-wide trust changes** — no CA, no forged certificates, no redirected traffic, no interception. It sits alongside a zero-new-trust improvement to what 1a already captures (JA3/JA4 TLS-fingerprint visibility from the existing SNI/ClientHello capture). The full device-wide MITM design from the original brainstorm is addressed directly in **Rejected alternatives**, not silently dropped — the issue asked for it, so this spec owes an explicit, reasoned "no, and here is what you get instead."

Framed in plain terms: the recommendation in this spec never asks you to make your Mac trust a new certificate authority, never touches Safari or any app you haven't explicitly pointed at it, and never changes what actually goes out over the network. It only adds the ability to also read the *plaintext* of traffic from one app you deliberately launch through a small wrapper, for that one run, using a mechanism (`SSLKEYLOGFILE`) that browser vendors themselves ship specifically so tools like Wireshark can do exactly this — it's a well-worn, narrow door, not a new one this project has to cut.

## Scope

**In scope — Tier A, core (ships first, zero new trust, zero new privilege):**
- Extend `capture-agent/src/parse.rs`'s existing passive TLS ClientHello parsing (already extracting SNI per 1a) to also extract cipher-suite list, extension list, and elliptic-curve/point-format lists, and compute a JA3 hash (and JA4 if scoped in during planning) from them — a well-known, purely-derived fingerprint of "what TLS client library/version is really talking here," independent of what the app claims to be.
- Surface the fingerprint in `ConnectionsView`'s detail panel, alongside 2's ownership enrichment, with a small, curated set of known-fingerprint labels (e.g. "matches Chrome 12x," "matches Go net/http default") — best-effort, not authoritative (see Security model).
- No agent privilege change, no new wire event category — a new field on the existing `LayerUpdate`/connection wire shape, following the field-for-field update checklist in `docs/wire-protocol.md`.

**In scope — Tier B, extended (ships second, same sub-project, opt-in per process, zero device-wide trust):**
- A new `osi-inspect <command...>` CLI wrapper (ships in this repo, not `npm`-published) that launches exactly one target process with `SSLKEYLOGFILE` set to a fresh, per-launch, `0600`-permissioned file under the app's data directory, and tags that process (by PID, inherited by its child-process tree) as "decrypt-eligible" for the current agent session.
- Agent-side: a new, narrowly-scoped watcher that tails a decrypt-eligible process's key-log file and combines it with the ciphertext the agent is *already* passively capturing for that process's flows (via the existing `process_lookup.rs` attribution) to compute TLS-record plaintext locally, after the fact. The wire between the app and the real remote server is never touched, delayed, or redirected — this is pure local computation over data the agent already legitimately holds plus a key the target process voluntarily wrote out.
- Decrypted plaintext surfaced only for connections belonging to a decrypt-eligible process; a new `decrypted_payload` wire event (capped size per record, same discipline as the packet-stream cap from #27) and corresponding `app/api/stream` relay handling, `lib/agent-mapping.ts` mapper, and `PacketStreamView` rendering path.
- HTTP/2 framing parsed from the now-plaintext byte stream by a new, self-contained frame parser (same shape as existing L7 sniffing in `src/l7.rs`) — not a proxy concern, since nothing is being terminated or re-originated; multiplexed streams are just structure inside bytes the agent now has in the clear.
- QUIC: handled by the same key-logging mechanism where the target client supports it (recent Chrome and curl+quiche builds emit QUIC traffic secrets through the same `SSLKEYLOGFILE` hook) — genuinely a case where avoiding a proxy sidesteps a whole category of work a MITM design would hit head-on (a terminating proxy would need to reimplement a QUIC server *and* client stack; this design needs only a QUIC secret-derivation reader).
- Key-log file lifecycle: deleted when the wrapped process exits (normal or crash, via a deferred cleanup in the wrapper), and never retained across runs.

**Explicitly out of scope (deferred to a future pass of this same sub-project):**
- HTTP/2 server push and any decrypted-content search/filtering UI beyond raw display — ships once Tier B's basic plumbing is proven.
- JA4+ variants beyond the base JA3/JA4 fingerprint (JA4S, JA4H, etc.) — same data source, more taxonomy, not required for the core "does this look like what it claims" use case.
- Any correlation between JA3/JA4 fingerprints and 2's RDAP org data (e.g. "this org's IP but a fingerprint that doesn't match their known client") — real potential value, but its own analysis feature on top of two already-landed data sources, not core plumbing.

**Permanently out of scope (not deferred — see Rejected alternatives for the full reasoning):**
- **Full device-wide transparent MITM**: traffic redirection (proxy/NAT), on-the-fly leaf-certificate forging, and a device-installed trusted root CA. This was the issue's literal ask and this spec recommends against it outright, not as a future phase of this design — Tier B is not an incremental step toward it, the two are architecturally unrelated (passive vs. on-path).
- Any inspection of apps that don't support `SSLKEYLOGFILE` (Safari/WebKit notably does not) without the user's explicit, per-run opt-in via the wrapper. There is no "inspect everything on this device" mode in this design, by design.
- Certificate-pinning bypass of any kind — Tier B doesn't need it (the real handshake is untouched), and Tier C would have silently failed against it anyway (see below).

## Architecture

```
Capture Mac
┌────────────────────────────────────────────────────────────────────┐
│  Target process, launched via:                                     │
│    osi-inspect  <command...>              (Tier B, opt-in, per-run)│
│         │  sets SSLKEYLOGFILE=<ephemeral 0600 file>, exec's command│
│         │  (env inherited by any child processes it spawns)        │
│         ▼                                                          │
│  Target process ──── real, untouched TLS handshake ────────────────┼──► real remote server
│         │  writes session secrets to SSLKEYLOGFILE as it goes      │    (unmodified traffic,
│         │  (its own TLS library's built-in, standard behavior)     │     unmodified cert chain,
│         ▼                                                          │     no redirection, ever)
│  Rust capture agent (1a, unchanged capture path)                   │
│   ├─ pcap capture of this process's flows (already happens today)  │
│   ├─ TLS ClientHello parse → SNI (1a) + cipher/ext list → JA3 (new,│
│   │    Tier A, ALL connections, no opt-in needed)                  │
│   └─ KeyLogWatcher (new, Tier B) — tails the key-log file for      │
│        decrypt-eligible PIDs only; combines w/ captured ciphertext │
│        → local TLS-record decrypt, entirely after the fact         │
│         │ NDJSON: decrypted_payload (new), ja3Fingerprint (new field│
│         │ on existing connection/layer events)                     │
│         ▼                                                          │
│  Next.js relay (unchanged transport pattern — SSE, same singleton  │
│  AgentClient shape 1a/2 already established)                       │
│         ▼                                                          │
│  Browser: ConnectionsView (JA3, Tier A, always) /                  │
│           PacketStreamView (decrypted bytes, Tier B, opt-in only)  │
└────────────────────────────────────────────────────────────────────┘
```

No new listening port, no new privilege boundary, no new trust store entry anywhere in this diagram.

## Components

### 1. `capture-agent/src/parse.rs` — JA3/JA4 extraction (Tier A)

- Pure, stateless extension of the existing ClientHello parser: reads the same bytes already being parsed for SNI, extracts cipher suites / extensions / curves / point formats per the standard JA3 algorithm (MD5 of a normalized, comma-joined field list), computed once per handshake, no per-connection state retained beyond the flow table entry.
- Same untrusted-input posture as the rest of `parse.rs`: `Option`/`Result` throughout, folded into the existing `cargo-fuzz` target rather than a new one (it's the same input, one more derived field).
- Fingerprint *matching* (mapping a hash to a human label like "Chrome 12x") is a small, versioned, hardcoded lookup table shipped in the repo, refreshed occasionally by hand — not a live lookup against any third-party fingerprint database (that would be this sub-project quietly reopening the "new outbound dependency" question 2 treated so carefully; explicitly not done here).

### 2. `osi-inspect` — the opt-in wrapper (Tier B)

- A small standalone script (Node, consistent with the rest of the relay tooling) that: generates a fresh random key-log filename under the app's data directory, `chmod 0600`s it before the target process can write to it, sets `SSLKEYLOGFILE` in the child's environment, execs the user's command as a direct child (not detached — its lifetime is the wrapper's lifetime), and on exit (success, failure, or signal) deletes the key-log file.
- Also writes the launched PID (and, best-effort, records child PIDs it can observe) to a small "decrypt-eligible" registration the agent polls or is notified of — the agent decrypts only flows attributed (via existing `process_lookup.rs`) to a PID on that list, for the lifetime of that PID.
- Deliberately **not** a persistent setting: there is no config flag that makes a named app "always decrypt-eligible." Every session of inspection is a conscious, one-command act, mirroring 2's "runtime-only, never persisted" opt-in precedent rather than inventing a new consent model.

### 3. `KeyLogWatcher` (agent-side, Tier B)

- Tails the registered key-log file(s) for currently-eligible PIDs (inotify/kqueue-based file watch, not polling-in-a-loop), parses `CLIENT_RANDOM`/TLS-1.3-labeled secret lines per the standard `SSLKEYLOGFILE` format, and holds them in memory only for the lifetime of the eligible PID — never written to the agent's own disk in any form.
- Decryption is applied to the ciphertext the agent's existing capture path already has in hand for that flow; a decrypt failure (missing key, out-of-order records, a cipher suite the decryptor doesn't implement) degrades to "ciphertext only, same as today," never a crash and never a silent wrong-plaintext render.
- Bounded like every other stream in this app: decrypted output is subject to the same size cap discipline already fixed for the raw packet stream (#27) — a capped ring buffer per connection, not unbounded accumulation.

### 4. Wire/event and data model changes

- `ja3Fingerprint?: string` and `ja3Label?: string` added to the existing connection/layer wire shape and `NetworkConnection`/`OSILayerInfo` types — Tier A, always-on, no gating, following the field-for-field checklist in `docs/wire-protocol.md` since this does touch `wire.rs`.
- New `decrypted_payload` NDJSON event (Tier B only, emitted only for decrypt-eligible flows), mapped by a new `lib/decrypted-mapping.ts` (kept separate from `agent-mapping.ts` for the same reason `enrichment-mapping.ts` was kept separate in sub-project 2: different trust/sensitivity characteristics than the always-on wire types).
- `docs/wire-protocol.md` updated for both additions, since both originate on the agent side of the agent↔relay boundary — unlike sub-project 2's enrichment data, this is genuinely new agent output, not relay-only.

### 5. UI surface

- Tier A: JA3 hash + best-effort label shown in `ConnectionsView`'s detail panel next to 2's Ownership section, always populated when the agent has parsed a handshake, no toggle needed.
- Tier B: `PacketStreamView` gains a per-connection "Decrypted" badge only for connections belonging to a currently decrypt-eligible process, with the decrypted bytes rendered as plain text (same `no-dangerous-html.test.ts`-audited posture as every other network-sourced string in this app) alongside the existing ciphertext view — never replacing it, so a user can see both.
- A visible, persistent banner while any process is decrypt-eligible ("Decrypting traffic for: `<command>` (pid NNNN)") — this state is unusual enough, and sensitive enough, that it should never be ambient/silent the way JA3 display is.

## Setup & operations

**One-time setup:** none. `osi-inspect` needs no CA, no keychain entry, no elevated privilege, no config file — it's a wrapper around an env var every major TLS library already checks for.

**Per-session use (Tier B):**
1. `osi-inspect npm run dev` (or any command) instead of running it directly.
2. The agent, already running per 1a's normal setup, picks up the new PID as decrypt-eligible automatically — no separate step.
3. Exit the wrapped command normally; the key-log file is deleted and the PID drops out of eligibility. Nothing persists.

**Coverage is real but partial, and that gets said in the UI, not just this doc:** `osi-inspect` decrypts traffic for anything that honors `SSLKEYLOGFILE` — Chrome/Chromium/Edge, Firefox, curl/OpenSSL-linked CLI tools, Node.js, and CPython's `ssl` module (3.8+) all do, by design, specifically so tools like this and Wireshark can do this. It does **not** work for Safari/WebKit (no support), most closed-source GUI apps, or anything using certificate pinning with private key material that never reaches the process's standard TLS library hook. When a wrapped process produces zero decrypted flows, the UI states that plainly ("no TLS libraries in this process wrote key-log data") rather than implying a bug.

## Security model summary

| Threat | Mitigation |
|---|---|
| Device-wide trust compromise from a MITM root CA (the issue's literal ask) | **Not built.** No CA exists in this design at all — see Rejected alternatives for why that's the recommendation, not an oversight |
| CA private-key theft granting whole-device HTTPS interception (would compound the already-documented mkcert CA weak point in `docs/security.md`) | N/A — no CA, no key, nothing to steal for this purpose |
| Certificate-pinned apps breaking silently under interception | N/A — Tier B never touches the real handshake or cert chain, so pinning is never triggered; this is also the concrete reason Tier C wouldn't have reliably delivered "full DPI" even if built |
| Key-log file (`SSLKEYLOGFILE`) read by another local process/user | `0600` permissions set before the target process can write to it; file lives under the app's own data directory, same posture as 2's cache/log files; deleted on wrapped-process exit (including crash, via deferred cleanup) |
| Key-log file surviving after a crash of `osi-inspect` itself (cleanup never runs) | Documented residual gap — a stale key-log file with no live process behind it is inert (nothing decrypts a *closed* connection's stored ciphertext with it unless the agent also retained that ciphertext, which it doesn't beyond the capped buffer), but the file should still be actively swept; a startup check in `osi-inspect` for orphaned files older than a threshold is a concrete follow-up task, not assumed away here |
| Scope creep: a wrapped process's child spawns unrelated long-lived services that inherit the env var and stay decrypt-eligible after the original command exits | Eligibility is tracked by PID/process-tree membership, torn down when the wrapper's direct child exits — a detached grandchild that outlives the wrapper is a known, narrow edge case (e.g. a daemonizing subprocess) called out for explicit test coverage, not silently assumed safe |
| Agent gains the ability to read decrypted application content — a new capability class even though it uses no new *privilege* | Named explicitly: this is qualitatively more sensitive than 1a's ciphertext-only or 2's metadata-only posture. Mitigated by scope (opt-in, per-process, per-run only) and by keeping the agent's privilege model itself unchanged (`access_bpf`, no `sudo`) — a compromised agent already saw ciphertext for everything and plaintext for decrypt-eligible flows only, not a blast-radius expansion beyond what opting in explicitly grants |
| Decrypted plaintext relayed to the browser over the still-plaintext internal hops (`docs/security.md`'s "internal hops are still plaintext, by design" gap) | Named explicitly as a stakes-raising interaction with an existing, documented gap: those hops carrying decrypted HTTPS content is materially more sensitive than carrying connection metadata. Acceptable on loopback-only deployments (today's default); flagged as a hard prerequisite — not a nice-to-have — before this feature is ever used on a relay reachable via 1b's LAN access, until/unless that path also gets end-to-end protection beyond Caddy's outer mTLS hop |
| Relay-wide exposure: any browser session attached to the relay sees Tier B's decrypted-payload events, not just the session that ran `osi-inspect` | Same relay-wide-toggle limitation named in sub-project 2's spec; inherited here rather than re-solved, and the persistent "Decrypting traffic for…" banner (§UI) at least makes the state visible to every attached viewer rather than silent |
| Attacker-controlled decrypted content (now literal HTTP response bodies, not just headers/hostnames) rendered unsafely in the UI | Plain text rendering only, no `dangerouslySetInnerHTML`, covered by the same `no-dangerous-html.test.ts` regression suite already gating every other network-sourced string — explicitly extended to include this new, higher-stakes content type in its test fixtures, not assumed to already be covered |
| Malicious/adversarial target process supplying bogus or misleading key-log data | Out of scope by design — the target process is one the user deliberately chose to run through the wrapper, as themselves, on their own machine; it is not an adversary in this threat model. Worst case is displaying wrong/garbage "decrypted" bytes for a connection, not a privilege or confidentiality violation |
| JA3/JA4 fingerprint spoofing (a client can trivially claim any TLS stack's fingerprint) | Documented as best-effort/informational only, never treated as an authenticated identity signal anywhere in the UI or in future enrichment correlation — same "don't overclaim certainty" posture 2 applied to registry-derived ASN data |
| Oversized decrypted-payload stream exhausting memory/UI | Same capped-ring-buffer discipline already fixed for the raw packet stream (#27), applied identically to decrypted output — not a new, separately-tuned cap to get wrong |
| A user assuming "TLS interception shipped" means whole-device inspection (expectation mismatch vs. the issue's literal ask) | Addressed head-on in this spec's Purpose and the Setup section's explicit per-app coverage statement, plus a UI string stating plainly which processes are and are not currently decrypt-eligible — never implied to be "everything" |
| HTTP/2/QUIC frame parser (new code, parses attacker-reachable decrypted bytes) mishandling malformed input | Same defensive posture as `src/l7.rs`'s existing sniffers and `parse.rs`'s fuzzed entry point — `Option`/`Result` throughout, added to fuzz coverage before shipping, not assumed safe because the bytes are "already decrypted by us" |

## Error handling & lifecycle

- **`osi-inspect` target process exits (normal, crashed, or killed):** key-log file deleted, PID (and any tracked children) removed from decrypt-eligibility immediately; any decrypted-payload events already emitted for that session remain in the browser's existing state (nothing retroactively un-shows them), but no new ones fire.
- **Key-log file missing/unreadable when the watcher expects it:** treated as "not yet decrypt-eligible," not an error — the target process may not have completed a handshake yet; watcher keeps polling the file's existence, not a fixed retry count.
- **A TLS record can't be decrypted (unsupported cipher suite, out-of-order/missing key material, truncated capture):** that specific record renders as "undecryptable" in `PacketStreamView`, ciphertext remains visible; never a crash, never a wrong-plaintext render papering over the gap.
- **Agent restart mid-session:** decrypt-eligibility state is in-memory only and does not survive an agent restart — matches 2's "opt-in never persists across restart" precedent; the user re-runs `osi-inspect` if they still want the wrapped process (already running) newly tracked, though note a restart mid-flight also loses the flow's already-captured ciphertext per 1a's existing (unrelated) flow-table lifecycle.
- **JA3 computation on a malformed/truncated ClientHello:** returns `None` for the fingerprint field, same tolerance `parse.rs` already applies to every other malformed-input case; never blocks SNI extraction or any other already-working field.

## Dependency hygiene

- Tier A (JA3): pure Rust, no new crate — the hashing (MD5, per the standard JA3 spec) uses a crate already reasonable to vet on its own if not already in the tree; if it is, that's the only addition this whole sub-project needs on the agent side.
- Tier B: `osi-inspect` is plain Node using only built-ins (`child_process`, `fs`, `crypto` for the random filename) — zero new npm dependencies, matching the precedent 1a and 2 both set. The `KeyLogWatcher` and TLS-record decryption logic on the agent side is new Rust code; if it pulls in a TLS/crypto crate for the record-layer decrypt math rather than hand-rolling it, that crate gets the extra-scrutiny treatment `docs/security.md`'s dependency-hygiene section calls for on anything security-critical — this is exactly that case, not routine churn.
- `npm ci`, `ignore-scripts=true`, exact pinning — unchanged, repo-wide policy, restated here per this sub-project's own dependency footprint above.

## Testing

- **JA3 correctness:** fixture-driven tests against known ClientHello byte captures with known-correct JA3 hashes (publicly documented test vectors exist for this), plus the malformed/truncated cases folded into `parse.rs`'s existing `cargo-fuzz` target.
- **`osi-inspect` file permissions and cleanup:** a test asserting the key-log file is created `0600` before the child process starts (not after), and is deleted on normal exit, non-zero exit, and on receipt of a termination signal.
- **Decrypt-eligibility scoping:** a test that a flow belonging to a non-eligible PID never triggers a `decrypted_payload` event even when a key-log file happens to exist on disk from an unrelated prior run.
- **Decryption correctness:** an integration-style test that captures real loopback TLS traffic from a test server, wraps the test client with `osi-inspect`, and asserts the agent's decrypted output matches the plaintext the test actually sent — the load-bearing end-to-end proof for this whole tier.
- **Decrypt failure paths:** explicit tests for missing keys, out-of-order records, and an unsupported cipher suite, each asserting graceful "undecryptable" marking rather than a panic or silent garbage output.
- **HTTP/2 frame parser:** fixture-driven tests with deliberately malformed frames, same rigor as `l7.rs`'s existing sniffer tests, added to fuzz coverage before this ships.
- **Rendering safety:** decrypted-payload fixtures containing HTML/script-like content added to `no-dangerous-html.test.ts`'s existing suite, asserting plain-text rendering only.
- **Relay-wide exposure banner:** a component test asserting the "Decrypting traffic for…" banner renders whenever any process is decrypt-eligible, regardless of which browser session triggered it.
- **Coverage-mismatch UX:** a test that wrapping a process which never writes key-log data (simulating an unsupported app) surfaces the explicit "no TLS libraries wrote key-log data" state, not a silent no-op.

## Rejected alternatives

**Full device-wide MITM proxy with a self-issued, device-installed root CA (the issue's literal ask) — rejected outright, not deferred:**

- **Requires a privilege the agent deliberately doesn't have.** Today's agent is a passive observer by construction — its unprivileged `access_bpf` posture is safe precisely because it cannot drop, delay, or redirect a single packet. Interception requires exactly that capability (via a system proxy setting or `pf`/NAT redirection), which is a different privilege class the agent has never needed and this repo has no established pattern for granting safely.
- **Forged-certificate-per-SNI is new, real stateful attack surface**, not a stated gap to gloss over: every distinct hostname seen needs an on-the-fly-signed leaf cert, which is a signing operation (and cache) per origin, not per connection — a single page load can mean dozens of signing operations, and an under-designed cache is a real perf/DoS surface this spec would otherwise have had to design from scratch.
- **The trust grant is categorically different from this repo's existing precedent, not a bigger version of it.** 1b's client-cert install lets a device prove "I am trusted" to this app's own Caddy front door — narrow, single-purpose. A device-wide MITM CA lets the device believe forged certificates for *any* hostname on the internet — compromising its key is equivalent to compromising the device's entire TLS trust model, every site, not just this app. Treating these as points on the same spectrum, as an earlier draft of this reasoning did, undersells the difference.
- **It compounds an already-documented weak point rather than introducing an isolated new one.** `docs/security.md` already names the mkcert CA key as unencrypted, `0400`-only-protected, and already capable of MITMing the user's own browsing via `mkcert -install`. Reusing that key for active interception (not just occasional client-cert signing) raises its value as a target enormously; a second, separate CA doubles the unencrypted-private-key attack surface on disk instead. Neither option is "solved" by this spec without hardware-backed key storage (Keychain/Secure Enclave) for the CA signing key specifically — a nontrivial addition on its own, and one this spec declines to take on in service of a design it's simultaneously recommending against.
- **It doesn't even reliably deliver the goal.** Certificate-pinned apps (many banking apps, some messaging apps) reject the forged chain outright and simply stop working under a MITM proxy rather than being inspected — "full DPI of encrypted traffic" was never actually achievable universally by this approach, which weakens the case for absorbing all of the above risk to get it.
- **HTTP/2 and QUIC are protocol-stack problems for an on-path proxy, not parsing problems.** A terminating proxy has to negotiate ALPN, multiplex/demultiplex HTTP/2 streams, and — for QUIC — implement a full UDP-based QUIC server *and* client stack (since QUIC carries its own encryption independent of the outer TLS story) just to stay in the traffic path at all. Tier B sidesteps all of this because it never leaves the path in the first place; it only reads bytes that already arrived.

If a future maintainer decides whole-device inspection of apps that fundamentally don't support `SSLKEYLOGFILE` (Safari being the main real-world case) is worth it anyway, that is a legitimate future decision — but it is a from-scratch, its-own-spec effort with its own dedicated security review, exactly as issue #25 itself demands. It is not a natural next phase of this spec's Tier B, which is architecturally passive by design.

## Deferred to later sub-projects / follow-ups

- **JA3↔RDAP org correlation** ("this org's IP, but a client fingerprint that doesn't match their known stack") — real value, but a distinct analysis feature layered on two already-shipped data sources (2's enrichment, this spec's Tier A), not core plumbing.
- **Orphaned key-log file sweep** on `osi-inspect` startup — named as a concrete residual gap in the Security model table, small enough to fold into Tier B's own implementation plan rather than warranting a separate spec.
- **End-to-end protection of the decrypted-payload SSE path once 1b's LAN access is in play** — today's loopback-only default makes the existing "internal hops are plaintext" gap acceptable; this feature raises the stakes of that gap and should be revisited as a hard prerequisite, not a nice-to-have, before Tier B is ever enabled on a relay reachable via LAN.
- **Hardware-backed (Keychain/Secure-Enclave) storage for CA signing keys** — relevant only if a future maintainer pursues the rejected Tier C design; noted here so it isn't rediscovered from scratch if that conversation happens later.
