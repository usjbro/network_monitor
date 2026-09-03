# TLS Content Visibility — Design Spec

**Sub-project:** 4 of 4
**Status:** Approved by usjbro (jamesmbrownjr@gmail.com) on 2026-09-01 — ship Tier A + Tier B; full MITM/CA proxy rejected outright, not deferred. Cleared to proceed to an implementation plan.
**Date:** 2026-08-29
**Resolves:** issue #25, synthesizing two competing drafts (Draft A: narrow `SSLKEYLOGFILE`-based alternative; Draft B: full device MITM proxy with maximal hardening), revised after four adversarial review passes (CA-compromise blast radius, consent/UX, decrypted-content handling, feasibility)

## Revision notes (for the human reviewer)

This is a revision of the 2026-08-28 synthesized spec, not a new design. The recommendation is unchanged — ship Tier A + Tier B now, reject the MITM proxy — but four adversarial reviews found real gaps in the reasoning and in the shipped design's own safety properties. All of the following were applied:

- **CA-compromise review:** the spec's own framing of 1b's client-cert CA as "narrow, single-purpose" was factually wrong — it's the same system/browser-trusted mkcert root that `docs/security.md` already flags as capable of whole-device, any-hostname HTTPS interception if stolen. Corrected throughout, including the Security model table, which previously implied this was a purely hypothetical future risk.
- **Consent/UX review:** the "Rejected for now" section cited Draft B's disclosure copy by section number instead of preserving it — the one artifact where reconstruction risk is highest. Concrete disclosure copy is now written out in full, and the reopening bar is tightened to require it name the forgery capability in plain language and contrast explicitly against 1b's already-shipped client-cert flow.
- **Decrypted-content-handling review:** the shipped Tier B design had no treatment of credentials/session tokens, no analysis of what happens when a general-purpose browser (explicitly listed as supported) is wrapped, no swap protection despite naming swap as a threat, and no core-dump protection. All four are addressed below with concrete mechanisms, not just acknowledged.
- **Feasibility review:** Tier B's one-line treatment of HTTP/2 multiplexing ("just structure inside bytes we already have") ignored HPACK's stateful, order-dependent decoding and the need for byte-stream reassembly before framing — this is now a full component with an honest whole-connection fallback strategy. The rejected MITM design's cert-generation performance claims were unquantified hand-waving — now named explicitly as an unresolved gap and added as a condition for reopening, not smoothed over.

Everything below is the complete, standalone spec incorporating those fixes — not a diff against the prior version.

## Recommendation, stated up front

**Build the narrow design now. Do not build the full MITM proxy as part of this sub-project, or on any committed timeline.**

Concretely:

- **Ship Tier A (JA3/JA4 TLS fingerprinting) and Tier B (opt-in, per-process `SSLKEYLOGFILE` decryption)** as sub-project 4, using Draft A's architecture, with several of Draft B's hardening decisions folded in where they cost little and close real gaps (see below).
- **Do not build the CA-based, traffic-redirecting MITM proxy described in Draft B.** It is not deferred as "phase 2 of this sub-project" — it is a categorically different trust grant, addressed here only as a *rejected-for-now* design with explicit reopening conditions. If a future maintainer decides it's worth it, Draft B's component design (Secure Enclave CA custody, session-scoped signing, mandatory origin validation, `mlock`/no-disk-write plaintext handling, 7-day CA expiry, dual-trust-store revocation tooling) is preserved below as the reference design for that future, independently-approved sub-project — not rediscovered from scratch, but also not built now.

The rest of this document is organized around that recommendation: what ships, why the alternative was set aside rather than merely postponed, and what would have to be independently true before it's revisited.

## Purpose

Issue #25 asks for "full deep packet inspection of encrypted (HTTPS/TLS) traffic by running a local intercepting proxy with a self-issued root CA installed on each device you want to inspect — effectively a personal mitmproxy." Both drafts took that ask seriously; they disagree about whether to build it.

Draft A's core argument is not "MITM is hard" — it's that MITM is a **different kind of trust grant** than anything this repo has shipped, that it **compounds an already-documented weak point** (`docs/security.md` already flags the unencrypted mkcert CA key as capable of MITMing the user's own browsing), and that it **doesn't reliably deliver its own promise** — certificate-pinned apps simply stop working under it rather than getting inspected, and HTTP/3 traffic is invisible to it regardless.

Draft B doesn't dispute any of that. It accepts the same premises — a dedicated CA, Secure-Enclave-only key custody, 7-day validity, mandatory origin certificate validation, `mlock`'d never-touches-disk plaintext, a hard kill switch, per-connection (not device-wide) opt-in — specifically *because* it agrees this is the highest-risk sub-project in the roadmap and treats every piece of new trust as something to minimize. Its own Architecture section says the plainest part of the honest case against itself: `mitm-proxy` has to be a **separate privileged binary** from `capture-agent`, specifically so the agent's passive, unprivileged, `access_bpf`-only security story — the thing that has let sub-projects 1a through 3 ship without asking the user to trust anything new — doesn't get contaminated for every user who never enables interception.

That last point is the crux of this synthesis. Even Draft B's *best possible engineering* of a MITM proxy still requires standing up a new privileged, trust-anchored, traffic-redirecting component that:

- installs a root CA capable (if its key is ever extracted, misused during its live signing window, or the revoke tooling is skipped) of impersonating **any hostname on the internet**, not just this app's traffic;
- actively terminates and re-originates the user's real TLS connections rather than only observing what's already on the wire;
- still fails to deliver "full DPI of encrypted traffic" against pinned apps and is architecturally blind to HTTP/3 — the exact two limits Draft A used to argue the goal was never fully achievable this way;
- only covers proxy-aware software even when working as designed — non-proxy-aware CLI tools, VPN clients, and pinned apps bypass it silently.

Meanwhile, Draft A's `SSLKEYLOGFILE`-based approach delivers **the same decrypted-content end-state** — real plaintext request/response bytes in `PacketStreamView`, including HTTP/2 and QUIC where the client supports it — for the overwhelming majority of realistic uses (the user's own browser, their own dev-server traffic, their own CLI tools) **without creating a CA, without redirecting a single packet, and without asking macOS to trust anything new.** It uses a mechanism TLS library authors themselves built specifically for this purpose. Its blast radius, if the agent is fully compromised, is "plaintext for the flows the user explicitly ran through a wrapper this session" — never "an attacker-forgeable certificate for the user's banking site."

The judgment call this synthesis makes explicitly: **the marginal visibility MITM would add (Safari, non-proxy-aware apps, pinned apps that would break anyway) is not worth taking on a CA-based trust anchor to get**, especially since even that marginal visibility is partly illusory (pinned apps break, HTTP/3 is invisible either way). That calculus could change — see "Conditions for revisiting," below — but it hasn't yet, and this spec declines to build it speculatively.

**Important scope correction carried through this whole document (see "Rejected for now" for the full analysis):** an earlier draft of this reasoning implied that a MITM CA would be the *first* whole-device, any-hostname trust anchor this repo creates. That's not accurate. Sub-project 1b already installed a system/browser-trusted mkcert root CA to issue client certificates for LAN access, and `docs/security.md` already documents that the same CA key can mint a server certificate for any hostname and MITM the user's own browsing. The correct comparison is not "zero CA risk today vs. new CA risk if we build this" — it's "an already-live CA-based exposure vs. a design that would exercise that capability far more actively, and/or add a second such anchor." This doesn't change the recommendation, but the rest of this document states it accurately rather than repeating the earlier, incorrect framing.

## Scope

### Ships now — Tier A: JA3/JA4 fingerprinting (zero new trust, zero opt-in required)

- Extend `capture-agent/src/parse.rs`'s existing passive TLS ClientHello parsing (already extracting SNI per 1a) to also extract cipher-suite list, extension list, and elliptic-curve/point-format lists, and compute a JA3 hash (JA4 if scoped in during implementation planning) — a purely-derived fingerprint of "what TLS client library is really talking here," independent of what the app claims to be.
- Surface the fingerprint in `ConnectionsView`'s detail panel next to sub-project 2's ownership enrichment, with a small, curated, hardcoded, occasionally-hand-refreshed lookup table of known fingerprint labels (e.g. "matches Chrome 12x") — best-effort and explicitly non-authoritative, never a live third-party lookup (that would reopen the "new outbound dependency" question sub-project 2 treated carefully).
- A new field on the existing `LayerUpdate`/connection wire shape (`ja3Fingerprint?: string`, `ja3Label?: string`), following the field-for-field update checklist in `docs/wire-protocol.md`. No new wire event category, no agent privilege change.

### Ships now — Tier B: opt-in, per-process decrypted content via `SSLKEYLOGFILE`

- A new `osi-inspect <command...>` CLI wrapper (plain Node, built-ins only — `child_process`, `fs`, `crypto`) that launches exactly one target process with `SSLKEYLOGFILE` pointed at a fresh, per-launch, `0600` file created *before* the child can write to it, and tags that process's PID (and observed child PIDs) as "decrypt-eligible" for the current agent session only.
- **Scope confirmation before wrapping a general-purpose browser.** Decrypt-eligibility is per-*process*, not per-destination-host: wrapping a browser decrypts every tab and origin open (or later opened) in that process, not just the one the user meant to inspect — there is no way to scope by host at the `SSLKEYLOGFILE` layer, since the key log doesn't carry destination information usable for filtering ahead of time. `osi-inspect` detects common general-purpose browser binaries by name (Chrome/Chromium/Edge/Firefox and their common launcher names) and refuses to proceed without an explicit interactive confirmation naming that scope, or a `--yes-decrypt-entire-browser` flag for scripted use. This is a named, accepted limitation, not a solved one — see Security model summary.
- Agent-side `KeyLogWatcher`: tails the key-log file for currently-eligible PIDs (file-event-based, not poll-in-a-loop), combines the logged secrets with ciphertext the agent's existing capture path already legitimately holds for that process's flows (via `process_lookup.rs` attribution), and computes TLS-record plaintext **in memory only**. A decrypt-eligible PID's traffic was already being passively captured as ciphertext before this feature; this only adds the ability to also read it in the clear for that one deliberately-launched process.
- **Sensitive-header redaction, applied before content ever enters the ring buffer or is emitted.** Once HTTP/1.1 or HTTP/2 headers are parsed from the decrypted stream, well-known sensitive header names — `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`, and pattern-matched bearer-token values — are replaced with a `[REDACTED]` placeholder before the record is buffered or sent over the wire; the header *name* is preserved so the structure stays legible. This is **best-effort, not exhaustive**: credentials embedded in request/response *bodies* (a login form POST, an API key inside a JSON payload) are not automatically redacted and remain visible to every attached viewer — the UI and docs state this plainly rather than implying full credential safety (see Security model summary and Setup & operations).
- **Decrypted plaintext never touches disk anywhere in this sub-project's own code** — adopted directly from Draft B's §8 as a hard requirement, not softened just because the mechanism here is passive rather than an active proxy: no `write()`/`open()`-for-write call on the decrypted-record code path, capped in-memory ring buffer per connection (same discipline already fixed for the raw packet stream, #27), zeroed via an explicit zeroing primitive (not relied-upon-`Drop` alone) and dropped on eviction. The ring buffer's backing memory is `mlock`'d — best-effort, since macOS enforces `RLIMIT_MEMLOCK` limits and this is hardening rather than an absolute guarantee, and is documented as such rather than claimed as complete swap protection. The one on-disk artifact this design does create — the `SSLKEYLOGFILE` itself — is a *key*, not plaintext content, is `0600`, is ephemeral, and is deleted on process exit; that distinction is real but is stated plainly here rather than let the "never touches disk" claim quietly not apply to it.
- **The agent process disables core dumps unconditionally at startup** (`RLIMIT_CORE=0` or the platform equivalent), independent of whether Tier B is in active use — cheap, no functional downside, and closes the gap that a crash while the ring buffer holds live plaintext (or credentials that survived redaction) could otherwise leave a core file on disk.
- HTTP/2 framing is parsed from the now-plaintext byte stream by a new stream-reassembly + HPACK-aware component (see Components §4) — not a proxy concern, since nothing is terminated or re-originated, but a real piece of new work, not the "just structure in bytes we already have" one-liner an earlier draft used.
- QUIC: handled by the same key-logging hook where the target client emits it (recent Chrome, curl+quiche) — a case where the passive design sidesteps a whole category of work a MITM proxy would hit head-on (Draft B's own scope concedes it cannot touch QUIC at all).
- Key-log file lifecycle: deleted on wrapped-process exit (normal, crashed, or signaled, via deferred cleanup in the wrapper); a startup sweep in `osi-inspect` for orphaned files older than a threshold, closing the residual gap Draft A named but left as a follow-up.

### Explicitly out of scope for this sub-project, permanently (not "later phase of this same design")

- **The full device-wide MITM proxy from Draft B — root CA, TLS termination/re-origination, leaf-certificate forgery, system-proxy traffic redirection.** See "Rejected for now" below. This is the load-bearing scope decision of this synthesis: Tier B above is not an incremental step toward MITM. The two are architecturally unrelated (passive key-log reading vs. active on-path termination), and this spec does not want a future contributor to read Tier B's ticket history and conclude "and then naturally we added the proxy."
- Certificate-pinning bypass of any kind.
- Inspection of apps that don't support `SSLKEYLOGFILE` (Safari/WebKit notably does not) without the per-run opt-in wrapper. There is no "inspect everything on this device" mode in this design, by design — this matches Draft A's stance and Draft B's own core-scope restriction to explicit, narrow opt-in.
- Automatic redaction of credentials embedded in request/response bodies (as opposed to headers). Header redaction is in scope (see Tier B above); body-content credential scanning is a materially harder, higher-false-negative problem and is not attempted in this sub-project.
- Per-destination-host scoping of decrypt-eligibility. Named as a real limitation of the browser-wrapping case above, not solved here.
- JA4+ variants beyond base JA3/JA4 (JA4S, JA4H, etc.) and JA3↔RDAP correlation — real value, own future feature, not core plumbing.

## Architecture

```
Capture Mac
┌────────────────────────────────────────────────────────────────────┐
│  Target process, launched via:                                     │
│    osi-inspect  <command...>              (Tier B, opt-in, per-run)│
│         │  sets SSLKEYLOGFILE=<ephemeral 0600 file>, exec's command│
│         │  (env inherited by any child processes it spawns)        │
│         │  refuses to wrap a recognized general-purpose browser    │
│         │  without explicit confirmation of full-process scope     │
│         ▼                                                          │
│  Target process ──── real, untouched TLS handshake ────────────────┼──► real remote server
│         │  writes session secrets to SSLKEYLOGFILE as it goes      │    (unmodified traffic,
│         │  (its own TLS library's built-in, standard behavior)     │     unmodified cert chain,
│         ▼                                                          │     no redirection, ever)
│  Rust capture agent (1a, unchanged capture path — still passive,   │
│  still unprivileged access_bpf, still cannot drop/delay/redirect   │
│  a single packet — that invariant is preserved by this whole spec; │
│  core dumps disabled at startup, unconditionally)                  │
│   ├─ pcap capture of this process's flows (already happens today)  │
│   ├─ TLS ClientHello parse → SNI (1a) + cipher/ext list → JA3 (new,│
│   │    Tier A, ALL connections, no opt-in needed)                  │
│   ├─ KeyLogWatcher (new, Tier B) — tails the key-log file for      │
│   │    decrypt-eligible PIDs only; combines w/ captured ciphertext │
│   │    → local TLS-record decrypt, in memory only, mlock'd +       │
│   │    zeroed-on-evict ring buffer, entirely after the fact        │
│   │    (never on-path, never delays a packet)                      │
│   ├─ Header redaction pass (new, Tier B) — strips Authorization/   │
│   │    Cookie/Set-Cookie/API-key header values before buffering    │
│   │    or emission; body content is NOT redacted (named limit)     │
│   └─ HTTP/2 reassembly + HPACK decode (new, Tier B) — per-connection│
│        byte-stream reassembly ahead of frame parsing; whole-        │
│        connection fallback to ciphertext-only on any gap/desync     │
│         │ NDJSON: decrypted_payload (new, mTLS-gated — see below), │
│         │ ja3Fingerprint (new field on existing connection event)  │
│         ▼                                                          │
│  Next.js relay (unchanged transport pattern — SSE, same singleton  │
│  AgentClient shape 1a/2 already established)                       │
│         ▼                                                          │
│  Browser: ConnectionsView (JA3, Tier A, always) /                  │
│           PacketStreamView (decrypted bytes, Tier B, opt-in only,  │
│           persistent "Decrypting traffic for… (full-process scope  │
│           if browser-wrapped)" banner while live)                  │
└────────────────────────────────────────────────────────────────────┘

NOT BUILT (Draft B's design, preserved below as a reference for a possible future,
independently-approved sub-project — see "Rejected for now"):

  mitm-proxy (separate privileged binary, dedicated Secure-Enclave CA,
  system-proxy traffic redirection, leaf-cert forgery per SNI)
```

No new listening port, no new privilege boundary, no new trust-store entry anywhere in the built design. The agent's passive, cannot-alter-traffic invariant — the property Draft B itself identifies as the reason `mitm-proxy` would have needed to be a separate binary — is never broken by this spec.

## Components

### 1. `capture-agent/src/parse.rs` — JA3/JA4 extraction (Tier A)

- Pure, stateless extension of the existing ClientHello parser: same bytes already parsed for SNI, standard JA3 algorithm (MD5 of a normalized, comma-joined field list), computed once per handshake, no state retained beyond the flow table entry.
- Same untrusted-input posture as the rest of `parse.rs`: `Option`/`Result` throughout, folded into the existing `cargo-fuzz` target — same input, one more derived field, not a new attack surface warranting a new target.
- Fingerprint *matching* (hash → human label) is a small, versioned, hand-maintained lookup table shipped in the repo — not a live third-party lookup.

### 2. `osi-inspect` — the opt-in wrapper (Tier B)

- Generates a fresh random key-log filename under the app's data directory, `chmod 0600`s it before the target process can write to it, sets `SSLKEYLOGFILE`, execs the user's command as a direct (not detached) child, and on exit — success, failure, or signal — deletes the key-log file via deferred cleanup.
- **Browser-wrap confirmation:** before launching, checks the target binary's basename against a small hardcoded list of known general-purpose browsers (`chrome`, `chromium`, `msedge`, `firefox`, and common platform variants of those names). If matched, prints the full-process-scope warning ("this will decrypt ALL tabs and origins currently open or later opened in this browser process — not just one site") and requires an interactive `y`/`N` confirmation, or the `--yes-decrypt-entire-browser` flag for non-interactive use. Non-browser targets proceed without this prompt.
- Writes the launched PID (and best-effort observed child PIDs) to a small "decrypt-eligible" registration the agent polls/is notified of. The agent decrypts only flows attributed, via `process_lookup.rs`, to a PID on that list, for the PID's lifetime.
- Deliberately **not persistent**: no config flag makes an app "always decrypt-eligible." Every session is a conscious, one-command act, mirroring sub-project 2's "runtime-only, never persisted" opt-in precedent.
- Startup orphan sweep (see Scope) deletes stale key-log files from a prior unclean exit before creating a new one.

### 3. `KeyLogWatcher` (agent-side, Tier B)

- File-event-based tail (not poll-in-a-loop) of the key-log file(s) for currently-eligible PIDs; parses `CLIENT_RANDOM`/TLS-1.3-labeled secret lines per the standard `SSLKEYLOGFILE` format; holds secrets in memory only for the eligible PID's lifetime — never written to the agent's own disk in any form.
- Decryption applies to ciphertext the agent's existing capture path already holds for that flow. A decrypt failure (missing key, out-of-order records, unimplemented cipher suite) degrades to "ciphertext only, same as today" — never a crash, never a wrong-plaintext render.
- **Header redaction** runs on the decrypted, reassembled application data before it is written into the ring buffer or emitted: `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`, and pattern-matched bearer tokens are replaced with `[REDACTED]`, header name kept. This is enforced pre-buffer and pre-emission (not a display-layer filter in the browser), so it also protects a compromised relay hop or an unexpected viewer. Body content is explicitly not scanned — named limitation, not silently absent.
- Decrypted output is subject to the same capped-ring-buffer discipline already fixed for the raw packet stream (#27) — bounded per connection, never unbounded accumulation, never spilled to disk. The buffer's backing allocation is `mlock`'d (best-effort hardening against swap, not an absolute guarantee — `RLIMIT_MEMLOCK` and macOS pager behavior mean this cannot be claimed as complete) and explicitly zeroed via a dedicated zeroing primitive on eviction, rather than relying on Rust's default `Drop` alone.

### 4. HTTP/2 stream reassembly & HPACK handling (agent-side, Tier B)

An earlier draft of this spec treated HTTP/2 as "just structure inside bytes we already have." That understated the real work, and this component replaces that one-liner with an honest design:

- TLS records don't align with HTTP/2 frame boundaries. A per-TCP-connection **byte-stream reassembly buffer** sits between `KeyLogWatcher`'s decrypted record output and the HTTP/2 frame parser, appending decrypted payloads in TCP sequence order (using the sequence-number tracking the agent's existing capture path already performs for stream reconstruction) before frame parsing begins.
- HPACK's dynamic header table is **stateful and order-dependent** for the life of the connection — unlike a single bad TLS record, which degrades gracefully per-record, a gap or reordering in the reassembled byte stream desyncs the entire HPACK decoder for that connection. There is no safe per-frame recovery for header blocks once desync occurs; a partial/guessed decode risks rendering corrupted or misattributed header names, which is worse than an honest "unavailable."
- **Fallback behavior:** the moment reassembly detects a gap or the HPACK decoder rejects a header block as structurally invalid, the *entire remaining connection* (not just the affected frame) is marked "decrypted framing unavailable" and reverts to ciphertext-only display for anything after that point. Frames already parsed before the desync point remain visible. This whole-connection fallback is explicitly different from — and coarser-grained than — the per-record "undecryptable" fallback used elsewhere in this spec, and is called out as such rather than conflated with it.
- **UI demuxing:** decrypted HTTP/2 content in `PacketStreamView` is grouped by HTTP/2 stream ID within the connection, not shown as one interleaved blob, so a multiplexed connection's decrypted content is legible the way a browser's own devtools would show it.
- New, self-contained, attacker-reachable-input code (frame bytes originate from real remote servers, not just the trusted-by-construction wrapped process) — same fuzzing/testing bar as `l7.rs` and `parse.rs`'s entry point, explicitly including out-of-order and truncated reassembly scenarios in addition to malformed individual frames (see Testing).
- If an external HPACK-decoding crate is used rather than hand-rolled, it gets the same extra-scrutiny dependency review `docs/security.md` calls for on security-critical dependencies (see Dependency hygiene).

### 5. Wire/event and data model changes

- `ja3Fingerprint?: string` / `ja3Label?: string` on the existing connection/layer wire shape and `NetworkConnection`/`OSILayerInfo` types — Tier A, always-on, no gating.
- New `decrypted_payload` NDJSON event (Tier B only, decrypt-eligible flows only), mapped by a new `lib/decrypted-mapping.ts` kept separate from `agent-mapping.ts` — same reasoning that kept `enrichment-mapping.ts` separate in sub-project 2: different trust/sensitivity characteristics than the always-on wire types. Includes a `streamId?: number` field for HTTP/2 demuxing and a `redacted: boolean` marker on any segment where a header value was stripped, so the UI can render the placeholder distinctly from real content.
- `docs/wire-protocol.md` updated for both additions, since both originate agent-side.
- **Transport gating, tightened from Draft A's original language:** Draft A's first pass only *flagged* the decrypted-payload SSE path as a "hard prerequisite, not a nice-to-have" before use over 1b's LAN access, without a concrete enforcement mechanism. This synthesis adopts Draft B's concrete mechanism instead of a documented intention: `decrypted_payload` is refused outright over any non-loopback listener, and once 1b lands, is additionally gated to require the mTLS-authenticated path independent of whatever posture the rest of `/api/stream` has — mirroring Draft B's §6 exactly. This costs nothing extra to build now (loopback-only is already the default) and closes the gap before it can be forgotten later.

### 6. UI surface

- Tier A: JA3 hash + best-effort label in `ConnectionsView`'s detail panel next to Ownership, always populated when a handshake was parsed, no toggle.
- Tier B: `PacketStreamView` gains a per-connection "Decrypted" badge only for decrypt-eligible processes; decrypted bytes render as plain text (same `no-dangerous-html.test.ts`-audited posture as every other network-sourced string) alongside the existing ciphertext view — additive, never replacing it. Redacted header values render as a visibly distinct `[REDACTED]` placeholder, not blank or silently omitted.
- A visible, persistent banner while any process is decrypt-eligible — `"Decrypting traffic for: <command> (pid NNNN)"`, extended with `"— entire browser process, all tabs/origins"` when the wrapped target was a browser confirmed via the full-process-scope prompt — adopted from both drafts' independent agreement that this state must never be ambient or silent, unlike JA3 display.
- When a wrapped process produces zero decrypted flows, the UI states plainly "no TLS libraries in this process wrote key-log data" rather than implying a bug — Safari/pinned-app coverage gaps are named, not hidden behind a blank state.
- When an HTTP/2 connection falls back to ciphertext-only mid-stream (Components §4), the UI states this plainly ("decrypted framing unavailable after this point — showing ciphertext") rather than silently reverting.

## Setup & operations

**One-time setup:** none. No CA, no keychain entry, no elevated privilege, no config file.

**Per-session use:**
1. `osi-inspect npm run dev` (or any command) instead of running it directly.
2. The already-running agent picks up the new PID as decrypt-eligible automatically.
3. Exit the wrapped command normally; the key-log file is deleted and the PID drops out of eligibility. Nothing persists.

**Coverage is real but partial, and the UI says so:** works for anything honoring `SSLKEYLOGFILE` — Chrome/Chromium/Edge, Firefox, curl/OpenSSL-linked CLI tools, Node.js, CPython's `ssl` module (3.8+). Does **not** work for Safari/WebKit, most closed-source GUI apps, or certificate-pinned apps whose key material never reaches the process's standard TLS library hook.

**Prefer single-purpose targets.** `osi-inspect` is most useful — and least risky — pointed at a single dev server, CLI tool, or test harness. Wrapping a full multi-tab browser decrypts every origin open in it, not just the one you meant to inspect, and requires the explicit confirmation described in Components §2. If you must wrap a browser, prefer a dedicated/temporary profile with only the tab(s) you intend to inspect open, and treat the whole session as sensitive — every other origin open in that process is decrypted and broadcast to every attached viewer too.

**Redaction is best-effort, not complete.** Known sensitive headers are stripped automatically. Credentials or tokens embedded in request/response bodies (login forms, JSON API payloads) are not — anyone viewing the decrypted stream while it's live sees those in full.

## Security model summary

| Threat | Mitigation |
|---|---|
| Device-wide trust compromise from a MITM root CA (the issue's literal ask) | **Not built, and not deferred as a later phase of this sub-project.** No new CA exists anywhere in the shipped design — see "Rejected for now" for the full reasoning and the conditions under which that could be revisited as its own, separately-approved sub-project |
| CA private-key theft granting whole-device HTTPS interception | This sub-project adds **zero incremental CA risk** — no new CA, no new key, nothing new to steal. That is a narrower claim than "not a risk," and this table states the baseline plainly rather than implying otherwise: the client-auth CA sub-project 1b already shipped (mkcert-based) is **not narrow-blast-radius** today — because `mkcert -install` trusts it as a system/browser root, its key already grants whole-device, any-hostname HTTPS interception if stolen, independent of anything in this spec (see `docs/security.md`'s existing warning). This spec neither creates nor reduces that pre-existing exposure. (Preserved for the record: if MITM is ever revisited, Draft B's requirement of a *distinct*, Secure-Enclave-backed, non-extractable CA key — never reusing the mkcert key, which is exactly the key already carrying this exposure today — is the correct starting point, not reuse.) |
| Certificate-pinned apps breaking silently under interception | N/A — Tier B never touches the real handshake or cert chain, so pinning never triggers. This is also the concrete reason a MITM proxy would not have reliably delivered "full DPI" even if built |
| Key-log file (`SSLKEYLOGFILE`) read by another local process/user | `0600` permissions set before the target process can write to it; lives under the app's own data directory (same posture as sub-project 2's cache/log files); deleted on wrapped-process exit including crash; orphan sweep on `osi-inspect` startup |
| Decrypted content contains live credentials (session cookies, `Authorization`/bearer tokens, API keys) broadcast to every browser session attached to the relay | Agent applies a best-effort **header-redaction pass** before content enters the ring buffer or is emitted: `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`, and pattern-matched bearer tokens are replaced with `[REDACTED]`. This is not exhaustive — credentials in request/response **bodies** are not automatically redacted and remain fully visible to every attached viewer; the persistent banner and docs say this plainly rather than implying full credential safety |
| Decrypt-eligibility is per-process, not per-destination-host — wrapping a general-purpose browser (explicitly listed as supported) decrypts every open tab/origin in that process, not just the intended one | `osi-inspect` detects common browser binaries and requires explicit interactive confirmation (or `--yes-decrypt-entire-browser`) before proceeding, stating the full-process scope plainly; the persistent UI banner states the same when active. True per-origin scoping is not feasible with a key-log-based design and is named as an accepted limitation, not solved |
| Decrypted plaintext persisted to disk (swap, log, cache) anywhere in this sub-project's own code | No `write()`/`open()`-for-write call on the decrypted-record path (enforced, tested — see Testing); ring-buffer memory `mlock`'d and explicitly zeroed on eviction. The `mlock` protection is stated as **best-effort hardening against swap, not a guarantee** — subject to `RLIMIT_MEMLOCK` and platform pager behavior — rather than claimed as complete, closing the gap where an earlier draft named swap as a threat but only tested for explicit write syscalls |
| Agent process crash while holding decrypted plaintext writes a macOS core dump to disk | Core dumps disabled for the agent process (`RLIMIT_CORE=0` or platform equivalent) unconditionally at startup — cheap, no functional downside |
| Scope creep: a wrapped process's child spawns unrelated long-lived services that inherit the env var and stay decrypt-eligible after the original command exits | Eligibility tracked by PID/process-tree membership, torn down when the wrapper's direct child exits; a detached grandchild that outlives the wrapper is a known, narrow edge case called out for explicit test coverage, not silently assumed safe |
| Agent gains the ability to read decrypted application content — a new capability class even though it uses no new *privilege* | Named explicitly: qualitatively more sensitive than 1a's ciphertext-only or 2's metadata-only posture. Mitigated by scope (opt-in, per-process, per-run), redaction of known-sensitive headers, and by the agent's own privilege model staying unchanged (`access_bpf`, no `sudo`) |
| Decrypted plaintext relayed to the browser over an internal hop, including once 1b's LAN access is live | `decrypted_payload` refused outright over any non-loopback listener; once 1b lands, additionally requires the mTLS-authenticated path independent of the rest of `/api/stream`'s posture — a concrete gate adopted from Draft B's §6, not just a documented intention |
| Relay-wide exposure: any browser session attached to the relay sees Tier B's decrypted events, not just the session that ran `osi-inspect` | The relay-wide-toggle *mechanism* mirrors sub-project 2's limitation, but the **severity does not** — sub-project 2 broadcast non-sensitive ownership/ASN metadata; this broadcasts live application content, potentially including credentials that survived redaction gaps (bodies) or that predate redaction being applied correctly. Treated with matching severity, not casually inherited: mandatory persistent banner plus the header-redaction pass above. A genuinely per-viewer-scoped decrypted stream is not solved by this spec and is named as a real, open gap rather than papered over |
| Attacker-controlled decrypted content (literal HTTP response bodies) rendered unsafely in the UI | Plain text rendering only, no `dangerouslySetInnerHTML`, covered by `no-dangerous-html.test.ts`'s regression suite, explicitly extended to this higher-stakes content type in its fixtures |
| Malicious/adversarial target process supplying bogus key-log data | Out of scope by design — the target process is one the user deliberately chose to run through the wrapper, as themselves; it is not an adversary in this threat model. Worst case is garbage "decrypted" bytes for a connection, not a privilege or confidentiality violation |
| JA3/JA4 fingerprint spoofing (trivially claimable by any client) | Documented as best-effort/informational only, never treated as an authenticated identity signal — same "don't overclaim certainty" posture sub-project 2 applied to registry-derived ASN data |
| Oversized decrypted-payload stream exhausting memory/UI | Same capped-ring-buffer discipline already fixed for the raw packet stream (#27), applied identically here |
| A user assuming "TLS interception shipped" means whole-device inspection | Addressed head-on in Purpose and Setup's explicit per-app coverage statement, plus a UI string stating plainly which processes are and are not currently decrypt-eligible — never implied to be "everything" |
| HTTP/2/QUIC frame parser (new code parsing attacker-reachable decrypted bytes) mishandling malformed or out-of-order input | Same defensive posture as `l7.rs`'s existing sniffers and `parse.rs`'s fuzzed entry point — `Option`/`Result` throughout, added to fuzz coverage before shipping, including reassembly-level out-of-order/gap scenarios (Components §4), not just single malformed frames |

## Error handling & lifecycle

- **`osi-inspect` target process exits (normal, crashed, or killed):** key-log file deleted, PID (and tracked children) removed from decrypt-eligibility immediately; already-emitted `decrypted_payload` events remain in the browser's existing state, but no new ones fire.
- **Key-log file missing/unreadable when expected:** treated as "not yet decrypt-eligible," not an error — watcher keeps watching the file's existence, not a fixed retry count.
- **A TLS record can't be decrypted** (unsupported cipher suite, out-of-order/missing key material, truncated capture): that record renders as "undecryptable" in `PacketStreamView`, ciphertext remains visible; never a crash, never a wrong-plaintext render.
- **An HTTP/2 connection's HPACK state desyncs** (gap or invalid header block after reassembly): the entire remainder of that connection falls back to ciphertext-only display; frames parsed before the desync point remain visible. This is a whole-connection fallback, distinct from the per-record TLS fallback above (Components §4).
- **Agent restart mid-session:** decrypt-eligibility state is in-memory only, does not survive a restart — matches sub-project 2's "opt-in never persists across restart" precedent.
- **JA3 on a malformed/truncated ClientHello:** returns `None`, same tolerance `parse.rs` already applies elsewhere; never blocks SNI extraction or any other working field.
- **Agent process crash of any kind while decrypt-eligible sessions are active:** core dumps are disabled agent-wide (see Security model summary), so a crash does not leave decrypted plaintext in a core file; already-buffered content is simply lost along with the process, matching the "memory only, no persistence" invariant.

## Dependency hygiene

- Tier A: pure Rust, no new crate beyond whatever standard JA3 MD5 hashing already exists (or is added once) in the tree.
- Tier B: `osi-inspect` is plain Node using only built-ins (`child_process`, `fs`, `crypto`) — zero new npm dependencies, matching the precedent sub-projects 1a and 2 both set. `KeyLogWatcher`, the TLS-record decrypt math, the HTTP/2 reassembly/HPACK component, and the zeroing/mlock primitives are new Rust code; any TLS/crypto crate, HPACK-decoding crate, or memory-hardening crate (e.g. for zeroing or `mlock`) pulled in for this gets the extra-scrutiny treatment `docs/security.md`'s dependency-hygiene section calls for on anything security-critical.
- `npm ci`, `ignore-scripts=true`, exact pinning — unchanged, repo-wide policy.

## Testing

- **JA3 correctness:** fixture-driven tests against known ClientHello captures with known-correct JA3 hashes, plus malformed/truncated cases folded into `parse.rs`'s existing `cargo-fuzz` target.
- **`osi-inspect` file permissions and cleanup:** asserts the key-log file is `0600` *before* the child process starts, and is deleted on normal exit, non-zero exit, and termination signal.
- **Browser-wrap confirmation:** wrapping a recognized browser binary without confirmation or the `--yes-decrypt-entire-browser` flag refuses to proceed; with either, proceeds and the eligibility registration/banner state reflects full-process scope.
- **Decrypt-eligibility scoping:** a flow belonging to a non-eligible PID never triggers `decrypted_payload` even when a key-log file happens to exist on disk from an unrelated prior run.
- **Decryption correctness:** integration test — real loopback TLS traffic from a test server, client wrapped with `osi-inspect`, asserts the agent's decrypted output matches the plaintext actually sent. The load-bearing end-to-end proof for this whole tier.
- **Decrypt failure paths:** explicit tests for missing keys, out-of-order records, unsupported cipher suite — each asserting graceful "undecryptable" marking, never a panic or silent garbage output.
- **Header redaction:** fixtures containing `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, and bearer-token-shaped values assert they are replaced with `[REDACTED]` *before* entering the ring buffer and *before* emission — not just filtered at render time. A companion fixture with body-embedded credentials asserts (documenting the known gap) that body content is passed through unredacted.
- **No-disk-write invariant:** a test harness that fails if any `write()`/`open()`-for-write syscall occurs on the decrypted-record code path during a simulated decrypt session — adopted directly from Draft B's equivalent MITM test, applied to this design's own plaintext-handling path.
- **`mlock`/zeroing best-effort check:** asserts the ring buffer's allocation path invokes the memory-locking primitive and that evicted buffer contents are overwritten (not merely dropped) — explicitly framed as testing "the hardening was applied," not "swap is impossible," matching the documented best-effort claim.
- **Core-dump-disabled check:** asserts `RLIMIT_CORE` is `0` (or platform equivalent) immediately after agent startup, unconditionally.
- **HTTP/2 frame parser and reassembly:** fixture-driven tests with deliberately malformed frames (same rigor as `l7.rs`'s sniffer tests) plus dedicated out-of-order/gapped-delivery fixtures asserting the whole-connection ciphertext fallback triggers correctly and that frames parsed before the desync point remain intact; all added to fuzz coverage before shipping.
- **Rendering safety:** decrypted-payload fixtures containing HTML/script-like content added to `no-dangerous-html.test.ts`, including fixtures with `[REDACTED]` placeholders to confirm they render distinctly rather than as blank/omitted content.
- **`decrypted_payload` transport gating:** a test asserting the event is refused over any non-loopback listener, and (once 1b's auth context exists) never emitted over a non-mTLS-verified connection.
- **Relay-wide exposure banner:** a component test asserting the "Decrypting traffic for…" banner renders whenever any process is decrypt-eligible, regardless of which browser session triggered it, and that the extended "entire browser process" wording appears when applicable.
- **Coverage-mismatch UX:** wrapping a process that never writes key-log data surfaces the explicit "no TLS libraries wrote key-log data" state, not a silent no-op.

## Rejected for now: full device-wide MITM proxy

This section preserves Draft B's design intact — not because it's wrong engineering, but so a future maintainer who decides to pursue it doesn't have to redo the thinking. It is **not part of this sub-project** and is not approved by this spec.

### Why it's rejected now, honestly, not just "hard"

- **Corrected framing (per adversarial review) — this is not "zero CA risk today" vs. "new CA risk if built."** An earlier draft of this section described 1b's client-cert install as "narrow, single-purpose" and contrasted it against a hypothetical MITM CA's "any hostname on the internet" blast radius, as if the latter were a wholly new category of risk this sub-project would introduce. That's not accurate. Per `docs/security.md`, sub-project 1b's already-shipped mkcert CA is, today, a system/browser-trusted root: *"because `mkcert -install` adds that CA to your system and browser trust stores, that same key can also mint a server certificate for any hostname on the internet and MITM your own browsing. This is the single highest-value secret this design creates."* The whole-device, any-hostname MITM blast radius this section warns about isn't a hypothetical future risk unique to a MITM proxy — it is a live property of the CA this repo has already shipped, independent of whether sub-project 4 builds anything.

  The distinction that actually holds up is narrower: a MITM proxy sub-project would either (a) put that existing dangerous capability into *active, routine use* — signing leaf certs continuously at proxy runtime rather than issuing certs occasionally during setup, which multiplies how often the capability is exercised and how much new code touches it — or, if Draft B's own recommendation of a *distinct* CA is followed, (b) add a **second** system-trusted root, doubling the number of "please don't leak this" trust anchors on the machine rather than introducing the first one. Either framing is real, and still supports not building this now — it's just not "categorically new," and this document no longer claims it is.
- **It requires a privilege the agent deliberately doesn't have**, and Draft B's own architecture concedes this by requiring a *separate* privileged binary specifically so the passive agent's trust story isn't contaminated for users who never opt in. That's the right engineering call *if this is built* — but it's also an admission that this sub-project would be adding a whole new privileged component to the repo, not extending an existing one.
- **It doesn't reliably deliver the goal even with maximal hardening.** Certificate-pinned apps reject the forged chain and simply stop working rather than being inspected. HTTP/3 is invisible to it end to end by Draft B's own scope. Non-proxy-aware software bypasses it silently. "Full DPI of encrypted traffic" was never fully achievable this way — which weakens the case for taking on the CA-based trust anchor to get partial coverage of it.
- **It would deepen an already-documented weak point rather than create an unrelated new one** — see the corrected framing above. Whether via heavier use of the existing CA or a second CA, this sub-project would be adding real, additional exposure on top of a baseline that `docs/security.md` already flags as the repo's single highest-value secret.
- **The engineering cost is not small, and parts of it are unquantified even in Draft B's own reference design (see below).** Secure Enclave key provisioning, per-session (not per-signature) biometric-gated signing with an explicitly *named* weakening versus the existing client-cert precedent, an in-memory LRU leaf-cert cache, mandatory origin certificate validation on the outbound leg (without which the feature makes the user *less* safe from a real attacker's MITM, not just "observed by their own tool"), forced ALPN downgrade to HTTP/1.1, `mlock`'d/zeroed/no-core-dump plaintext handling, 7-day CA expiry, and dual-trust-store (Keychain *and* Firefox NSS) revocation tooling. None of this is optional if the feature is built responsibly — Draft B is right that it's all load-bearing — which is exactly why it's a large, standalone undertaking rather than an add-on to sub-project 4.

### Known gaps in Draft B's own reference design, preserved honestly rather than smoothed over

Two gaps surfaced by feasibility review remain unresolved in the reference design as written. They don't change the rejection, but a future implementer needs to close them, not inherit them silently:

- **Per-connection cert-generation performance is asserted, not quantified.** The design leans on "an in-memory LRU leaf-cert cache" and a shift from per-signature to per-session Secure Enclave signing, explicitly flagged as a "named weakening" of the client-cert precedent — which means the design already knows per-signature Enclave signing is too slow to do on every connection, but never says by how much. There is no Secure Enclave ECDSA sign latency figure, no target time-to-first-byte budget, no cache size/eviction policy, and no analysis of a cold-cache burst (a single page load routinely opens TLS connections to 20-50+ distinct SNIs — CDNs, ad/analytics, fonts, APIs — each triggering a first-touch signature, potentially concurrently). "Session" itself is undefined: whether the Enclave key stays resident for one `osi-inspect` invocation or something shorter is a real security/performance tradeoff neither drafts analyze in either direction. No comparison point (e.g. mitmproxy's or Charles's own leaf-cert caching numbers) is cited to ground a claim that this is fast enough to be usable.
- **The ALPN-downgrade mitigation names the technique but not its costs.** "Forced ALPN downgrade to HTTP/1.1" is a real, known way to sidestep HTTP/2 multiplexing at a MITM boundary, but its side effects are never enumerated: loss of multiplexing/performance for the user's real connections, breaking servers or apps that require HTTP/2, and the downgrade itself being a passive, detectable signal to the origin server (and potentially to the user) that interception is occurring — which cuts against Draft B's own "closes real gaps" framing for choosing this approach.

Any future implementation of this design needs a dedicated feasibility spike on both points before "correct starting point" can mean "buildable as specified."

### Preserved disclosure copy (Draft B §7)

The prior version of this document cited Draft B's §7 disclosure flow by section number rather than reproducing its wording — the one artifact in this whole section where reconstruction-from-scratch risk is highest, since architecture and test plans are the kind of thing a competent engineer can rebuild from a spec, but the literal sentence a user reads in a "trust this?" dialog is not. That citation-only treatment is corrected here. (Note for provenance: the original two drafts under review did not themselves preserve Draft B's exact §7 wording verbatim in a form recoverable by this synthesis — only the section reference survived. Rather than repeat that gap one layer deeper, this revision writes concrete literal copy now, so a future implementer starts from real wording rather than a second by-reference citation.)

Minimum required disclosure text, to be shown as an explicit, non-dismissible-by-accident consent step (typed confirmation, not a single click) before any future MITM CA is ever installed:

> **This will let your Mac forge any website's identity to you.**
>
> [App name] wants to install a certificate authority (CA) on this device. Once installed:
>
> - This Mac will be able to generate certificates that make **any website** — including your bank, your email, your employer's login page — appear valid and trusted to this device's browsers and apps, whether or not you are actively using [App name] to inspect that specific connection right now.
> - **This is a fundamentally bigger grant of trust than the device certificate you installed for LAN access.** That certificate only lets this app's own dashboard recognize this specific device — it cannot be used to impersonate any other website. This CA can.
> - If the key behind this CA is ever stolen, misused, or leaked, whoever holds it can intercept and read HTTPS traffic on this device for any site, not just the ones you intend to inspect.
> - Some apps (certificate-pinned apps) will simply stop working while this is active, rather than being inspected.
> - Traffic sent over HTTP/3 or QUIC will not be visible through this feature regardless.
>
> Type `INSTALL FORGERY-CAPABLE CA` to confirm you understand this device will be able to impersonate any website's identity until you remove this CA.

This is the floor, not the ceiling — a future implementation may add more (screenshots, a link to this spec, a shorter re-confirmation on each renewal), but must not ship with less than the plain-language forgery statement and the explicit named contrast against 1b's client-cert flow.

### What would have to be true to revisit it

Per Draft B's own closing paragraph, this is a legitimate future decision, but only as **its own, from-scratch spec with its own dedicated security review** — never a natural next phase of Tier B above, which is architecturally passive by design and doesn't lead toward MITM incrementally. Concretely, reopening it would need:

1. A demonstrated, specific gap that Tier A/B genuinely can't close — most plausibly Safari-only workflows, since that's the one major, non-niche client this design cannot reach at all.
2. A commitment to build the full hardening stack Draft B specifies, not a cut-down version — in particular the distinct-from-mkcert Secure Enclave CA, mandatory origin validation, and the no-disk-write plaintext invariant are not negotiable simplifications.
3. **The disclosure requirement, made concrete rather than qualitative.** The prior version of this condition required the UI to state that coverage is partial and that this is "a bigger trust grant than everything else this repo has shipped" — vague comparative language that a user already habituated to approving 1b's client-cert prompt could plausibly click through as "more of the same, turned up." This condition is now satisfied only by disclosure copy that, at minimum, matches the "Preserved disclosure copy" above: a literal sentence naming the forgery capability in plain terms ("this device will be able to impersonate any website's identity"), and an explicit named contrast against 1b's already-shipped client-cert flow, not a superlative comparison alone.
4. **A resolved, quantified answer to the cert-generation performance gap named above** — real Secure Enclave signing latency numbers, a defined "session" scope for key residency, and a concurrency/burst analysis for the 20-50+ simultaneous-SNI page-load case — before "the correct starting point" can be treated as buildable-as-specified rather than aspirational.
5. Its own dependency-hygiene and fuzzing bar for a brand-new privileged component handling untrusted ClientHello input (`mitm-proxy`'s TLS termination path), matching what `capture-agent/src/parse.rs` already meets.

If those conditions are met, Draft B's Components §1-9, Security model table, and Testing plan above (in the original two drafts under review) are the correct starting design — reuse them rather than re-deriving — with the performance and disclosure gaps above closed as part of that future work, not carried forward unresolved.

## Deferred to later sub-projects / follow-ups

- **JA3↔RDAP org correlation** ("this org's IP, but a client fingerprint that doesn't match their known stack") — real value, own analysis feature on top of two already-shipped data sources, not core plumbing.
- **Orphaned key-log file sweep** — folded into Tier B's own implementation (Components §2) rather than left as a standalone gap.
- **Per-destination-host scoping of decrypt-eligibility** — named as a real limitation of the browser-wrapping case (Scope, Security model summary), not solved in this sub-project; revisit only if a concrete design for host-aware filtering at the key-log layer emerges.
- **Automatic redaction of body-embedded credentials** — header redaction ships now; scanning bodies (form posts, JSON payloads) for credential-shaped content is a materially harder problem with real false-negative risk and is left for a future pass, not attempted here.
- **Full device-wide MITM proxy** — see "Rejected for now" above; its own future sub-project, its own approval, its own security review, not a phase of this one.
- **Multi-device CA distribution** — relevant only if MITM is ever pursued; noted so it isn't rediscovered from scratch.
- **Hardware-backed (Secure Enclave) CA signing key custody** — relevant only if MITM is ever pursued; Draft B's design (session-scoped signing, named weakening vs. the per-signature client-cert precedent) is the reference if that conversation happens, with the performance gap in "Rejected for now" closed first.
