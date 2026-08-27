# Security

## Current posture (localhost-only increment)

This tool captures and displays real, sensitive data about your own device: every process's network connections, remote IPs, DNS queries, TLS SNI hostnames, and raw packet bytes. Treat it accordingly.

**Where it stands today:**

- **Both processes bind to `127.0.0.1` only.** The capture agent listens on `127.0.0.1:9990`; `npm run dev`/`npm run start` explicitly pass `-H 127.0.0.1`. Nothing here is reachable from your LAN, from another device, or from the internet. If you deliberately expose either port (port-forwarding, a reverse proxy, changing the bind address), you are opting out of this protection yourself — don't do that without adding authentication first.
- **No authentication of any kind exists yet.** Anything that *can* reach these ports can read the full capture feed and pause it via `/api/control`. This is acceptable only because both are loopback-only.
- **The capture agent runs unprivileged at runtime**, via macOS's `access_bpf` group rather than `sudo`/root. If the agent process is ever compromised (e.g. a bug in its packet parser), the blast radius is "your BPF-group-scoped user," not "root."
- **The packet parser is hardened against its highest-risk input**: it parses untrusted, attacker-reachable network bytes (any device that can send you a packet can influence what the agent parses), so every parsing function returns `Option`/`Result` rather than panicking, and `capture-agent/src/parse.rs`'s entry point is fuzzed via `cargo-fuzz`.
- **No secrets or credentials are handled anywhere in this pipeline.**

## What's explicitly NOT done yet

- **No TLS, no encryption in transit**, anywhere — agent↔relay is plaintext TCP, relay↔browser is plaintext HTTP/SSE. Fine on loopback (traffic never leaves your machine's kernel); would not be fine over a real network.
- **No authentication** on the SSE stream or the control endpoint.
- **No LAN-access story yet.** A previous design pass considered this in depth (mutual TLS via a local CA, a Caddy reverse proxy enforcing client certificates, a native macOS app with a Keychain-backed client cert and a WKWebView locked to a single trusted origin) — see the design spec and the security research referenced in this repo's git history for that analysis. None of it is implemented; it's tracked as GitHub epic #22. **Do not attempt to expose this app to your LAN or the internet before that work lands** — there is currently nothing standing between an unauthenticated request and your full capture feed. (HTML-escaping of network-sourced strings is audited and regression-tested via `lib/__tests__/no-dangerous-html.test.ts` to prevent injection attacks via crafted DNS query names, HTTP paths, or process names.)
- **No TLS interception / decrypted HTTPS content.** The agent reads TLS SNI (which site) but never decrypts traffic content. Full content inspection would require a much more invasive MITM-proxy approach, which is a separate, not-yet-designed, explicitly-flagged-as-highest-risk sub-project (epic #25) — installing a trusted root CA on your own devices, breaking certificate pinning for some apps, and requiring its own dedicated security review before any implementation starts.
- **No ownership/reputation enrichment (WHOIS/RDAP)** on remote IPs or domains yet (epic #23) — you're seeing raw IPs and SNI hostnames, not who they belong to.

## Dependency hygiene

Given active, ongoing npm supply-chain attacks (compromised popular packages, credential-stealing worms propagating through maintainer accounts) are a real and current threat as of this writing, this repo enforces:

- `ignore-scripts=true` in `.npmrc` — disables all lifecycle scripts (`preinstall`, `postinstall`, etc.) during `npm ci`/`npm install`, reducing the attack surface of compromised dependencies that try to run arbitrary code at install time.
- `save-exact=true` in `.npmrc` — ensures all new dependencies are pinned to exact versions, not broad `^`/`~` ranges.
- Always use `npm ci` (not `npm install`) in any automated/CI context — always installs exactly what the lockfile specifies.
- No new dependency should be added for something you can reasonably build with what's already in the tree, especially anything touching auth, crypto, or credential storage — fewer dependencies is fewer places a supply-chain compromise can hide.
- If you add a dependency and something in your editor/IDE config changes that you didn't make (tasks, extensions, settings files), treat that as a signal to investigate before dismissing it — implanted editor config has been an observed persistence mechanism in real npm worm campaigns.

## Reporting a security issue

This is a personal/hobby project without a formal disclosure program. If you find a real vulnerability (not just "there's no auth yet" — that's a known, documented, intentional gap at this stage), open a GitHub issue or reach out directly rather than a public PR with exploit details, so there's time to fix it first.

## If you're extending this project

- Anything you add that increases what's captured, stored, or displayed should be weighed against the fact that this data is sensitive by nature (who you talk to, what sites you visit, what your devices do in the background).
- Before adding any feature that listens on a non-loopback address, stop — that's exactly the gap epic #22 is meant to close first, in a deliberate, reviewed way, not incidentally.
- If you add a new dependency, prefer well-audited, widely-used libraries for anything security-critical (TLS, credential storage, auth) over rolling your own — this is standard security engineering practice, not specific to this project, but worth restating given how much of this codebase deliberately avoids it in favor of vetted primitives (the OS Keychain, mkcert-issued certs, a reverse proxy's own TLS implementation) in the parts of the design that do touch security.
