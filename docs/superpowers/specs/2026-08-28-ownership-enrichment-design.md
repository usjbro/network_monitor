# Ownership Enrichment — Design Spec

**Status:** Approved for implementation planning
**Date:** 2026-08-28
**Sub-project:** 2 of 4 (capture ingestion → ownership enrichment → path visualization → TLS interception)

## Purpose

Sub-project 1a gives the app real `remoteAddr` values but no sense of who's on the other end — every remote endpoint is just an IP. This sub-project adds ownership context (org, ASN, country, and — as a second tier — domain registrant) so a user looking at `ConnectionsView` can tell "is this AWS, Cloudflare, my ISP, or something I don't recognize?" without leaving the app.

That lookup is also this app's first outbound network dependency of any kind. Every byte the app has moved so far — agent↔relay, relay↔browser — has been loopback or LAN-internal; a WHOIS/RDAP query is a new, automatic channel that tells a third-party registry which remote IPs this Mac is talking to. That makes this sub-project's design problem two things at once, not one: it has to produce genuinely useful ownership data (not just plumbing), and it has to treat every one of those third-party queries as a cost — to the user's privacy and to this repo's "narrow, unprivileged component does the risky I/O" precedent from 1a — that's paid deliberately and rarely, never as a default convenience.

That cost is bigger than any single query. Because the design deliberately reuses one stable home IP over a multi-week cache TTL, a registry that wanted to could assemble more than "this Mac looked up IP X once" — it could infer rough usage rhythm, the breadth of destinations investigated, and that this household runs a technical home-network-monitoring tool at all. This spec treats that aggregate/longitudinal exposure as a real, named risk (see Security model summary), not just the narrower "you're disclosing one IP per query" framing — both the disclosure text shown to the user and the mitigations below are built to be honest about it.

## Scope

**In scope — core (ships first):**
- RDAP lookup (RFC 7482/7483) for `remoteAddr`, resolved via the IANA IP RDAP bootstrap registry (`ipv4.json`/`ipv6.json`, cached locally with a long TTL) to the authoritative RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC), extracting org name, ASN, ASN-holder name, and country.
- **ASN is registry data, not routing data, and the spec is explicit about that limitation.** RIR RDAP IP-network responses describe the registered *allocation* (the `inetnum`/`network` object and its org entities), not the BGP-observed ASN currently announcing that prefix — those are different data sources (RDAP/WHOIS vs. a routing-table feed). `asn`/`asnOrg` are therefore best-effort, sourced only from registry-registered ASN blocks, and will legitimately come back empty for many address blocks where the registry record doesn't carry ASN data. That's an accepted, documented gap, not a bug to chase — see Permanently out of scope below for why it isn't closed by adding another provider.
- Skipping RFC1918, loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), and multicast ranges before any network call — never queued regardless of mode.
- A disk-persisted, CIDR-block-keyed, TTL cache with stale-on-failure and negative-result caching, as the primary privacy control (see Components §2).
- A hardcoded, numerically-specified, jittered, spaced outbound query shaper (concrete values in Components §5), independent of and stricter than per-registry 429 backoff, plus exponential backoff and a circuit breaker for actual registry pushback.
- Two-tier opt-in (on-demand default once enabled; background/whole-table mode requires a second, separately-worded confirmation), default **off**, with inline disclosure text shown every time it's activated (not just the first time ever) before either toggle.
- A new relay→browser-only data path: `connection_enrichment` SSE event, new optional `enrichment` field on `NetworkConnection`, a new `lib/enrichment-mapping.ts`. The agent and `docs/wire-protocol.md` are untouched.

**In scope — extended tier (ships second, same sub-project, not deferred):**
- Reverse-DNS resolution of `remoteAddr` to populate the existing (currently-unused) `remoteHostname` field, as the prerequisite for domain-level lookup.
- Domain RDAP lookup for the resolved hostname, using the IANA **domain-name** RDAP bootstrap file (`dns.json`) — a separate, independently-maintained bootstrap registry from the IP one used by the core tier (RFC 7484 defines these as distinct files; treating them as one mechanism, as an earlier draft of this spec did, was a factual error). Extracts **organization-level registrant fields only**; no personal-contact vCard fields are ever retained or forwarded to the browser.
- **Registry-to-registrar RDAP referrals are followed only against an allowlist, never blindly.** For thin gTLD registries (`.com`, `.net`, and most others), the registry-level RDAP response typically doesn't carry full registrant data itself — a compliant client is expected to follow a `links` entry in the response to the sponsoring registrar's RDAP server (RFC 7484-style referral). That URL comes from the response body, not from the bootstrap file, which makes it a distinct SSRF surface from "attacker supplies the request hostname" (see Components §5 for the full hardening story). This spec resolves it explicitly: a referral is followed only if its host matches a small, maintained allowlist of known registrar RDAP hosts kept alongside the RIR/bootstrap list; a referral to any other host returns `unavailable` rather than being followed. This means registrant lookup for some smaller or newly-added registrars may legitimately come back `unavailable` until their RDAP host is added to the allowlist — an accepted, documented tradeoff, not silently-broken behavior.
- Legacy port-43 WHOIS fallback, narrow and explicit: a short, code-maintained allowlist of known RDAP-gap cases (specific ccTLDs without RDAP, known legacy ARIN blocks), capped at a small initial size (target: five or fewer entries) precisely because each entry requires its own free-text response parser maintained against adversarial/malformed input — "zero new npm dependencies" describes the transport, not the effort, and this spec is explicit that the allowlist stays small for that reason rather than growing opportunistically. Never a general "RDAP failed, try WHOIS" catch-all. Implemented with Node's built-in `net` module (a plain port-43 TCP text client, mirroring how `agent-client.ts` already uses `net.Socket`), so this adds zero new npm dependencies.
- A lookup that's neither RDAP-eligible (including a non-allowlisted referral) nor on the WHOIS allowlist returns "unavailable" rather than escalating to broader WHOIS querying.
- Both extended-tier lookups are subject to the identical cache/rate/jitter/timeout rules as the core tier — there is no separate, looser path for them.
- **This split is a phase boundary within one committed scope, not an escape hatch — and that's intentional, not an oversight.** 1a's own "Deferred to later sub-projects" table already commits this sub-project to "WHOIS/RDAP lookups for IP org/ASN **and domain registrant**"; cutting registrant lookup here would silently break a commitment made in an already-approved spec, so extended tier is not deferred to a follow-up spec. What the phase boundary does buy: core tier is structured to be independently completable, mergeable, and (behind its own opt-in, default-off) shippable before extended tier lands, so a schedule slip mid-delivery still leaves a coherent, useful, non-broken increment rather than a half-built feature with nothing to show.

**Explicitly out of scope (deferred to later sub-projects):**
- Traceroute-based path visualization and per-hop geolocation — sub-project 3, which will consume this sub-project's cached ASN/org data as hop context rather than re-querying registries independently, with the same best-effort-ASN caveat carried forward.
- TLS interception / decrypted HTTPS content, and any enrichment derived from certificate-issuer fields — sub-project 4.
- Enrichment of traffic from devices other than the capture Mac — mirrors 1a's identical deferral for capture itself.
- **Per-session/per-viewer consent scoping.** The opt-in flag lives on the relay singleton (mirroring `AgentClient`), which means one person typing `enrich on` enables outbound queries — and reveals results — for every browser session currently attached to the relay, not just the one that toggled it. Today that's a single operator on a loopback-only relay, so the practical exposure is limited, but sub-project 1b (mTLS/Caddy LAN access) is explicitly designed to add multiple trusted viewing devices, at which point a relay-wide toggle stops matching a reasonable consent model. Building per-session consent now would require session-identity plumbing that doesn't exist anywhere in today's relay (there is no per-connection session concept on `/api/stream` at all) — real scope, and scope that belongs with 1b's own device/session model, not invented ad hoc here. This is a named, tracked limitation to resolve when 1b lands, not a silently-dropped concern.

**Permanently out of scope (not deferred to any sub-project — cut deliberately, revisit only via its own spec):**
- **BGP-derived/routing-table ASN attribution** (e.g., via Team Cymru's IP-to-ASN WHOIS service, RIPEstat's network-info API, or any other routing-table-backed feed). This would close the "ASN often comes back empty" gap noted above, but it's a different data source and a different third party than RDAP/WHOIS, with its own trust and disclosure characteristics — adding it is exactly the kind of "one more provider" scope creep the next bullet already rules out, and doing it well (understanding each provider's own rate limits, terms of use, and privacy posture) is a scoped effort in its own right. The `asn`/`asnOrg` fields stay best-effort registry data only; this is an accepted limitation of shipping this sub-project as RDAP/WHOIS-only, not an oversight to quietly patch later.
- Any lookup service beyond RDAP/WHOIS org/ASN/registrant data — no threat-intel feeds, no reputation scoring, no third-party enrichment APIs. Each additional provider is another party this Mac's activity gets disclosed to; that tradeoff deserves its own spec and its own privacy review, not a ride-along on this one.
- A general-purpose "look up any IP/domain" search UI — this sub-project only enriches connections the capture pipeline actually observed.
- Bulk/preemptive enrichment of full connection history on relay start — lookups are triggered by newly-observed connections (background mode) or user selection (on-demand mode), never a backfill sweep.
- **Application-level encryption-at-rest for the disk cache and query log.** Both stores get restrictive file permissions (Components §2, §8) and long-but-bounded retention, but this repo doesn't build its own encryption layer for local data anywhere else — it relies on the operator's OS-level disk encryption (FileVault). Adding a bespoke encryption layer for just this one store would be inconsistent with that existing posture and is out of scope here.

## Architecture

```
Capture Mac (today's actual deployment — loopback-only, no mTLS/Caddy yet)
┌───────────────────────────────────────────────────────────────┐   External registries
│ Rust capture agent (1a, unchanged)                              │   ┌───────────────────────┐
│  loopback TCP, NDJSON                                           │   │ IANA RDAP bootstrap    │
│         │                                                       │   │  ipv4.json / ipv6.json │
│         ▼                                                       │   │  (core tier)           │
│  Next.js relay (`next start -H 127.0.0.1`)                       │   │  dns.json (ext. tier,  │
│   ├─ AgentClient (1a, unchanged)                                 │   │  separate file/TTL)    │
│   │                                                               │   └───────────┬───────────┘
│   └─ EnrichmentClient (new) — lib/enrichment.ts             ─────┼───────────────┤ HTTPS, manual-
│        opt-in gate (default: off, runtime-only,                  │               │ redirect,
│        relay-wide — see "per-session consent" out-of-scope note)  │               │ timeout+size-
│        RFC1918/loopback/link-local/CGNAT filter                    │               │ capped,
│        disk-persisted CIDR/domain-keyed TTL cache (0600 perms)      │               │ batched+jittered,
│        separate outbound query log (0600, 30-day rotation)           │               │ cache-miss only
│        single-flight queue, concurrency=1, jitter, backoff            │   ┌──────────▼──────────┐
│        exponential 429 backoff + per-registry circuit breaker          │◄──┤ RIR / registrar RDAP │
│        referral URLs followed only if host on allowlist                 │   │ servers (JSON)       │
│         │ cache hit or fresh result                                     │   └──────────┬───────────┘
│         ▼                                                                │              │ text, cleartext
│  connection_enrichment (new SSE event, same /api/stream                    │◄─fallback,──┤ port 43 (WHOIS
│  connection browser already holds — not a new port)                         │  allowlist  │ allowlist only)
└───────────────────────────────────────────────────────────────────────────┼─only         └───────────────────
                    │                                                        └─────────────────────
                    ▼
         Browser (same-origin, loopback today;
         gains mTLS automatically once 1b lands —
         at which point the relay-wide consent gap
         above needs its own follow-up)
         ConnectionsView detail panel → "Ownership" section
```

The agent is untouched and still makes zero outbound calls. Only the already-unprivileged relay gains new egress, and only when the user has explicitly turned enrichment on in the current session. No lookup fires as a side effect of a connection merely appearing in the table.

## Components

### 1. `lib/enrichment.ts` — `EnrichmentClient`

- **Structure:** a singleton stashed on `global.__enrichmentClient`, deliberately mirroring `AgentClient`'s shape (EventEmitter-based, emits `'result'`/`'status'`) — one consistent pattern in this relay for "long-lived background client with a cache and event emission," not two.
- **Privilege model:** runs inside the existing unprivileged Next.js process. This is genuinely new capability for that process — its first outbound network call of any kind — so it stays confined to this one module, fully gated behind the runtime opt-in flag, and is never invoked from anywhere else in the relay.
- **Opt-in gate:** two levels. (a) *on-demand* — a lookup queues only when a human selects a connection row and expands the Ownership section; this is the default once enrichment is turned on at all. (b) *background* — lookups queue opportunistically for the whole visible table (still subject to §5's rate/jitter ceiling), in **randomized order**, never all-at-once on table load. (b) requires its own separately-worded confirmation, since it multiplies the number of registries contacted and the correlatable query volume. Note the relay-wide (not per-viewer) scope of this gate — see Scope's "Explicitly out of scope" note.
- **Disclosure surface:** shown before **every** activation of either toggle — not just the first time the app is ever used — since the runtime-only, non-persisted opt-in is only meaningful as an "informed, deliberate, non-default" control if the disclosure is actually re-read each time the flag gets re-armed. States plainly which registries/servers may be contacted, that this discloses "you are talking to IP X" to that registry *and*, over the cache's multi-week TTL, builds a longitudinal picture of usage rhythm and destination breadth (see Purpose), the cache TTL, and offers a one-click "clear cache, query log, and disable" action (renamed from "clear cache and disable" — see §8).
- **Scope limiter:** RFC1918, loopback, link-local, CGNAT, and multicast ranges are short-circuited before ever reaching the queue, in both modes — they can't resolve to a meaningful registry record and would only waste rate budget.
- **Hardening:** see §5 for the full SSRF story (request-controlled and response-controlled).

### 2. Caching (the primary privacy control)

- **Storage: a single flat JSON file** under the app's data directory (new — this repo has no pre-existing app data directory to reuse), written via write-to-temp-then-atomic-rename (never an in-place partial write), with **file permissions restricted to the owning user (`0600`)**. This is a deliberate, explicit decision (an earlier draft of this spec left "SQLite or a flat JSON store" unresolved, which isn't a decision) made for a concrete reason: all cache reads and writes are funneled through the single `EnrichmentClient` singleton's own in-process write queue, so there is no concurrent-writer problem to solve with a database engine — the concurrency story is "one process, one serialized writer," the same assumption `AgentClient` already makes about itself. This explicitly assumes a single relay process; if `next start` is ever run with multiple workers, that assumption breaks and would need revisiting before this cache is safe to reuse as-is — noted here rather than left implicit.
- **Keying:** by CIDR allocation block (not bare IP) for IP lookups — RDAP responses cover whole allocations, so caching at the returned prefix means an entire /24 or /20 of future connections resolves from cache after one real query — and by registered domain for hostname/registrant lookups.
- **TTL:** long, days-to-weeks range (14 days default, configurable), reflecting how stable ASN/org/registrant data actually is and explicitly favoring fewer registry contacts over freshness.
- **Stale-on-failure vs. negative caching — both, for different situations:** if a background refresh of an *already-cached* entry fails (network error, rate-limited, registry down, timeout), the last-known-good value is served with an "as of" timestamp rather than blanking or retrying. If a lookup has *never* succeeded (first-ever query for that block fails), the failure itself is cached with a short TTL (~1 hour) so a repeated bad/rate-limited lookup doesn't retry every time the same IP recurs in a session. A failed refresh must never turn into a retry storm either way.
- **No cache = no query implied by mere presence in the table:** entries are populated lazily per §1's triggers, never eagerly for every connection the agent reports.
- **Accepted residual-exposure property, named rather than glossed over:** because the cache is most effective for large, common allocations (AWS, Cloudflare, major ISPs), the queries that actually reach a registry skew toward rare/novel blocks — i.e., the self-hosted, niche, or unusual destinations that are most identifying in the first place. Caching reduces *total* query volume a great deal, but it does not reduce exposure uniformly across destinations; it concentrates the residual exposure on the most revealing subset of traffic. This is inherent to any cache-miss-triggered lookup design and is called out explicitly in the Security model table rather than left implied by "caching helps privacy."

### 3. RDAP primary, narrow WHOIS fallback (extended tier)

- **RDAP first, always**, via HTTPS JSON — structured entities/vCard contacts, no per-registry regex parsing for the core tier.
- **Legacy WHOIS fallback**, extended tier only, invoked solely for the specific known-gap cases on a short, explicit, code-maintained allowlist (certain ccTLDs without RDAP, known legacy ARIN blocks), capped at a small initial size for the reason given in Scope — never a generic "if RDAP fails, try WHOIS" catch-all. Implemented with Node's built-in `net` module (a plain port-43 TCP text client, mirroring how `agent-client.ts` already uses `net.Socket`), so this adds zero new npm dependencies. Response text is matched only against a strict per-registry allowlist of known field patterns — never general scraping — and treated as untrusted input, same posture the agent's parser gives untrusted packet bytes.
- **Confidentiality-in-transit is explicitly weaker on this path and the spec doesn't paper over it:** port-43 WHOIS is cleartext. The allowlist bounds *scope creep* (which registries get queried this way), but it does not bound *who can observe* an allowlisted query in transit — an on-path observer (the ISP today; potentially anyone on the local network once 1b's LAN access ships) can read both the query and the response. This is a distinct exposure from the RDAP path's HTTPS and gets its own row in the Security model table rather than being folded into the scope-creep mitigation.
- A lookup that isn't RDAP-eligible (including a referral to a non-allowlisted host) and isn't on the WHOIS-fallback allowlist returns "unavailable" rather than escalating to broader WHOIS querying.
- Fallback lookups are subject to the identical cache/rate/jitter/timeout rules as RDAP — no separate, looser path.

### 4. Reverse DNS + domain registrant (extended tier)

- Reverse-DNS resolution of `remoteAddr` via Node's built-in `dns.promises.reverse()` (no new dependency) to populate `remoteHostname`. This queries the relay's configured DNS resolver — **stated carefully, not overstated**: it's a new query the app itself generates (not a replay of some forward lookup the OS already made), and "the relay's configured resolver" may well be a third-party DNS provider (e.g. 1.1.1.1, 8.8.8.8) rather than the household's ISP, which is a different trust relationship than "the ISP already sees this." It's still generally lower-sensitivity than a registry query — it doesn't disclose intent or produce a durable per-IP registry record the way RDAP does — but it is a real, new disclosure to whichever resolver is configured, and the disclosure text and Security model table describe it that way rather than as "no new exposure."
- If reverse DNS resolves, a domain-level RDAP query fetches registrant data for the resolved domain via the `dns.json` bootstrap (see Scope's referral-allowlist note for the thin-gTLD case), or the WHOIS allowlist as a fallback. Only organization-level fields are extracted (registrant org name, country); postal address, personal name, phone, and email fields are discarded immediately on parse and never stored or forwarded to the browser.
- Subject to the same cache (keyed by domain), rate, jitter, and timeout rules as §2–§3, §5.

### 5. Outbound request shaping (query-timing privacy and SSRF hardening)

- **Rate ceiling, with actual numbers, not just "hardcoded low concurrency":**
  - Concurrency: **1 in-flight request at a time**, across RDAP and WHOIS combined.
  - Minimum spacing between distinct outbound queries: a randomized delay of **3–10 seconds**, redrawn per request, before the next queued lookup is dispatched.
  - Exponential 429 backoff: start at **30 seconds** (or the registry's `Retry-After` value, whichever is larger), doubling on each consecutive 429 from that registry, capped at **30 minutes**.
  - Circuit breaker: trips after **3 consecutive 429s from the same registry within a 10-minute window**; while tripped, that registry is not queried at all for a **1-hour cooldown** (stale cache values, if any, continue to be served during the cooldown).
  - Request timeout: **10 seconds** connect+read for both the RDAP HTTPS fetch and the WHOIS TCP read — with concurrency pinned at 1, an unbounded wait on one slow/non-responding registry would otherwise stall the entire queue indefinitely.
  - Max response size: **256KB** for RDAP JSON, **64KB** for WHOIS text; a response exceeding its cap is aborted mid-read and treated as a failure (subject to the same stale-on-failure/negative-cache handling as any other failure), never buffered in full before the allowlist field-matching in §3 gets a chance to run.
  - These are self-imposed and independent of per-registry 429 behavior, not merely reactive to it — RIRs throttle aggressively on undocumented thresholds, so a client-side ceiling stricter than any observed backoff signal is the actual control, not a fallback.
- **Batching and randomized order, not activity-ranked order:** in background mode, queued lookups are **shuffled** and spaced with the jitter above before dispatch. An earlier draft of this spec ordered background-mode lookups "most-active connections first" — that's a direct contradiction of the jitter's stated purpose, since it would preferentially expose exactly the connections carrying the most live traffic right now to the registry's query-timing view. Order is randomized instead, with no correlation to connection activity, recency, or any other signal a registry could use to line up query bursts with capture activity.
- **SSRF hardening covers both request-controlled and response-controlled URLs, not just the first:**
  - *Request-controlled:* registry/bootstrap hostnames used to make the initial IP or domain query come only from the IANA bootstrap response (`ipv4.json`/`ipv6.json`/`dns.json`) or a small static RIR list — never constructed from request-controlled input.
  - *Response-controlled (the more realistic vector for this feature):* the bootstrap response itself is third-party network data, so hostnames extracted from it are validated against an expected-domain shape before ever being dialed, not trusted blindly because they came from IANA's response body. All outbound `fetch` calls set **`redirect: 'manual'`** — Node's default of following redirects is never used — so a 3xx from any registry, including one of the narrower, less-well-maintained legacy WHOIS-fallback endpoints, cannot silently redirect a request to an internal address such as the capture agent's unauthenticated control channel (`127.0.0.1:9990`) or the relay's own `/api/control`. Response-embedded referral URLs (RDAP `links` entries used for the registry→registrar handoff described in Scope, `port43` fields, `notices[].links`) are followed **only** if their host matches the maintained allowlist described there; anything else resolves to `unavailable` rather than being dialed.
- **Bootstrap-only discovery:** the IANA bootstrap files route each query to the authoritative RIR/registry rather than hardcoding servers; each bootstrap file (IP and, separately, domain) is cached locally with a long TTL so neither is re-fetched per lookup.
- **No bulk/automated-harvesting posture:** the client never sweeps a CIDR range or pre-fetches beyond what §1's triggers queue.

### 6. Wire/event and data model changes

- New SSE event `connection_enrichment`, flat camelCase JSON shape matching the style `connection_update`/`layer_update` already use — deliberately not a differently-shaped payload, since a second JSON convention on the same transport would itself be the kind of inconsistency this sub-project should avoid introducing.
- `lib/types.ts`: `NetworkConnection` gains an optional nested field: `enrichment?: { org?: string; asn?: string; asnOrg?: string; country?: string; registrant?: string; source: 'rdap' | 'whois' | 'cache'; fetchedAt: string; }`. Nested rather than flat, so `enrichment === undefined` unambiguously means "never looked up" and a single presence check gates rendering the whole Ownership section. `asn`/`asnOrg` are documented in the type's own comment as best-effort registry data, not routing data, per Scope.
- **Not added to `capture-agent/src/wire.rs` or `docs/wire-protocol.md`** — that document is specifically the agent↔relay contract, and the agent never produces this data. A new `docs/enrichment-protocol.md` documents the relay↔browser `connection_enrichment` event, mirroring `wire-protocol.md`'s format but scoped to this new boundary.
- `lib/agent-mapping.ts` is untouched. A new `lib/enrichment-mapping.ts` converts RDAP/WHOIS responses into the `enrichment` shape — kept separate because its input is untrusted third-party response data with different trust characteristics than the agent's own wire format.

### 7. UI surface (`components/ConnectionsView.tsx`, `app/page.tsx`)

- The connections table (already 8 columns, `min-w-[760px]`, horizontally scrolling) gains no new columns — ownership data appears only in the existing per-selection detail panel, as a new "Ownership" section alongside the OSI encapsulation stack.
- The section shows an explicit state machine, not just data-or-blank: **"Enrichment disabled"** (points at the command-bar toggle) / **"Not yet looked up"** (button, on-demand mode) / **"Looking up…"** / **"Org: … · ASN: … · as of \<cached timestamp\>"** (ASN shown as blank/"—" when the registry record doesn't carry one, not as an error) / **"Unavailable."**
- `app/page.tsx` handles `connection_enrichment` the same way `connection_update` is already handled — merge by connection key into the existing `connections` state, no new state shape or client-side data-fetching library.
- **Rendering:** RDAP/WHOIS org, ASN-holder, and registrant strings are attacker-influenceable third-party text — same untrusted-input posture 1a already established for network-sourced strings. Rendered exclusively via plain JSX text interpolation; no `dangerouslySetInnerHTML` anywhere in this component or its diff.
- **Command-bar control:** `enrich on` / `enrich off` toggles on-demand mode; `enrich background on` / `enrich background off` toggles the stricter mode, matching the existing `pause`/`resume` interaction pattern rather than introducing a new settings page. `enrich clear` runs the "clear cache, query log, and disable" action from §1/§8.

### 8. Outbound query audit log (a sensitive artifact in its own right, not just a debugging aid)

The Egress hygiene section below requires logging every outbound query so an operator can audit what left the machine. For RDAP/WHOIS, the thing being logged *is* the queried IP/CIDR/domain — there's no version of "log the endpoint but not the target" for this feature, unlike a generic API client. That means this log is, in miniature, the same kind of durable "who did this Mac look up and when" record the third-party registry itself accumulates — a first-party copy of exactly the data this sub-project otherwise works hard to keep private from third parties. It gets treated with matching rigor rather than being an afterthought of "Egress hygiene":

- **Separate file from the cache**, under the app's data directory, newline-delimited JSON (endpoint/target + cache hit-or-miss + timestamp only — never full response bodies).
- **File permissions restricted to the owning user (`0600`)**, same as the cache.
- **Bounded retention:** rotated (daily or size-based) and retained for **30 days**, not kept indefinitely — this is the one place the earlier draft gave the cache a concrete TTL but left this log unbounded.
- **Covered by the privacy escape hatch:** the command-bar action is `enrich clear`, described to the user as "clear cache, query log, and disable" (renamed from the earlier "clear cache and disable," which didn't actually clear this log) — invoking it wipes both stores, not just the cache.
- **Excluded from any future diagnostics/support-bundle tooling.** No such tooling exists yet, but if one is added later, this log (and the cache) must be excluded by default rather than swept in as "just another log file" — noted here so that's a deliberate decision when that tooling is designed, not a default nobody chose.

## Setup & operations

**One-time setup:**
1. None required — RDAP and the narrow WHOIS fallback are unauthenticated; no API key, account, or config file is introduced. (This is a deliberate consequence of scoping to RDAP/WHOIS org data only — see Permanently out of scope.)
2. Confirm the disk cache and query-log directory (under the app's data directory, newly created for this sub-project) is writable by the relay process, and that files created there land with `0600` permissions (verify once at setup, same spirit as 1b's mTLS-rejection check).
3. **Update `docs/security.md`.** Its "What's explicitly NOT done yet" section currently states plainly that no ownership/reputation enrichment happens (epic #23). Once this ships, that line goes stale and needs replacing with a short description of the opt-in egress this sub-project adds (default-off, runtime-only, what's contacted, where the cache/log live) — tracked here as a concrete follow-up task, not left to be noticed later.

**Runtime (each session):**
1. Start the capture agent and `next start` as in 1a — no separate process for enrichment; it runs inside the relay.
2. Enrichment starts **off** every session. If desired, enable it via the command bar (`enrich on`, optionally `enrich background on`) after reading the inline disclosure text — shown every time, per §1.
3. On-demand lookups queue as connections are selected; background-mode lookups (if enabled) queue in randomized order per the rate/jitter rules as new connections appear.
4. Disabling enrichment mid-session immediately stops new queries (in-flight ones complete) and leaves the existing cache and query log in place; `enrich clear` additionally wipes both.

## Security model summary

| Threat | Mitigation |
|---|---|
| Silent disclosure of "this Mac talks to IP X" to third-party registries | Default-off, runtime-only opt-in (never persisted across restarts); explicit disclosure text before every enable, not just the first ever; separate, more-explicit confirmation for background (whole-table) mode |
| Longitudinal/aggregate profiling of this household by a registry (usage rhythm, destination breadth, existence of this tool) from one stable home IP querying over the multi-week cache TTL | Named explicitly in the disclosure text (not just "you're talking to IP X"); cache/rate design minimizes total query count, but this risk isn't eliminated by that alone — it's a stated, accepted tradeoff of the opt-in feature, not something the mitigations claim to fully close |
| Cache-miss traffic disproportionately exposing rare/novel (most identifying) destinations, since caching is most effective for large common allocations | Named explicitly in Components §2 rather than left implied by "caching helps privacy"; not separately mitigated beyond the rate/jitter shaping that applies to all queries |
| Relay-wide opt-in exposing enrichment to every browser session attached to the relay, not just the one that toggled it | Acceptable today (single loopback operator); explicitly flagged as a limitation to resolve alongside sub-project 1b's multi-viewer model — see Scope |
| Registry correlating query timing with this Mac's live capture activity | Randomized-order batching (not activity-ranked), randomized 3–10s jitter, and a hardcoded concurrency=1 rate ceiling independent of per-registry 429 backoff |
| Home IP soft-banned by a registry from burst/automated queries | Disk-persisted CIDR-aware cache with long TTL, self-imposed concurrency=1/spacing, exponential 429 backoff (30s–30min), per-registry circuit breaker (trips after 3 429s/10min, 1hr cooldown) |
| Attacker-controlled RDAP/WHOIS org/ASN/registrant text rendered unsafely | Plain JSX text interpolation only; no `dangerouslySetInnerHTML` for enrichment fields, same rule 1a applies to all network-sourced strings |
| SSRF via a crafted request-controlled "registry" address | Registry hostnames come only from the IANA bootstrap response or a static RIR list, never from request-controlled input |
| SSRF via response-controlled URLs — redirects or RDAP referral links pointing at internal addresses (e.g. the agent's loopback control port) | `redirect: 'manual'` on every outbound fetch (Node's default of following redirects is never used); response-embedded referral/notice URLs followed only if the host matches a maintained allowlist, otherwise `unavailable` |
| Slow/non-responding registry stalling the single-concurrency queue indefinitely, or an oversized response consuming memory before parsing | 10-second connect+read timeout per request; 256KB (RDAP)/64KB (WHOIS) response size caps, aborted mid-read if exceeded |
| Legacy WHOIS plaintext channel used more broadly than necessary | Narrow, explicit known-gap allowlist only, capped small; identical cache/rate rules as RDAP, no separate looser path; implemented with Node's built-in `net`, no new dependency |
| Legacy WHOIS plaintext channel readable by an on-path observer (distinct from the scope-creep concern above) | Named explicitly as a confidentiality-in-transit gap in §3; not closed by this sub-project — allowlisted queries are cleartext by nature of port 43, mitigated only by keeping the allowlist small and the queries rare |
| Reverse-DNS lookups conflated with registry-egress privacy exposure | Called out separately in §4 — a real, new query to the relay's configured resolver (which may itself be third-party, e.g. 1.1.1.1/8.8.8.8, not necessarily the ISP), lower-sensitivity than RDAP but not zero-exposure |
| The disk cache itself becoming a durable local record of who this household has looked up | `0600` file permissions, restricted to the owning user; covered by `enrich clear`; encryption-at-rest deliberately left to the OS (FileVault) — see Permanently out of scope |
| The outbound query audit log becoming an equivalent first-party record of the same sensitive data it's meant to help audit | Own file, `0600` permissions, 30-day bounded retention with rotation, covered by `enrich clear`, explicitly excluded from any future diagnostics-bundle tooling — see Components §8 |
| Stale/poisoned cache entry served indefinitely | TTL-based expiry per entry; stale data served on failure but never treated as fresher than its TTL implies |
| Scope creep into broader threat-intel/reputation lookups, or BGP-derived ASN sources | Explicitly permanent-out-of-scope for this sub-project (not deferred) — RDAP/WHOIS org/ASN/registrant data only; `asn`/`asnOrg` stay best-effort registry data |

## Error handling & lifecycle

- **Enrichment disabled:** `enrichment` is simply absent on every `NetworkConnection`; `connection_enrichment` is never emitted. UI shows the disabled state, never a blank/loading flicker implying a query is happening.
- **Cache miss, lookup queued but not yet returned:** UI shows "Looking up…"; no second query fires for the same key while one is already in flight (single-flight).
- **RDAP registry returns 429:** back off per `Retry-After` (or the 30s-start/30min-cap exponential default); serve stale cache if any exists; after repeated 429s, trip that registry's circuit breaker per the numbers in §5. Never a silent retry loop.
- **Request exceeds the 10-second timeout, or the response exceeds its size cap:** treated identically to any other lookup failure — stale cache served if available, otherwise the short-TTL negative-cache path — never a hang that stalls the concurrency=1 queue behind it.
- **RDAP referral chain broken / referral host not on the allowlist / no data / bootstrap has no server for this range:** fall through to the WHOIS allowlist check (§3) or resolve to "Unavailable" — presented as a normal, expected outcome, not an error, matching the "malformed packet is skipped, never fatal" tolerance the agent already applies to its own untrusted input.
- **Reverse-DNS lookup fails or times out:** `remoteHostname` stays unpopulated; domain-registrant lookup is simply not attempted for that connection — not surfaced as an error.
- **Relay restart:** cache and query log reload from disk; enrichment enabled-state resets to off and is never read back from anything persisted; no burst of re-queries against previously-cached entries, and none at all until the user re-enables.
- **User disables enrichment mid-flight:** any in-flight request is allowed to complete and cache its result (so work already sent isn't wasted and nothing is left dangling/retryable), but no new request is queued from that point on.
- **Cache or query-log file corruption/unreadable on disk:** treated as a full cache miss / fresh log, not a crash; rebuilt on next successful lookup or write. The atomic write-then-rename pattern in §2 means an interrupted write should not corrupt the previous good file in the first place.

## Dependency hygiene (applies to this repo going forward, not just this feature)

- `npm ci` in CI/deploy, never `npm install`; `ignore-scripts=true` in `.npmrc`; exact version pinning (`save-exact=true`); no automatic/same-day dependency upgrades.
- This sub-project ships **zero new production npm dependencies**: RDAP uses built-in `fetch`, the legacy WHOIS fallback uses built-in `net`, reverse DNS uses built-in `dns`, and the cache/query-log stores use built-in `fs` (flat files with atomic rename — see Components §2), not a database driver. This is a deliberate consequence of the narrow-allowlist WHOIS design (§3) and the single-writer cache design (§2), rather than a general text-parsing WHOIS client or a database dependency that a multi-writer story would have needed.
- If any future revision does introduce a WHOIS/RDAP client library, or a database dependency to support multi-process relay deployment, it gets extra scrutiny beyond the baseline policy above, since it would be new code with direct access to a live outbound network channel or to this sub-project's sensitive local data — not routine dependency churn.
- After any dependency churn, diff `.vscode/`/`.claude/` config against git.

## Egress hygiene (new with this sub-project — applies repo-wide going forward)

This is the app's first outbound network dependency, so the practices below are meant to outlive this specific feature:

- Every outbound query is cache-checked first; no code path bypasses the cache "for freshness" without an explicit, reviewed reason.
- All outbound registry requests carry an identifying `User-Agent` string naming the project — no impersonation of a browser or another tool.
- Outbound queries are logged (endpoint/target + cache hit-or-miss only, never full response bodies) to the bounded, permission-restricted, rotated store described in Components §8 — not an unbounded, unmanaged log file.
- Any future feature adding a new outbound network dependency must add its own row to its own security-model table and its own default-off opt-in gate, following this sub-project's precedent rather than treating egress as free once one instance of it exists.

## Testing

- **Opt-in gate:** Vitest test asserting zero HTTP calls are made when enrichment is disabled, via a mocked `fetch` that fails the test if invoked at all.
- **Opt-in state does not survive restart:** a test that constructs a fresh `EnrichmentClient` (simulating relay restart) and asserts the enabled flag is `false` regardless of any prior in-memory or environment state — the load-bearing guarantee behind the "runtime-only, never persisted" design, given its own explicit test rather than left implied by the opt-in-gate test above.
- **Disclosure re-display:** a test asserting the disclosure surface is returned/shown on every `enrich on`/`enrich background on` invocation, not only on the first one seen by the process.
- **CIDR-aware cache:** a lookup for an IP within an already-cached block returns a hit without a new request; a separate test for domain-keyed cache hits (extended tier).
- **Cache file writes are atomic:** a test that simulates a write interrupted partway (e.g. killing the write before rename) and asserts the previous cache file is unaffected and readable.
- **TTL / stale-on-failure / negative caching:** dedicated tests for TTL expiry, stale-value-served-on-refresh-failure (existing entry), and negative-result short-TTL caching (never-succeeded entry) as distinct code paths.
- **Rate/jitter — explicit verification, not just "looks right":** a deterministic fake-timer harness asserting the queue never exceeds concurrency=1 or the 3–10s spacing floor even when many lookups are queued simultaneously (background mode, table load).
- **Background-mode ordering is randomized, not activity-ranked:** a test that queues lookups for connections with clearly different activity levels and asserts dispatch order is not a deterministic function of activity/recency (e.g. across repeated runs with different random seeds, the most-active connection is not always queried first).
- **429 backoff and circuit breaker — explicit verification:** a test that mocks consecutive 429 responses and asserts the actual backoff delay follows the 30s-start/doubling/30min-cap schedule and that the circuit breaker trips after 3 429s within 10 minutes and holds its 1-hour cooldown — checked against the concrete numbers in §5, to the same explicit-verification rigor this repo expects for any security-critical negative-path behavior (assert the mechanism actually engages, not merely that the code compiles and looks like it backs off).
- **Request timeout and response-size cap — explicit verification:** a test with a mock server/socket that never responds asserts the request is aborted at 10 seconds, not hung; a test with an oversized mock response asserts it's aborted at the 256KB/64KB cap and treated as a failure rather than fully buffered.
- **SSRF hardening — explicit verification:** a test that a mocked 3xx response is never followed (`redirect: 'manual'` is actually honored, not just configured); a test that a referral/notice URL pointing at a non-allowlisted host (including a loopback address) is never dialed and resolves to `unavailable`; a test that a referral to an allowlisted host is followed.
- **Bootstrap routing logic:** a fixture-driven test of the IP-bootstrap CIDR/range matching (selecting the correct RIR base URL for a given queried IP) and, separately, the domain-bootstrap TLD matching — a distinct, self-contained algorithm in the same spirit as `capture-agent/src/parse.rs`'s tested/fuzzed parsing logic, previously untested by anything in this spec.
- **Private-range filtering — explicit verification:** a table-driven test over representative RFC1918/loopback/link-local/CGNAT/multicast addresses asserting the mock HTTP client was never invoked, checked by asserting the mock was never called, not by inspecting the skip logic in isolation.
- **RDAP/WHOIS mapping (`lib/enrichment-mapping.ts`):** fixture-driven tests, including deliberately malformed/oversized/wrong-shaped RDAP JSON and WHOIS text, treated as untrusted input the same way the agent's `cargo test` suite treats hostile packet bytes.
- **Registrant extraction (extended tier):** a dedicated test confirming personal-contact/vCard/postal fields are dropped and never forwarded, only org-level registrant fields survive.
- **Client merge logic:** a test that a `connection_enrichment` event correctly upserts onto an existing `connections` entry by `remoteAddr`/connection key without disturbing fields owned by `connection_update`.
- **Query-log retention:** a test that entries older than 30 days are rotated/pruned, and that `enrich clear` empties both the cache and the query log, not just the cache.
- **File permissions:** a test (where the platform allows checking it) that newly-created cache and query-log files are not group- or world-readable.
- **UI:** a component test for `ConnectionsView`'s Ownership section asserting each of the five states renders from props alone, plus an explicit audit that org/registrant strings are never passed through anything but plain JSX text children (no `dangerouslySetInnerHTML` anywhere in the diff).
- **End-to-end SSE path:** a regression check that a `connection_enrichment` event, once emitted by the relay, actually reaches the browser over `/api/stream` unchanged.
- No agent-side (`cargo test`/`cargo-fuzz`) work is needed — `capture-agent/` is untouched by this sub-project.

## Deferred to later sub-projects

- **Sub-project 3 (path visualization):** on-demand traceroute + geoIP hop mapping for any connection's remote endpoint, consuming this sub-project's cached ASN/org data as per-hop context (with the same best-effort-ASN caveat carried forward) rather than re-querying registries independently — and, since traceroute is an even more active outbound signal, subject to the same opt-in/disclosure posture established here.
- **Sub-project 4 (TLS interception):** a local CA-based MITM proxy for decrypted HTTPS content, including per-device trust installation and its own larger security review; any interaction between intercepted certificate-issuer data and RDAP org data is designed there, not here.
- **Sub-project 1b (secure LAN access) follow-up:** resolving the relay-wide (rather than per-session) enrichment consent gap once multi-viewer access actually ships — see Scope's "Explicitly out of scope" note.
- **Broader threat-intel/reputation enrichment, and BGP-derived ASN attribution:** explicitly not deferred but permanently excluded from this sub-project's scope — any future proposal to add either should get its own spec and its own privacy review, not ride in as an extension of this one.
