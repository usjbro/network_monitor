# Enrichment Protocol Reference

The relay→browser contract for ownership enrichment — a separate, newer
boundary from `docs/wire-protocol.md` (agent↔relay), which this feature does
not touch at all. Source of truth: `lib/enrichment.ts` (produces the event)
and `lib/enrichment-mapping.ts` / `lib/types.ts` (consume it).

## Transport

Reuses the existing `GET /api/stream` SSE connection — not a new port or
endpoint. `connection_enrichment` lines are interleaved with
`connection_update`/`packet`/`layer_update`/`connection_status` lines on the
same stream.

## `connection_enrichment`

Emitted only when enrichment is enabled and a lookup (cache hit or fresh
RDAP/WHOIS result) resolves for a connection currently on the wire.

```json
{
  "type": "connection_enrichment",
  "connectionId": "Tcp-192.168.1.10:51000-93.184.216.34:443",
  "remoteAddr": "93.184.216.34",
  "remoteHostname": "example.com",
  "enrichment": {
    "org": "EXAMPLE-ORG",
    "asn": "AS15133",
    "asnOrg": "EDGECAST",
    "country": "US",
    "registrant": "Example Inc",
    "source": "rdap",
    "fetchedAt": "2026-08-28T00:00:00.000Z"
  }
}
```

Field notes:
- `asn`/`asnOrg` are **best-effort RIR registry data, not BGP-observed routing
  data** — legitimately absent for many address blocks. See the design spec's
  Scope section.
- `registrant` is populated only by the extended tier (domain-level lookup);
  absent for core-tier (IP-only) results.
- `source` is `'cache'` for a cache hit, `'rdap'`/`'whois'` for a fresh
  lookup that actually reached a registry.
- `remoteHostname` (top-level, sibling of `enrichment` — not nested inside
  it) is extended-tier only: the reverse-DNS PTR hostname resolved for
  `remoteAddr` as the prerequisite for the domain registrant lookup. Omitted
  entirely (not sent as `null`/`undefined`) whenever no hostname resolved —
  a private/no-PTR address, a core-tier-only result, or a cache hit that
  predates this field. The browser merges it onto the connection's own
  top-level `remoteHostname` (`lib/types.ts`), the same field
  `docs/wire-protocol.md` notes the capture agent itself never populates —
  this SSE event is that field's only source today.

## Control: `POST /api/enrichment/control`

```json
{ "action": "enable" }        // on-demand mode; response includes disclosureText
{ "action": "enable_background" } // background mode; response includes disclosureText
{ "action": "disable" }
{ "action": "disable_background" } // drops back to on-demand, not fully off
{ "action": "clear" }          // wipes cache + query log, disables
```

## On-demand trigger: `POST /api/enrichment/lookup`

```json
{ "connectionId": "Tcp-192.168.1.10:51000-93.184.216.34:443", "remoteAddr": "93.184.216.34" }
```

No-op (200, no lookup queued) if enrichment is currently disabled.
