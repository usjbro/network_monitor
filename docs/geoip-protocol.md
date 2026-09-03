# GeoIP Protocol Reference

The relay→browser contract for opt-in geoIP enrichment of traceroute hops —
relay-originated only, unlike `traceroute_hop` (agent-originated, documented
in `docs/wire-protocol.md`). A separate, newer boundary from
`docs/wire-protocol.md` (agent↔relay), which this feature does not touch at
all. Source of truth: `lib/geoip.ts` (`GeoIpClient`, produces the raw
`'result'` event) and `lib/geoip-mapping.ts` (`buildGeoHopEvent`, builds the
SSE event) / `lib/types.ts` (consumes it).

## Transport

Reuses the existing `GET /api/stream` SSE connection — not a new port or
endpoint. `geo_hop_update` lines are interleaved with
`connection_update`/`packet`/`layer_update`/`connection_status`/
`traceroute_hop` lines on the same stream.

## `geo_hop_update`

Emitted only when geoIP is enabled and a lookup (cache hit or fresh
provider result) resolves for a hop IP the agent has already reported via a
`traceroute_hop` event. Never emitted automatically — a `geo_hop_update` for
a given hop can only follow that hop's own `traceroute_hop` event, since
`app/api/stream/route.ts` only calls `GeoIpClient.lookup` in response to
seeing a hop's `hopIp` on the wire.

```json
{
  "type": "geo_hop_update",
  "targetIp": "93.184.216.34",
  "hopNumber": 4,
  "hopIp": "12.122.1.1",
  "location": {
    "city": "Ashburn",
    "country": "US",
    "lat": 39.04,
    "lon": -77.48,
    "source": "geoip"
  }
}
```

Field notes:
- `targetIp`/`hopNumber` correlate this event back to the `traceroute_hop`
  event it enriches — there is no separate trace-id, matching the
  correlation approach `traceroute_hop` itself uses (see
  `docs/wire-protocol.md`).
- `location` is `null` when the lookup failed (provider error, timeout, or a
  non-OK HTTP response) — a real, expected outcome, not something the
  browser should treat as an error state distinct from "no data yet."
- `location.source` is `'cache'` for a cache hit, `'geoip'` for a fresh
  lookup that actually reached the provider.
- A hop with no `hopIp` (i.e. that hop got no ICMP reply) never triggers a
  lookup and therefore never gets a matching `geo_hop_update` — there is
  nothing to geolocate.
- Private/reserved-range hop IPs (RFC1918, loopback, link-local, CGNAT,
  multicast — see `lib/enrichment/scope-filter.ts`'s `isPrivateOrReserved`)
  never trigger a provider request; `GeoIpClient.lookup` no-ops for them
  even when geoIP is enabled.

## Control: `POST /api/geoip/control`

```json
{ "action": "enable" }   // response includes disclosureText
{ "action": "disable" }
{ "action": "clear" }    // wipes the on-disk cache (.data/geoip/cache.json)
```

Mode is runtime-only and default-off: it resets to `'off'` on every relay
restart, the same precedent sub-project 2's `EnrichmentClient` established —
no task in this feature persists an "enabled" flag to disk.

## On-demand trigger: `POST /api/traceroute/start`

```json
{ "connectionId": "Tcp-192.168.1.10:51000-93.184.216.34:443", "remoteAddr": "93.184.216.34" }
```

Starts the actual traceroute (see `docs/wire-protocol.md`'s `trace_route`
control message); geoIP lookups for each resulting hop are triggered
automatically by the relay as `traceroute_hop` events arrive, provided geoIP
is enabled at that time. There is no separate "trigger geoIP for this hop"
endpoint — enabling geoIP mode is the only opt-in gesture needed.
