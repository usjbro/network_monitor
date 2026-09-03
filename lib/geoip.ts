// lib/geoip.ts
//
// GeoIpClient — opt-in, runtime-only geoIP lookups for traceroute hops.
// Mirrors sub-project 2's EnrichmentClient shape: default-off, scope-filtered
// via the shared isPrivateOrReserved check, disk-cached, mode never persisted
// across a relay restart. See docs/geoip-protocol.md and the design spec at
// docs/superpowers/specs/2026-09-01-path-visualization-design.md.
import { EventEmitter } from 'node:events';
import { isPrivateOrReserved } from './enrichment/scope-filter';
import { EnrichmentCache } from './enrichment/cache';

export interface GeoLocation {
  city?: string;
  country?: string;
  lat?: number;
  lon?: number;
  source: 'geoip' | 'cache';
}

export type GeoIpMode = 'off' | 'on';

// 30 days — longer than sub-project 2's 14-day RDAP TTL by design (a
// deliberate, named difference per the spec, not an oversight).
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const DISCLOSURE_TEXT =
  'GeoIP lookups send hop IP addresses to a third-party location service. ' +
  'Private/reserved-range IPs are never sent. Results are cached for 30 days. ' +
  'Run "geoip disable" to turn this off, or "geoip clear" to erase the cache.';

export interface GeoIpClientOptions {
  fetchImpl?: typeof fetch;
  cachePath?: string;
  providerUrl?: (ip: string) => string;
}

export class GeoIpClient extends EventEmitter {
  private mode: GeoIpMode = 'off';
  private fetchImpl: typeof fetch;
  private cache: EnrichmentCache;
  private providerUrl: (ip: string) => string;

  constructor(opts: GeoIpClientOptions = {}) {
    super();
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.cache = new EnrichmentCache(opts.cachePath ?? '.data/geoip/cache.json');
    this.cache.load();
    // Provider URL is intentionally injectable and not hardcoded to one
    // vendor here — the specific geoIP HTTP API is an implementation-time
    // choice per the spec (Components §2), not pinned by this plan.
    this.providerUrl = opts.providerUrl ?? ((ip) => `https://example-geoip-provider.invalid/lookup/${ip}`);
  }

  getMode(): GeoIpMode {
    return this.mode;
  }

  enable(): string {
    this.mode = 'on';
    return DISCLOSURE_TEXT;
  }

  disable(): void {
    this.mode = 'off';
  }

  async clear(): Promise<void> {
    await this.cache.clear();
  }

  async lookup(ip: string): Promise<void> {
    if (this.mode === 'off' || isPrivateOrReserved(ip)) {
      return;
    }
    const cached = this.cache.getForIp(ip);
    if (cached && this.cache.isFresh(cached)) {
      this.emit('result', {
        ip,
        location: cached.record ? { ...(cached.record as unknown as GeoLocation), source: 'cache' } : null,
      });
      return;
    }
    try {
      const res = await this.fetchImpl(this.providerUrl(ip));
      if (!res.ok) {
        this.emit('result', { ip, location: null });
        return;
      }
      const body = await res.json();
      const location: GeoLocation = {
        city: body.city,
        country: body.country,
        lat: body.lat,
        lon: body.lon,
        source: 'geoip',
      };
      await this.cache.setSuccess(`${ip}/32`, location as any, CACHE_TTL_MS);
      this.emit('result', { ip, location });
    } catch {
      this.emit('result', { ip, location: null });
    }
  }
}
