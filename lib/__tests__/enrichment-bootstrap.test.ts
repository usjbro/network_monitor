// lib/__tests__/enrichment-bootstrap.test.ts
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadIpBootstrap, parseIpBootstrap, resolveRdapBaseForIp } from '../enrichment/bootstrap';

// Fixture shaped like IANA's real ipv4.json (RFC 7484 bootstrap format):
// { "services": [ [ [prefixes...], [urls...] ], ... ] }
const FIXTURE_IPV4_BOOTSTRAP = {
  services: [
    [['93.184.216.0/24', '198.51.100.0/24'], ['https://rdap.arin.net/registry/']],
    [['192.0.2.0/24'], ['https://rdap.db.ripe.net/']],
    // A malicious/compromised-CDN entry: not a real RIR host. Must be
    // dropped by parseIpBootstrap, not trusted just because it came back in
    // IANA's response body (spec Components §5, response-controlled SSRF).
    [['203.0.113.0/24'], ['https://attacker.example/rdap/']],
  ],
};

describe('parseIpBootstrap', () => {
  it('extracts prefix->url mappings and drops non-allowlisted RIR hosts', () => {
    const services = parseIpBootstrap(FIXTURE_IPV4_BOOTSTRAP);
    expect(services).toHaveLength(2);
    expect(services.some((s) => s.url.includes('attacker.example'))).toBe(false);
  });

  it('tolerates malformed entries without throwing', () => {
    expect(() => parseIpBootstrap({ services: [null, [], ['only one element'], { not: 'an array' }] })).not.toThrow();
    expect(parseIpBootstrap({})).toEqual([]);
    expect(parseIpBootstrap(null)).toEqual([]);
  });
});

describe('resolveRdapBaseForIp', () => {
  const services = parseIpBootstrap(FIXTURE_IPV4_BOOTSTRAP);

  it('routes to the correct RIR base URL for an IP inside a listed prefix', () => {
    expect(resolveRdapBaseForIp('93.184.216.34', services)).toBe('https://rdap.arin.net/registry/');
    expect(resolveRdapBaseForIp('192.0.2.5', services)).toBe('https://rdap.db.ripe.net/');
  });

  it('returns null for an IP not covered by any listed prefix', () => {
    expect(resolveRdapBaseForIp('8.8.8.8', services)).toBeNull();
  });
});

describe('loadIpBootstrap', () => {
  let dir: string;
  let cachePath: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'bootstrap-')); cachePath = join(dir, 'bootstrap-ipv4.json'); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('fetches once and reuses the disk cache on a second call within TTL', async () => {
    let fetchCount = 0;
    const fetchImpl = (async () => {
      fetchCount += 1;
      return new Response(JSON.stringify(FIXTURE_IPV4_BOOTSTRAP), { status: 200 });
    }) as typeof fetch;

    const first = await loadIpBootstrap(cachePath, fetchImpl, 30 * 24 * 60 * 60 * 1000);
    const second = await loadIpBootstrap(cachePath, fetchImpl, 30 * 24 * 60 * 60 * 1000);

    expect(fetchCount).toBe(1);
    expect(first).toEqual(second);
  });
});
