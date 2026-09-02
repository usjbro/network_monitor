// lib/__tests__/enrichment-bootstrap.test.ts
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadIpBootstrap, parseIpBootstrap, resolveRdapBaseForIp, loadDomainBootstrap, parseDomainBootstrap, resolveRdapBaseForDomain } from '../enrichment/bootstrap';

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

  // These two mirror RdapClient's own timeout/size-cap coverage
  // (enrichment-rdap-client.test.ts) — loadIpBootstrap/loadDomainBootstrap
  // call fetchImpl directly rather than going through RdapClient, so without
  // their own guard a hung or oversized data.iana.org response would hang
  // forever (bootstrapPromise is memoized and awaited by every lookup()) or
  // buffer an unbounded body into memory.

  it('aborts at the 10-second timeout when the bootstrap host never responds', async () => {
    vi.useFakeTimers();
    const fetchImpl = ((_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      })) as typeof fetch;

    const resultPromise = loadIpBootstrap(cachePath, fetchImpl, 30 * 24 * 60 * 60 * 1000);
    resultPromise.catch(() => {}); // rejection is expected/asserted below; suppress the fake-timer-tick warning
    await vi.advanceTimersByTimeAsync(10_000);
    await expect(resultPromise).rejects.toThrow();
    vi.useRealTimers();
  });

  it('rejects a response exceeding the size cap rather than buffering it unbounded', async () => {
    const bigChunk = new Uint8Array(3 * 1024 * 1024); // 3MB > the 2MB cap
    const fetchImpl = (async () => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bigChunk);
          controller.close();
        },
      });
      return new Response(stream, { status: 200 });
    }) as typeof fetch;

    await expect(loadIpBootstrap(cachePath, fetchImpl, 30 * 24 * 60 * 60 * 1000)).rejects.toThrow();
  });
});

// Fixture shaped like IANA's real dns.json (RFC 7484-style bootstrap format):
// { "services": [ [ [tlds...], [urls...] ], ... ] }
const FIXTURE_DNS_BOOTSTRAP = {
  services: [
    [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
    [['org'], ['https://rdap.publicinterestregistry.org/rdap/']],
    // A malicious/compromised-CDN entry: not a real domain registry host.
    // Must be dropped by parseDomainBootstrap, not trusted just because it
    // came back in IANA's response body (same response-controlled SSRF
    // posture as the IP bootstrap above).
    [['xyz'], ['https://attacker.example/rdap/']],
  ],
};

describe('domain bootstrap (extended tier)', () => {
  it('routes to the correct registry base URL by TLD', () => {
    const services = parseDomainBootstrap(FIXTURE_DNS_BOOTSTRAP);
    expect(resolveRdapBaseForDomain('example.com', services)).toBe('https://rdap.verisign.com/com/v1/');
    expect(resolveRdapBaseForDomain('example.org', services)).toBe('https://rdap.publicinterestregistry.org/rdap/');
    expect(resolveRdapBaseForDomain('example.xyz', services)).toBeNull();
  });

  it('drops non-allowlisted domain registry hosts from a parsed bootstrap response', () => {
    const services = parseDomainBootstrap(FIXTURE_DNS_BOOTSTRAP);
    expect(services.some((s) => s.url.includes('attacker.example'))).toBe(false);
  });

  it('tolerates malformed entries without throwing', () => {
    expect(() => parseDomainBootstrap({ services: [null, [], ['only one element'], { not: 'an array' }] })).not.toThrow();
    expect(parseDomainBootstrap({})).toEqual([]);
    expect(parseDomainBootstrap(null)).toEqual([]);
  });

  it('fetches once and reuses the disk cache on a second call within TTL', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'domain-bootstrap-'));
    try {
      const cachePath = join(dir, 'bootstrap-dns.json');
      let fetchCount = 0;
      const fetchImpl = (async () => {
        fetchCount += 1;
        return new Response(JSON.stringify(FIXTURE_DNS_BOOTSTRAP), { status: 200 });
      }) as typeof fetch;

      const first = await loadDomainBootstrap(cachePath, fetchImpl, 30 * 24 * 60 * 60 * 1000);
      const second = await loadDomainBootstrap(cachePath, fetchImpl, 30 * 24 * 60 * 60 * 1000);

      expect(fetchCount).toBe(1);
      expect(first).toEqual(second);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
