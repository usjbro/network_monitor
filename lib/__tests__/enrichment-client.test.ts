// lib/__tests__/enrichment-client.test.ts
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EnrichmentClient } from '../enrichment';
import { shuffle } from '../enrichment/request-queue';

// Fixture shaped like IANA's real ipv4.json (RFC 7484 bootstrap format),
// covering every address this test file queries — mirrors the fixture in
// enrichment-bootstrap.test.ts. Every fetchImpl below must route requests to
// data.iana.org to this fixture rather than the per-IP RDAP body, since
// EnrichmentClient uses the same fetchImpl for both the one-time bootstrap
// fetch and the actual per-IP RDAP query.
const BOOTSTRAP_FIXTURE = {
  services: [
    [['93.184.216.0/24'], ['https://rdap.arin.net/registry/']],
    [['198.51.100.0/24'], ['https://rdap.arin.net/registry/']],
    [['203.0.113.0/24'], ['https://rdap.arin.net/registry/']],
  ],
};

function routedFetch(rdapBody: unknown, status = 200) {
  return vi.fn(async (url: string) => {
    if (url.includes('data.iana.org')) {
      return new Response(JSON.stringify(BOOTSTRAP_FIXTURE), { status: 200 });
    }
    return new Response(JSON.stringify(rdapBody), { status });
  }) as unknown as typeof fetch;
}

function fakeFetch(status = 200, body: unknown = { objectClassName: 'ip network', name: 'EXAMPLE-ORG' }) {
  return routedFetch(body, status);
}

// Task 12 wired a reverse-DNS step into the successful-RDAP path of
// lookup(). This suite predates that and is otherwise fully offline (all
// HTTP goes through the fetchImpl fixtures above) — inject a fast, no-PTR
// stub everywhere a client actually exercises that path, rather than
// falling through to the real dns.promises.reverse() default and making a
// live DNS query from an automated test.
const NO_PTR = async () => null;

describe('EnrichmentClient', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'enrichment-client-')); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('makes zero HTTP calls when disabled', async () => {
    const fetchImpl = vi.fn();
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl: fetchImpl as unknown as typeof fetch });
    client.requestLookup('conn-1', '93.184.216.34');
    await new Promise((r) => setTimeout(r, 50));
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('starts in "off" mode on every fresh instance — opt-in never survives a simulated restart', () => {
    const client = new EnrichmentClient({ dataDir: dir });
    expect(client.getMode()).toBe('off');
    client.enable();
    expect(client.getMode()).toBe('on-demand');

    // Simulate a relay restart: a brand new instance, same data directory.
    const restarted = new EnrichmentClient({ dataDir: dir });
    expect(restarted.getMode()).toBe('off');
  });

  it('returns non-empty disclosure text on every activation, not only the first', () => {
    const client = new EnrichmentClient({ dataDir: dir });
    const first = client.enable();
    client.disable();
    const second = client.enable();
    expect(first.disclosureText.length).toBeGreaterThan(0);
    expect(second.disclosureText).toBe(first.disclosureText);
  });

  it('background mode gets its own, separately-worded disclosure text, not a reuse of the on-demand text', () => {
    const client = new EnrichmentClient({ dataDir: dir });
    const onDemand = client.enable();
    client.disable();
    const background = client.enableBackground();
    expect(background.disclosureText.length).toBeGreaterThan(0);
    expect(background.disclosureText).not.toBe(onDemand.disclosureText);
  });

  it('never queries a private/reserved IP', async () => {
    const fetchImpl = fakeFetch();
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl });
    client.enable();
    client.requestLookup('conn-1', '192.168.1.50');
    await new Promise((r) => setTimeout(r, 50));
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('on-demand lookup emits a "result" event with mapped org data on success', async () => {
    const fetchImpl = fakeFetch();
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn: NO_PTR });
    client.enable();

    const resultPromise = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-1', '93.184.216.34');
    const result = (await resultPromise) as { connectionId: string; enrichment: { org?: string } };

    expect(result.connectionId).toBe('conn-1');
    expect(result.enrichment.org).toBe('EXAMPLE-ORG');
  }, 15_000);

  it('single-flight: two requests for the same key before the first resolves trigger only one fetch', async () => {
    let rdapCalls = 0;
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.includes('data.iana.org')) {
        return new Response(JSON.stringify(BOOTSTRAP_FIXTURE), { status: 200 });
      }
      rdapCalls += 1;
      await new Promise((r) => setTimeout(r, 20));
      return new Response(JSON.stringify({ name: 'X' }), { status: 200 });
    }) as unknown as typeof fetch;
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn: NO_PTR });
    client.enable();

    client.requestLookup('conn-1', '93.184.216.34');
    client.requestLookup('conn-1', '93.184.216.34'); // same connection, in flight already
    await new Promise((r) => setTimeout(r, 150));
    expect(rdapCalls).toBeLessThanOrEqual(1);
  }, 15_000);

  it('caches a successful RDAP result at the allocation\'s CIDR block, not just the queried /32 — the spec\'s "primary privacy control"', async () => {
    const fetchImpl = fakeFetch(200, {
      objectClassName: 'ip network',
      name: 'EXAMPLE-ORG',
      startAddress: '93.184.216.0',
      endAddress: '93.184.216.255',
    });
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn: NO_PTR });
    client.enable();

    const first = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-1', '93.184.216.34');
    await first;

    // A second, different address inside the same /24 must now resolve from
    // cache — i.e. without a second fetch — proving the entry was actually
    // keyed by the derived 93.184.216.0/24 block and not by the single
    // queried address.
    const callsBefore = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls.length;
    const second = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-2', '93.184.216.200');
    const secondResult = (await second) as { enrichment: { org?: string; source?: string } };

    expect((fetchImpl as ReturnType<typeof vi.fn>).mock.calls.length).toBe(callsBefore);
    expect(secondResult.enrichment.source).toBe('cache');
    expect(secondResult.enrichment.org).toBe('EXAMPLE-ORG');
  }, 15_000);

  it('caches a successful RDAP result using the cidr0_cidrs extension when present, preferring it over startAddress/endAddress', async () => {
    const fetchImpl = fakeFetch(200, {
      objectClassName: 'ip network',
      name: 'CIDR0-ORG',
      startAddress: '198.51.100.10', // deliberately NOT block-aligned, to prove cidr0_cidrs wins
      endAddress: '198.51.100.10',
      cidr0_cidrs: [{ v4prefix: '198.51.100.0', length: 24 }],
    });
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn: NO_PTR });
    client.enable();

    const first = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-1', '198.51.100.10');
    await first;

    const callsBefore = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls.length;
    const second = new Promise((resolve) => client.once('result', resolve));
    // A different address within the cidr0-declared /24 (but outside the
    // narrow startAddress/endAddress range) must still hit cache.
    client.requestLookup('conn-2', '198.51.100.200');
    const secondResult = (await second) as { enrichment: { org?: string; source?: string } };

    expect((fetchImpl as ReturnType<typeof vi.fn>).mock.calls.length).toBe(callsBefore);
    expect(secondResult.enrichment.source).toBe('cache');
    expect(secondResult.enrichment.org).toBe('CIDR0-ORG');
  }, 15_000);

  it('falls back to a /32 cache key when the RDAP response has no derivable CIDR block', async () => {
    const fetchImpl = fakeFetch(200, { objectClassName: 'ip network', name: 'NO-RANGE-ORG' });
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn: NO_PTR });
    client.enable();

    const first = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-1', '203.0.113.7');
    await first;
    // After the first lookup: one bootstrap fetch (data.iana.org, fetched
    // once and reused for the rest of this client's lifetime) plus one RDAP
    // fetch for .7 — two calls total.
    const callsAfterFirst = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls.length;
    expect(callsAfterFirst).toBe(2);

    // A different address must NOT be served from cache — the fallback key
    // is /32, scoped to exactly the queried address — so this must issue a
    // genuine second RDAP fetch (the bootstrap fetch is not repeated, since
    // it's already cached in-process from the first lookup above).
    const second = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-2', '203.0.113.8');
    const secondResult = (await second) as { enrichment: { source?: string } };
    expect(secondResult.enrichment.source).toBe('rdap');
    expect((fetchImpl as ReturnType<typeof vi.fn>).mock.calls.length).toBe(callsAfterFirst + 1);
  }, 15_000);

  it('falls back to a /32 key (not a poisoned wide block) when a malformed/malicious RDAP response claims a whole-internet range', async () => {
    // A response claiming startAddress 0.0.0.0 / endAddress 255.255.255.255
    // derives, with no floor, "0.0.0.0/0" — which EnrichmentCache.getForIp
    // matches against every subsequent IP address, silently poisoning
    // ownership data for the whole cache. MIN_CIDR_PREFIX_LEN must reject
    // this and fall back to the /32-scoped key instead.
    const fetchImpl = fakeFetch(200, {
      objectClassName: 'ip network',
      name: 'BOGUS-WHOLE-INTERNET-ORG',
      startAddress: '0.0.0.0',
      endAddress: '255.255.255.255',
    });
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn: NO_PTR });
    client.enable();

    const first = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-1', '203.0.113.7');
    await first;
    const callsAfterFirst = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls.length;

    // A different address — even one in the same /24 as the first query —
    // must NOT be served the bogus cached org from a poisoned /0 entry; it
    // must issue its own genuine RDAP fetch, proving the fallback really is
    // scoped to /32 and not to the malicious whole-internet range.
    const second = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-2', '203.0.113.99');
    const secondResult = (await second) as { enrichment: { source?: string; org?: string } };
    expect(secondResult.enrichment.source).toBe('rdap');
    expect((fetchImpl as ReturnType<typeof vi.fn>).mock.calls.length).toBe(callsAfterFirst + 1);
  }, 15_000);

  it('single-flight fanout: two different connections requesting the same in-flight address both eventually receive a result', async () => {
    let rdapCalls = 0;
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.includes('data.iana.org')) {
        return new Response(JSON.stringify(BOOTSTRAP_FIXTURE), { status: 200 });
      }
      rdapCalls += 1;
      await new Promise((r) => setTimeout(r, 30));
      return new Response(JSON.stringify({ objectClassName: 'ip network', name: 'SHARED-ORG' }), { status: 200 });
    }) as unknown as typeof fetch;
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn: NO_PTR });
    client.enable();

    const results: Array<{ connectionId: string }> = [];
    const done = new Promise<void>((resolve) => {
      client.on('result', (r: { connectionId: string }) => {
        results.push(r);
        if (results.length === 2) resolve();
      });
    });

    // Same remote address, two different connection ids — the second must
    // join the first's in-flight request rather than being dropped, and
    // both must be notified once it resolves.
    client.requestLookup('conn-a', '93.184.216.34');
    client.requestLookup('conn-b', '93.184.216.34');

    await done;
    expect(rdapCalls).toBe(1);
    const ids = results.map((r) => r.connectionId).sort();
    expect(ids).toEqual(['conn-a', 'conn-b']);
  }, 15_000);

  it('background mode dispatch order is not a deterministic function of input order (randomized, per spec §5)', async () => {
    const seen: string[] = [];
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.includes('data.iana.org')) {
        return new Response(JSON.stringify(BOOTSTRAP_FIXTURE), { status: 200 });
      }
      seen.push(url);
      return new Response(JSON.stringify({ name: 'X' }), { status: 200 });
    }) as unknown as typeof fetch;

    // Deterministic injected `random` (fixed sequence) so the resulting
    // dispatch order can be asserted exactly, rather than statistically. The
    // same sequence feeds both the shuffle() call and the queue's jittered
    // inter-dispatch delay, matching how EnrichmentClient wires a single
    // injected `random` through to both.
    let i = 0;
    const fixedSequence = [0.9, 0.1, 0.5, 0.2, 0.8];
    const random = () => fixedSequence[i++ % fixedSequence.length];

    const client = new EnrichmentClient({
      dataDir: dir,
      fetchImpl,
      random,
      // Tiny, deterministic-from-`random` delay window so this test doesn't
      // have to wait out the real 3-10s production inter-dispatch spacing.
      queueOptions: { minDelayMs: 1, maxDelayMs: 2 },
      reverseDnsFn: NO_PTR,
    });
    client.enableBackground();

    const conns = [
      { id: 'a', remoteAddr: '93.184.216.1' },
      { id: 'b', remoteAddr: '93.184.216.2' },
      { id: 'c', remoteAddr: '93.184.216.3' },
      { id: 'd', remoteAddr: '93.184.216.4' },
      { id: 'e', remoteAddr: '93.184.216.5' },
    ];
    const expectedOrder = shuffle(conns, (() => {
      let j = 0;
      return () => fixedSequence[j++ % fixedSequence.length];
    })()).map((c) => c.remoteAddr);

    client.notifyObservedConnections(conns);

    // Wait for all five (rate-limited, concurrency-1) lookups to complete.
    await new Promise((resolve) => {
      const check = setInterval(() => {
        if (seen.length >= 5) {
          clearInterval(check);
          resolve(undefined);
        }
      }, 10);
    });

    const dispatchedAddrs = seen.map((url) => new URL(url).pathname.split('/').pop());
    expect(dispatchedAddrs).toEqual(expectedOrder);
    expect(dispatchedAddrs).not.toEqual(conns.map((c) => c.remoteAddr));
  }, 15_000);

  // Task 15: extended-tier chain (reverse DNS -> domain RDAP/WHOIS) wired
  // end-to-end. reverseDnsFn is injected directly (the seam Task 12 already
  // built and every test above already uses via NO_PTR) rather than
  // vi.mock('node:dns') — same offline-only posture, one fewer mocking
  // mechanism in this file.
  const DOMAIN_BOOTSTRAP_FIXTURE = {
    services: [[['com'], ['https://rdap.verisign.com/com/v1/']]],
  };

  function extendedTierFetch(domainRdapResponse: unknown, ipRdapResponse: unknown = { objectClassName: 'ip network', name: 'EXAMPLE-NET', country: 'US' }) {
    return vi.fn(async (url: string) => {
      if (url.includes('ipv4.json')) return new Response(JSON.stringify(BOOTSTRAP_FIXTURE), { status: 200 });
      if (url.includes('dns.json')) return new Response(JSON.stringify(DOMAIN_BOOTSTRAP_FIXTURE), { status: 200 });
      if (url.includes('rdap.verisign.com')) return new Response(JSON.stringify(domainRdapResponse), { status: 200 });
      return new Response(JSON.stringify(ipRdapResponse), { status: 200 });
    }) as unknown as typeof fetch;
  }

  it('extended tier: resolves a hostname via reverse DNS, then looks up domain registrant, and emits both on one result', async () => {
    const domainRdapResponse = {
      objectClassName: 'domain',
      entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['org', {}, 'text', 'Example Registrant Org']]] }],
    };
    const fetchImpl = extendedTierFetch(domainRdapResponse);
    const reverseDnsFn = vi.fn(async () => 'example.com');
    const client = new EnrichmentClient({
      dataDir: dir,
      fetchImpl,
      reverseDnsFn,
      // Tiny jitter window — this lookup issues two queued fetches (IP RDAP,
      // then domain RDAP) and the default 3-10s inter-dispatch spacing would
      // make this test needlessly slow without adding any real coverage.
      queueOptions: { minDelayMs: 1, maxDelayMs: 2 },
    });
    client.enable();

    const resultPromise = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-1', '93.184.216.34');
    const result = (await resultPromise) as { connectionId: string; remoteHostname?: string; enrichment: { org?: string; registrant?: string; country?: string } };

    expect(result.enrichment.org).toBe('EXAMPLE-NET');
    expect(result.enrichment.country).toBe('US');
    expect(result.enrichment.registrant).toBe('Example Registrant Org');
    expect(result.remoteHostname).toBe('example.com'); // surfaced onto the connection, per Task 12's TODO
    expect(reverseDnsFn).toHaveBeenCalledWith('93.184.216.34');
  }, 20_000);

  it('extended tier: reverse-DNS failure leaves the core-tier result intact, no registrant field, no error', async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.includes('ipv4.json')) return new Response(JSON.stringify(BOOTSTRAP_FIXTURE), { status: 200 });
      // dns.json / any domain-registry host must never be requested in this
      // test — reverse DNS never resolves a hostname, so the domain chain
      // must never even start.
      return new Response(JSON.stringify({ objectClassName: 'ip network', name: 'EXAMPLE-NET', country: 'US' }), { status: 200 });
    }) as unknown as typeof fetch;
    const reverseDnsFn = vi.fn(async () => null);
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn });
    client.enable();

    const resultPromise = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-1', '93.184.216.34');
    const result = (await resultPromise) as { remoteHostname?: string; enrichment: { org?: string; registrant?: string } };

    expect(result.enrichment.org).toBe('EXAMPLE-NET');
    expect(result.enrichment.registrant).toBeUndefined();
    expect(result.remoteHostname).toBeUndefined();
    expect((fetchImpl as ReturnType<typeof vi.fn>).mock.calls.some((c: unknown[]) => String(c[0]).includes('dns.json'))).toBe(false);
  }, 15_000);

  it('extended tier: a registrar referral for the resolved domain is followed only through the hardened RdapClient path (allowlisted host)', async () => {
    // The registry (verisign) response refers to itself here for simplicity
    // — what's under test is that fetchWithReferral's allowlist-gated
    // referral-following is actually wired into this chain, not a specific
    // registry/registrar pairing.
    const domainRegistryResponse = {
      objectClassName: 'domain',
      links: [{ rel: 'related', href: 'https://rdap.publicinterestregistry.org/rdap/domain/example.com' }],
    };
    const domainRegistrarResponse = {
      objectClassName: 'domain',
      entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['org', {}, 'text', 'Referred Org']]] }],
    };
    const calls: string[] = [];
    const fetchImpl = vi.fn(async (url: string) => {
      calls.push(url);
      if (url.includes('ipv4.json')) return new Response(JSON.stringify(BOOTSTRAP_FIXTURE), { status: 200 });
      if (url.includes('dns.json')) return new Response(JSON.stringify(DOMAIN_BOOTSTRAP_FIXTURE), { status: 200 });
      if (url.includes('rdap.publicinterestregistry.org')) return new Response(JSON.stringify(domainRegistrarResponse), { status: 200 });
      if (url.includes('rdap.verisign.com')) return new Response(JSON.stringify(domainRegistryResponse), { status: 200 });
      return new Response(JSON.stringify({ objectClassName: 'ip network', name: 'EXAMPLE-NET' }), { status: 200 });
    }) as unknown as typeof fetch;
    const reverseDnsFn = vi.fn(async () => 'example.com');
    const client = new EnrichmentClient({
      dataDir: dir,
      fetchImpl,
      reverseDnsFn,
      queueOptions: { minDelayMs: 1, maxDelayMs: 2 },
    });
    client.enable();

    const resultPromise = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-1', '93.184.216.34');
    const result = (await resultPromise) as { enrichment: { registrant?: string } };

    expect(result.enrichment.registrant).toBe('Referred Org');
    expect(calls).toContain('https://rdap.publicinterestregistry.org/rdap/domain/example.com');
  }, 20_000);
});
