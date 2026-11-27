// lib/__tests__/enrichment-clear.test.ts
//
// KAN-317: after `enrich clear` resolves, nothing a lookup started before it
// may send a query, write the cache or log, or show a result.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EnrichmentClient } from '../enrichment';
import { EnrichmentCache } from '../enrichment/cache';

const DAY_MS = 24 * 60 * 60 * 1000;
const CACHE_OPTS = { label: 'test', isRecord: () => true, ttlMs: 14 * DAY_MS, negativeTtlMs: 14 * DAY_MS };
import { atomicWriteJson } from '../enrichment/fs-util';
import { QueryLog } from '../enrichment/query-log';

const ADDR = '93.184.216.34';
const IP_BOOTSTRAP = { services: [[['93.184.216.0/24', '198.51.100.0/24'], ['https://rdap.arin.net/registry/']]] };
const DNS_BOOTSTRAP = { services: [[['com'], ['https://rdap.verisign.com/com/v1/']]] };
const IP_RDAP = { objectClassName: 'ip network', name: 'EXAMPLE-NET', startAddress: '93.184.216.0', endAddress: '93.184.216.255' };
// The registry refers to the registrar, so a lookup sends a second query.
const DOMAIN_RDAP = { objectClassName: 'domain', links: [{ rel: 'related', href: 'https://rdap.publicinterestregistry.org/rdap/domain/example.com' }], entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['org', {}, 'text', 'Registrant']]] }] };

function deferred<T = void>() {
  let resolve: (v: T) => void = () => {};
  let reject: (e: unknown) => void = () => {};
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

describe('enrich clear', () => {
  let dir: string;
  let fetched: string[];
  let held: Map<string, Promise<void>>;
  let domainRdap: unknown;
  let results: unknown[];
  let unhandled: ReturnType<typeof vi.fn<(reason: unknown) => void>>;
  let error: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'enrichment-clear-'));
    fetched = [];
    held = new Map();
    domainRdap = DOMAIN_RDAP;
    results = [];
    unhandled = vi.fn<(reason: unknown) => void>();
    process.on('unhandledRejection', unhandled);
    error = vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    process.off('unhandledRejection', unhandled);
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  const fetchImpl = vi.fn(async (url: string) => {
    fetched.push(url);
    for (const [part, gate] of held) if (url.includes(part)) await gate;
    if (url.includes('ipv4.json')) return Response.json(IP_BOOTSTRAP);
    if (url.includes('dns.json')) return Response.json(DNS_BOOTSTRAP);
    if (url.includes('verisign')) return Response.json(domainRdap);
    return Response.json(IP_RDAP);
  }) as unknown as typeof fetch;

  const hold = (part: string) => {
    const gate = deferred();
    held.set(part, gate.promise);
    return gate.resolve;
  };

  const holdThenFail = (part: string) => {
    const gate = deferred();
    held.set(part, gate.promise);
    return () => gate.reject(new Error('fetch failed'));
  };

  const client = (reverseDnsFn: (ip: string) => Promise<string | null> = async () => null) => {
    const c = new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn, queueOptions: { minDelayMs: 1, maxDelayMs: 2 } });
    c.on('result', (r) => results.push(r));
    c.enableBackground();
    return c;
  };

  const settle = () => new Promise((r) => setTimeout(r, 50));

  // Nothing of the looked-up address is left, and nothing more is sent.
  const expectNothingLeft = async (fetchesAtClear: number) => {
    await settle();
    expect(results).toEqual([]);
    expect(fetched.slice(fetchesAtClear)).toEqual([]);
    expect(readFileSync(join(dir, 'query-log.ndjson'), 'utf8')).toBe('');
    expect(JSON.parse(readFileSync(join(dir, 'cache.json'), 'utf8'))).toEqual({ entries: [] });
    expect(unhandled).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
  };

  it('turns lookups off before it wipes anything', async () => {
    const c = client();
    const append = deferred();
    vi.spyOn(QueryLog.prototype, 'clear').mockImplementationOnce(async function (this: QueryLog) {
      await append.promise;
      return QueryLog.prototype.clear.call(this);
    });
    const cleared = c.clear();
    expect(c.getMode()).toBe('off');
    c.requestLookup('conn-1', ADDR);
    c.notifyObservedConnections([{ id: 'conn-2', remoteAddr: ADDR }]);
    append.resolve();
    await cleared;
    await expectNothingLeft(0);
  });

  it.each([
    ['the bootstrap fetch', 'ipv4.json'],
    ['its RDAP query', 'rdap.arin.net'],
  ])('drops a lookup held at %s', async (_name, part) => {
    const release = hold(part);
    const c = client();
    c.requestLookup('conn-1', ADDR);
    await vi.waitFor(() => expect(fetched.some((u) => u.includes(part))).toBe(true));
    const atClear = fetched.length;
    await c.clear();
    release();
    await expectNothingLeft(atClear);
  });

  it('drops a lookup for an address with no RDAP service, held at the bootstrap fetch', async () => {
    const release = hold('ipv4.json');
    const c = client();
    c.requestLookup('conn-1', '203.0.113.9');
    await vi.waitFor(() => expect(fetched).toHaveLength(1));
    await c.clear();
    release();
    await expectNothingLeft(1);
  });

  it('logs nothing when a dropped lookup then fails', async () => {
    const fail = holdThenFail('ipv4.json');
    const c = client();
    c.requestLookup('conn-1', ADDR);
    await vi.waitFor(() => expect(fetched).toHaveLength(1));
    await c.clear();
    fail();
    await expectNothingLeft(1);
  });

  it('logs nothing when a dropped lookup\'s registrant step then fails', async () => {
    const fail = holdThenFail('dns.json');
    const c = client(async () => 'example.com');
    c.requestLookup('conn-1', ADDR);
    await vi.waitFor(() => expect(fetched.some((u) => u.includes('dns.json'))).toBe(true));
    const atClear = fetched.length;
    await c.clear();
    fail();
    await expectNothingLeft(atClear);
  });

  it('does not hold new lookups behind queries it dropped', async () => {
    const release = hold('rdap.arin.net');
    const c = new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn: async () => null, queueOptions: { minDelayMs: 300, maxDelayMs: 300 } });
    c.on('result', (r) => results.push(r));
    c.enableBackground();
    c.requestLookup('conn-1', ADDR);
    await vi.waitFor(() => expect(fetched.some((u) => new URL(u).hostname === 'rdap.arin.net')).toBe(true));
    for (let i = 1; i <= 5; i++) c.requestLookup(`queued-${i}`, `198.51.100.${i}`);
    await settle();
    await c.clear();
    c.enable();
    c.requestLookup('conn-2', '93.184.216.99');
    const start = Date.now();
    release();
    await vi.waitFor(() => expect(results).toHaveLength(1), { timeout: 3000 });
    // One spacing delay after the held query, not one per dropped query.
    expect(Date.now() - start).toBeLessThan(900);
    expect(results).toMatchObject([{ connectionId: 'conn-2' }]);
  });

  it('skips a query still waiting in the queue', async () => {
    const release = hold('rdap.arin.net');
    const c = client();
    c.requestLookup('conn-1', ADDR);
    await vi.waitFor(() => expect(fetched.some((u) => new URL(u).hostname === 'rdap.arin.net')).toBe(true));
    c.requestLookup('conn-2', '198.51.100.7');
    await settle();
    const atClear = fetched.length;
    await c.clear();
    release();
    await expectNothingLeft(atClear);
  });

  it('drops a lookup held at reverse DNS, before any registrant query', async () => {
    const dns = deferred<string | null>();
    const reverse = vi.fn(() => dns.promise);
    const c = client(reverse);
    c.requestLookup('conn-1', ADDR);
    await vi.waitFor(() => expect(reverse).toHaveBeenCalled());
    const atClear = fetched.length;
    await c.clear();
    dns.resolve('example.com');
    await expectNothingLeft(atClear);
  });

  it.each([
    ['that refers to the registrar', true],
    ['with no referral', false],
  ])('drops a lookup held at its registrant query, %s', async (_name, referral) => {
    if (!referral) domainRdap = { ...DOMAIN_RDAP, links: [] };
    const release = hold('verisign');
    const c = client(async () => 'example.com');
    c.requestLookup('conn-1', ADDR);
    await vi.waitFor(() => expect(fetched.some((u) => u.includes('verisign'))).toBe(true));
    const atClear = fetched.length;
    await c.clear();
    release();
    await expectNothingLeft(atClear);
  });

  it('drops a cached result whose log entry is still being written', async () => {
    writeFileSync(join(dir, 'cache.json'), JSON.stringify({ entries: [{ key: '93.184.216.0/24', record: { org: 'X', source: 'rdap', fetchedAt: '2026-01-01' }, expiresAt: Date.now() + 60_000 }] }));
    // Held inside the log's write queue, as a slow disk would hold it.
    const write = deferred();
    type Writes = { appendNow: (...args: unknown[]) => Promise<void> };
    const proto = QueryLog.prototype as unknown as Writes;
    const appendNow = proto.appendNow;
    vi.spyOn(proto, 'appendNow').mockImplementationOnce(async function (this: Writes, ...args) {
      await write.promise;
      return appendNow.apply(this, args);
    });
    const c = client();
    c.requestLookup('conn-1', ADDR);
    const cleared = c.clear();
    write.resolve();
    await cleared;
    await expectNothingLeft(0);
  });

  it('a lookup turned on again after clear works and is not joined to a dropped one', async () => {
    const release = hold('rdap.arin.net');
    const c = client();
    c.requestLookup('conn-1', ADDR);
    await vi.waitFor(() => expect(fetched.some((u) => new URL(u).hostname === 'rdap.arin.net')).toBe(true));
    await c.clear();
    held.clear();
    c.enable();
    c.requestLookup('conn-2', ADDR);
    release(); // the queue sends one query at a time, so conn-2 waits for this
    await vi.waitFor(() => expect(results).toHaveLength(1));
    await settle();
    expect(results).toMatchObject([{ connectionId: 'conn-2' }]);
  });

  it('removes leftover temp files of the log and cache, and nothing else', async () => {
    mkdirSync(dir, { recursive: true });
    for (const name of ['query-log.ndjson.tmp-aaaaaaaaaaaa', 'cache.json.tmp-bbbbbbbbbbbb', 'bootstrap-ipv4.json', 'other.tmp-cccc'])
      writeFileSync(join(dir, name), ADDR);
    await client().clear();
    expect(readdirSync(dir).sort()).toEqual(['bootstrap-ipv4.json', 'cache.json', 'other.tmp-cccc', 'query-log.ndjson']);
  });

  it('a failed clear still turns lookups off and wipes what it can', async () => {
    writeFileSync(join(dir, 'cache.json'), JSON.stringify({ entries: [{ key: '93.184.216.0/24', record: null, expiresAt: Date.now() + 60_000 }] }));
    mkdirSync(join(dir, 'query-log.ndjson'));
    const c = client();
    await expect(c.clear()).rejects.toMatchObject({ code: 'EISDIR' });
    expect(c.getMode()).toBe('off');
    expect(JSON.parse(readFileSync(join(dir, 'cache.json'), 'utf8'))).toEqual({ entries: [] });
  });

  it('a clear whose two wipes both fail reports both', async () => {
    mkdirSync(join(dir, 'cache.json'), { recursive: true });
    mkdirSync(join(dir, 'query-log.ndjson'));
    const c = client();
    const failed = await c.clear().catch((err: unknown) => err);
    expect(failed).toBeInstanceOf(AggregateError);
    expect((failed as AggregateError).errors).toHaveLength(2);
    expect(c.getMode()).toBe('off');
  });
});

describe('EnrichmentCache writes', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'enrichment-cache-race-')); });
  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  it('a failed write leaves no temp file behind', async () => {
    vi.spyOn(fs, 'rename').mockRejectedValueOnce(Object.assign(new Error('rename failed'), { code: 'EXDEV' }));
    await expect(atomicWriteJson(join(dir, 'cache.json'), { entries: [] })).rejects.toMatchObject({ code: 'EXDEV' });
    expect(readdirSync(dir)).toEqual([]);
  });

  it('a write that began before clear() cannot land after it', async () => {
    const file = join(dir, 'cache.json');
    const cache = new EnrichmentCache(file, CACHE_OPTS);
    const rename = fs.rename;
    const gate = deferred();
    vi.spyOn(fs, 'rename').mockImplementationOnce(async (from, to) => {
      await gate.promise;
      await rename(from, to);
    });
    const write = cache.setSuccess('93.184.216.0/24', { org: 'X', source: 'rdap', fetchedAt: '2026-01-01' }, 60_000);
    await vi.waitFor(() => expect(fs.rename).toHaveBeenCalled());
    const cleared = cache.clear();
    // Time for clear() to write first, as it would if writes overlapped.
    await new Promise((r) => setTimeout(r, 50));
    gate.resolve();
    await Promise.all([write, cleared]);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ entries: [] });
    expect(existsSync(file)).toBe(true);
  });
});
