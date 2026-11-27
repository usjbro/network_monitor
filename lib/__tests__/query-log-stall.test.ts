// lib/__tests__/query-log-stall.test.ts
//
// KAN-319: one stalled query-log write must not hold up cached results,
// `enrich clear` or later prunes, and what it costs is stated: at most
// MAX_QUEUED_WRITES writes wait, beyond which cached-lookup entries are
// dropped and counted. An entry for a query that left the machine is never
// dropped.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CLEAR_TIMEOUT_MS, ClearTimeoutError, EnrichmentClient } from '../enrichment';
import { MAX_QUEUED_WRITES, QueryLog } from '../enrichment/query-log';
import { SerialWrites } from '../enrichment/fs-util';

const ADDR = '93.184.216.34';
const UNCACHED = '198.51.100.7';
const IP_BOOTSTRAP = { services: [[['93.184.216.0/24', '198.51.100.0/24'], ['https://rdap.arin.net/registry/']]] };
const IP_RDAP = { objectClassName: 'ip network', name: 'EXAMPLE-NET', startAddress: '198.51.100.0', endAddress: '198.51.100.255' };
// The registry refers to the registrar, so a lookup sends a second query.
const REFERRING_REGISTRY = { objectClassName: 'domain', links: [{ rel: 'related', href: 'https://rdap.publicinterestregistry.org/rdap/domain/example.com' }] };
const CACHED = { key: '93.184.216.0/24', record: { org: 'X', source: 'rdap', fetchedAt: '2026-01-01' } };

function isRegistryQuery(url: string): boolean {
  const { hostname, pathname } = new URL(url);
  return hostname === 'rdap.verisign.com' && pathname.startsWith('/com/v1/domain/');
}

function deferred() {
  let resolve = () => {};
  const promise = new Promise<void>((res) => { resolve = res; });
  return { promise, resolve };
}

type Writes = Record<'appendNow' | 'clearNow' | 'pruneNow', (...args: unknown[]) => Promise<unknown>>;

// Holds every call of one QueryLog write inside the write queue, as a slow
// disk would, until the returned function is called.
function holdWrites(name: keyof Writes): () => void {
  const gate = deferred();
  const proto = QueryLog.prototype as unknown as Writes;
  const real = proto[name];
  vi.spyOn(proto, name).mockImplementation(async function (this: Writes, ...args) {
    await gate.promise;
    return real.apply(this, args);
  });
  return gate.resolve;
}

describe('a stalled query-log write', () => {
  let dir: string;
  let results: unknown[];
  let error: ReturnType<typeof vi.spyOn>;
  const logFile = () => join(dir, 'query-log.ndjson');
  const logLines = () => readFileSync(logFile(), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

  let rdapGate: Promise<void> = Promise.resolve();
  let registryGate: Promise<void> = Promise.resolve();
  const fetchImpl = vi.fn(async (url: string) => {
    if (url.includes('ipv4.json')) return Response.json(IP_BOOTSTRAP);
    if (url.includes('dns.json')) return Response.json({ services: [[['com'], ['https://rdap.verisign.com/com/v1/']]] });
    if (new URL(url).hostname === 'rdap.verisign.com') {
      await registryGate;
      return Response.json(REFERRING_REGISTRY);
    }
    await rdapGate;
    return Response.json(IP_RDAP);
  }) as unknown as typeof fetch;

  const client = (opts: { clearTimeoutMs?: number } = {}) => {
    const c = track(new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn: async () => null, queueOptions: { minDelayMs: 1, maxDelayMs: 2 }, ...opts }));
    c.on('result', (r) => results.push(r));
    c.enableBackground();
    return c;
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'query-log-stall-'));
    writeFileSync(join(dir, 'cache.json'), JSON.stringify({ entries: [{ ...CACHED, expiresAt: Date.now() + 60_000 }] }));
    results = [];
    vi.mocked(fetchImpl).mockClear();
    rdapGate = Promise.resolve();
    registryGate = Promise.resolve();
    error = vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  // A cached lookup's log entry is written after its result, so each test's
  // writes are waited for before its folder is removed.
  let clients: EnrichmentClient[] = [];
  const track = (c: EnrichmentClient) => {
    clients.push(c);
    return c;
  };
  afterEach(async () => {
    await Promise.all(clients.map((c) => c.idle()));
    clients = [];
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  it('is idle only once its log writes are done', async () => {
    const release = holdWrites('appendNow');
    const c = client();
    c.requestLookup('conn-1', ADDR);
    let idle = false;
    void c.idle().then(() => { idle = true; });
    await new Promise((r) => setTimeout(r, 20));
    expect(idle).toBe(false);
    release();
    await vi.waitFor(() => expect(idle).toBe(true));
    expect(logLines()).toHaveLength(1);
  });

  it('does not hold up a cached result, whose entry is written once the disk responds', async () => {
    const release = holdWrites('appendNow');
    const c = client();
    c.requestLookup('conn-1', ADDR);
    await vi.waitFor(() => expect(results).toMatchObject([{ connectionId: 'conn-1' }]));
    release();
    await vi.waitFor(() => expect(logLines()).toMatchObject([{ target: ADDR, endpoint: 'cache', cacheStatus: 'hit' }]));
    expect(c.getMode()).toBe('background');
  });

  it(`queues at most ${MAX_QUEUED_WRITES} writes, then drops cached-lookup entries and reports how many`, async () => {
    expect(MAX_QUEUED_WRITES).toBe(1000);
    const release = holdWrites('appendNow');
    const c = client();
    for (let i = 0; i < MAX_QUEUED_WRITES + 5; i++) c.requestLookup(`conn-${i}`, ADDR);
    await vi.waitFor(() => expect(results).toHaveLength(MAX_QUEUED_WRITES + 5));
    expect(error.mock.calls).toEqual([[`[enrichment] the query log is backed up (${MAX_QUEUED_WRITES} writes queued): cached lookups are not logged, and lookups that need a query fail without sending it`]]);
    release();
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2));
    expect(error.mock.calls[1]).toEqual(['[enrichment] while the query log was backed up, 5 cached-lookup entries were not written and 0 lookups failed without sending a query']);
    expect(logLines()).toHaveLength(MAX_QUEUED_WRITES);
  });

  it('reports one dropped entry in the singular', async () => {
    const release = holdWrites('appendNow');
    const c = client();
    for (let i = 0; i < MAX_QUEUED_WRITES + 1; i++) c.requestLookup(`conn-${i}`, ADDR);
    await vi.waitFor(() => expect(results).toHaveLength(MAX_QUEUED_WRITES + 1));
    release();
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2));
    expect(error.mock.calls[1]).toEqual(['[enrichment] while the query log was backed up, 1 cached-lookup entry was not written and 0 lookups failed without sending a query']);
  });

  it('logs cached lookups again once a backlog clears, and counts each backlog on its own', async () => {
    let release = holdWrites('appendNow');
    const c = client();
    for (let i = 0; i < MAX_QUEUED_WRITES + 3; i++) c.requestLookup(`a-${i}`, ADDR);
    release();
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2));
    vi.restoreAllMocks();
    error = vi.spyOn(console, 'error').mockImplementation(() => {});
    c.requestLookup('after', ADDR);
    await vi.waitFor(() => expect(logLines()).toHaveLength(MAX_QUEUED_WRITES + 1));
    release = holdWrites('appendNow');
    for (let i = 0; i < MAX_QUEUED_WRITES + 2; i++) c.requestLookup(`b-${i}`, ADDR);
    release();
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2));
    expect(error.mock.calls[1]).toEqual(['[enrichment] while the query log was backed up, 2 cached-lookup entries were not written and 0 lookups failed without sending a query']);
  });

  const sentTo = (addr: string) => vi.mocked(fetchImpl).mock.calls.some(([u]) => String(u).includes(`/ip/${addr}`));

  it('never drops the entry for a query already sent when the backlog builds', async () => {
    const answer = deferred();
    rdapGate = answer.promise;
    const release = holdWrites('appendNow');
    const c = client();
    c.requestLookup('conn-off', UNCACHED);
    await vi.waitFor(() => expect(sentTo(UNCACHED)).toBe(true));
    // The backlog fills while the query is out; its answer then comes back.
    for (let i = 0; i < MAX_QUEUED_WRITES + 1; i++) c.requestLookup(`conn-${i}`, ADDR);
    answer.resolve();
    // The lookup waits for its entry rather than showing a result without one.
    await new Promise((r) => setTimeout(r, 50));
    expect(results).not.toContainEqual(expect.objectContaining({ connectionId: 'conn-off' }));
    release();
    await vi.waitFor(() => expect(results).toContainEqual(expect.objectContaining({ connectionId: 'conn-off' })));
    expect(logLines()).toContainEqual(expect.objectContaining({ target: UNCACHED, endpoint: 'rdap.arin.net', cacheStatus: 'miss' }));
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2));
    expect(error.mock.calls[1]).toEqual(['[enrichment] while the query log was backed up, 1 cached-lookup entry was not written and 0 lookups failed without sending a query']);
  });

  it('sends no query while the log is backed up, and counts the lookup that failed', async () => {
    const release = holdWrites('appendNow');
    const c = client();
    for (let i = 0; i < MAX_QUEUED_WRITES; i++) c.requestLookup(`conn-${i}`, ADDR);
    c.requestLookup('conn-off', UNCACHED);
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(1));
    expect(error.mock.calls[0]).toEqual([`[enrichment] the query log is backed up (${MAX_QUEUED_WRITES} writes queued): cached lookups are not logged, and lookups that need a query fail without sending it`]);
    await new Promise((r) => setTimeout(r, 50));
    expect(sentTo(UNCACHED)).toBe(false);
    release();
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2));
    expect(error.mock.calls[1]).toEqual(['[enrichment] while the query log was backed up, 0 cached-lookup entries were not written and 1 lookup failed without sending a query']);
    expect(results).not.toContainEqual(expect.objectContaining({ connectionId: 'conn-off' }));
  });

  it('counts a registrant query refused during a backlog, and still shows the ownership result', async () => {
    const ptr = deferred();
    const release = holdWrites('appendNow');
    const c = track(new EnrichmentClient({ dataDir: dir, fetchImpl, queueOptions: { minDelayMs: 1, maxDelayMs: 2 }, reverseDnsFn: async () => (await ptr.promise, 'host.example.com') }));
    c.on('result', (r) => results.push(r));
    c.enableBackground();
    c.requestLookup('conn-off', UNCACHED);
    await vi.waitFor(() => expect(sentTo(UNCACHED)).toBe(true));
    release(); // the RDAP query's entry is written; the lookup reaches reverse DNS
    await vi.waitFor(() => expect(logLines()).toHaveLength(1));
    // A second spy on a spied method is the same spy; restore it first.
    vi.mocked((QueryLog.prototype as unknown as Writes).appendNow).mockRestore();
    const hold = holdWrites('appendNow');
    for (let i = 0; i < MAX_QUEUED_WRITES; i++) c.requestLookup(`conn-${i}`, ADDR);
    ptr.resolve();
    await vi.waitFor(() => expect(results).toContainEqual(expect.objectContaining({ connectionId: 'conn-off' })));
    expect(vi.mocked(fetchImpl).mock.calls.some(([u]) => isRegistryQuery(String(u)))).toBe(false);
    hold();
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2));
    expect(error.mock.calls[1]).toEqual(['[enrichment] while the query log was backed up, 0 cached-lookup entries were not written and 1 lookup failed without sending a query']);
    // Cached for an hour, not 14 days, so the registrant is looked up again.
    await vi.waitFor(() => expect(JSON.parse(readFileSync(join(dir, 'cache.json'), 'utf8')).entries).toHaveLength(2));
    const entry = JSON.parse(readFileSync(join(dir, 'cache.json'), 'utf8')).entries.find((e: { key: string }) => e.key.startsWith('198.51.100'));
    expect(entry.expiresAt).toBeLessThanOrEqual(Date.now() + 60 * 60 * 1000);
  });

  it('sends no registrar referral once the log backs up while the registry query is out', async () => {
    const registry = deferred();
    registryGate = registry.promise;
    const c = track(new EnrichmentClient({ dataDir: dir, fetchImpl, queueOptions: { minDelayMs: 1, maxDelayMs: 2 }, reverseDnsFn: async () => 'host.example.com' }));
    c.on('result', (r) => results.push(r));
    c.enableBackground();
    c.requestLookup('conn-off', UNCACHED);
    await vi.waitFor(() => expect(vi.mocked(fetchImpl).mock.calls.some(([u]) => isRegistryQuery(String(u)))).toBe(true));
    const release = holdWrites('appendNow');
    for (let i = 0; i < MAX_QUEUED_WRITES; i++) c.requestLookup(`conn-${i}`, ADDR);
    registry.resolve();
    // The lookup waits for the sent registry query's entry, behind the backlog.
    await new Promise((r) => setTimeout(r, 50));
    release();
    await vi.waitFor(() => expect(results.some((r) => (r as { connectionId: string }).connectionId === 'conn-off')).toBe(true));
    expect(vi.mocked(fetchImpl).mock.calls.some(([u]) => new URL(String(u)).hostname === 'rdap.publicinterestregistry.org')).toBe(false);
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2));
    // The registry query went out, so it is logged even though the referral was refused.
    await vi.waitFor(() => expect(logLines()).toContainEqual(expect.objectContaining({ target: 'host.example.com', endpoint: 'rdap.verisign.com', cacheStatus: 'miss' })));
  });

  it('a lookup refused during a backlog uses up no rate-limit delay', async () => {
    const release = holdWrites('appendNow');
    const c = track(new EnrichmentClient({ dataDir: dir, fetchImpl, queueOptions: { minDelayMs: 1_000, maxDelayMs: 1_000 }, reverseDnsFn: async () => null }));
    c.enableBackground();
    for (let i = 0; i < MAX_QUEUED_WRITES; i++) c.requestLookup(`conn-${i}`, ADDR);
    const started = Date.now();
    for (const n of [1, 2, 3]) c.requestLookup(`off-${n}`, `198.51.100.${n}`);
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(1));
    release();
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2), { timeout: 3_000 });
    expect(error.mock.calls[1]).toEqual(['[enrichment] while the query log was backed up, 0 cached-lookup entries were not written and 3 lookups failed without sending a query']);
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it('reports a backlog that has not ended after a while, and then reports the rest as a new one', async () => {
    const release = holdWrites('appendNow');
    const c = track(new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn: async () => null, backlogReportMs: 50 }));
    c.on('result', (r) => results.push(r));
    c.enableBackground();
    for (let i = 0; i < MAX_QUEUED_WRITES + 2; i++) c.requestLookup(`a-${i}`, ADDR);
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2));
    expect(error.mock.calls[1]).toEqual(['[enrichment] while the query log was backed up, 2 cached-lookup entries were not written and 0 lookups failed without sending a query']);
    c.requestLookup('b', ADDR);
    expect(error).toHaveBeenCalledTimes(3);
    release();
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(4));
    expect(error.mock.calls[3]).toEqual(['[enrichment] while the query log was backed up, 1 cached-lookup entry was not written and 0 lookups failed without sending a query']);
  });

  it(`a clear held up by it reports a timeout after ${CLEAR_TIMEOUT_MS / 1000} s, with lookups off, and still wipes afterwards`, async () => {
    expect(CLEAR_TIMEOUT_MS).toBe(10_000);
    const release = holdWrites('appendNow');
    const c = client({ clearTimeoutMs: 50 });
    c.requestLookup('conn-1', ADDR);
    await vi.waitFor(() => expect(results).toHaveLength(1));
    const failed = await c.clear().catch((err: unknown) => err);
    expect(failed).toBeInstanceOf(ClearTimeoutError);
    expect(c.getMode()).toBe('off');
    expect(error).not.toHaveBeenCalled();
    // The held write lands first; the wipe queued behind it then removes it.
    release();
    await vi.waitFor(() => expect(error.mock.calls).toEqual([['[enrichment] clear finished after timing out']]));
    expect(readFileSync(logFile(), 'utf8')).toBe('');
    expect(JSON.parse(readFileSync(join(dir, 'cache.json'), 'utf8'))).toEqual({ entries: [] });
  });

  it('a timed-out clear that then fails says so, without a path', async () => {
    const release = holdWrites('appendNow');
    const c = client({ clearTimeoutMs: 50 });
    c.requestLookup('conn-1', ADDR);
    vi.spyOn(QueryLog.prototype as unknown as Writes, 'clearNow').mockRejectedValueOnce(Object.assign(new Error(`EACCES: open '${logFile()}'`), { code: 'EACCES' }));
    await expect(c.clear()).rejects.toBeInstanceOf(ClearTimeoutError);
    release();
    await vi.waitFor(() => expect(error.mock.calls).toEqual([['[enrichment] clear failed after timing out:', 'EACCES']]));
  });

  it('a wipe that has already failed is reported as failed, not as timed out', async () => {
    const release = holdWrites('appendNow');
    const c = client({ clearTimeoutMs: 50 });
    c.requestLookup('conn-1', ADDR);
    const { EnrichmentCache } = await import('../enrichment/cache');
    vi.spyOn(EnrichmentCache.prototype, 'clear').mockRejectedValueOnce(Object.assign(new Error('EACCES: x'), { code: 'EACCES' }));
    await expect(c.clear()).rejects.toMatchObject({ code: 'EACCES' });
    expect(c.getMode()).toBe('off');
    release();
    await vi.waitFor(() => expect(error.mock.calls).toEqual([['[enrichment] clear failed after timing out:', 'EACCES']]));
  });

  it('an entry written after lookups are turned on again is kept by the late wipe', async () => {
    const release = holdWrites('appendNow');
    const c = client({ clearTimeoutMs: 50 });
    c.requestLookup('conn-1', ADDR);
    await expect(c.clear()).rejects.toBeInstanceOf(ClearTimeoutError);
    c.enable();
    c.requestLookup('conn-2', UNCACHED);
    release();
    await vi.waitFor(() => expect(results).toContainEqual(expect.objectContaining({ connectionId: 'conn-2' })));
    expect(logLines()).toMatchObject([{ target: UNCACHED, cacheStatus: 'miss' }]);
  });

  it('a clear\'s timer does not keep the process alive', async () => {
    const release = holdWrites('appendNow');
    const c = client({ clearTimeoutMs: 50 });
    c.requestLookup('conn-1', ADDR);
    const set = vi.spyOn(globalThis, 'setTimeout');
    const cleared = c.clear().catch(() => {});
    const index = set.mock.calls.findIndex(([, ms]) => ms === 50);
    expect((set.mock.results[index].value as NodeJS.Timeout).hasRef()).toBe(false);
    await cleared;
    release();
    await vi.waitFor(() => expect(error.mock.calls).toEqual([['[enrichment] clear finished after timing out']]));
  });

  it('a clear that is not held up is not reported as timed out, and leaves no timer running', async () => {
    const c = client({ clearTimeoutMs: 50 });
    c.requestLookup('conn-1', ADDR);
    const set = vi.spyOn(globalThis, 'setTimeout');
    const cancel = vi.spyOn(globalThis, 'clearTimeout');
    await c.clear();
    const index = set.mock.calls.findIndex(([, ms]) => ms === 50);
    expect(cancel).toHaveBeenCalledWith(set.mock.results[index].value);
    await new Promise((r) => setTimeout(r, 100));
    expect(error).not.toHaveBeenCalled();
  });
});

describe('a stalled prune', () => {
  const SIX_HOURS = 6 * 60 * 60 * 1000;
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'query-log-stall-'));
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
    rmSync(dir, { recursive: true, force: true });
  });

  it('is logged when the next prune is due, and later prunes run once it finishes', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    let finish = (_: number) => {};
    const prune = vi.spyOn(QueryLog.prototype, 'prune').mockReturnValueOnce(new Promise((r) => { finish = r; })).mockResolvedValue(0);
    void new EnrichmentClient({ dataDir: dir }).startPruning();
    await vi.advanceTimersByTimeAsync(SIX_HOURS);
    expect(error.mock.calls).toEqual([['[enrichment] query-log prune skipped: the last one has not finished']]);
    expect(prune).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(SIX_HOURS);
    expect(error).toHaveBeenCalledTimes(1);
    // The skipped prunes run once, as soon as the stalled one finishes.
    finish(0);
    await vi.advanceTimersByTimeAsync(0);
    expect(prune).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(SIX_HOURS);
    expect(prune).toHaveBeenCalledTimes(3);
  });
});

describe('SerialWrites', () => {
  it('reports its size, and is drained after each backlog', async () => {
    const writes = new SerialWrites();
    expect(writes.size).toBe(0);
    for (const round of [1, 2]) {
      const gate = deferred();
      const held = writes.run(() => gate.promise);
      void writes.run(async () => {});
      expect(writes.size).toBe(2);
      let drained = false;
      void writes.drained().then(() => { drained = true; });
      await new Promise((r) => setTimeout(r, 10));
      expect({ round, drained }).toEqual({ round, drained: false });
      gate.resolve();
      await held;
      await vi.waitFor(() => expect({ round, drained }).toEqual({ round, drained: true }));
      expect(writes.size).toBe(0);
    }
  });
});
