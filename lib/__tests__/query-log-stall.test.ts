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

const ADDR = '93.184.216.34';
const UNCACHED = '198.51.100.7';
const IP_BOOTSTRAP = { services: [[['93.184.216.0/24', '198.51.100.0/24'], ['https://rdap.arin.net/registry/']]] };
const IP_RDAP = { objectClassName: 'ip network', name: 'EXAMPLE-NET', startAddress: '198.51.100.0', endAddress: '198.51.100.255' };
const CACHED = { key: '93.184.216.0/24', record: { org: 'X', source: 'rdap', fetchedAt: '2026-01-01' } };

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

  const fetchImpl = vi.fn(async (url: string) => Response.json(url.includes('ipv4.json') ? IP_BOOTSTRAP : IP_RDAP)) as unknown as typeof fetch;

  const client = (opts: { clearTimeoutMs?: number } = {}) => {
    const c = new EnrichmentClient({ dataDir: dir, fetchImpl, reverseDnsFn: async () => null, queueOptions: { minDelayMs: 1, maxDelayMs: 2 }, ...opts });
    c.on('result', (r) => results.push(r));
    c.enableBackground();
    return c;
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'query-log-stall-'));
    writeFileSync(join(dir, 'cache.json'), JSON.stringify({ entries: [{ ...CACHED, expiresAt: Date.now() + 60_000 }] }));
    results = [];
    error = vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
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
    expect(error.mock.calls).toEqual([[`[enrichment] the query log is backed up (${MAX_QUEUED_WRITES} writes queued); cached lookups are not being logged`]]);
    release();
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2));
    expect(error.mock.calls[1]).toEqual(['[enrichment] the query log was backed up: 5 cached-lookup entries were not written']);
    expect(logLines()).toHaveLength(MAX_QUEUED_WRITES);
  });

  it('reports one dropped entry in the singular', async () => {
    const release = holdWrites('appendNow');
    const c = client();
    for (let i = 0; i < MAX_QUEUED_WRITES + 1; i++) c.requestLookup(`conn-${i}`, ADDR);
    await vi.waitFor(() => expect(results).toHaveLength(MAX_QUEUED_WRITES + 1));
    release();
    await vi.waitFor(() => expect(error).toHaveBeenCalledTimes(2));
    expect(error.mock.calls[1]).toEqual(['[enrichment] the query log was backed up: 1 cached-lookup entry was not written']);
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
    expect(error.mock.calls[1]).toEqual(['[enrichment] the query log was backed up: 2 cached-lookup entries were not written']);
  });

  it('never drops the entry for a query that went off the machine', async () => {
    const release = holdWrites('appendNow');
    const c = client();
    for (let i = 0; i < MAX_QUEUED_WRITES; i++) c.requestLookup(`conn-${i}`, ADDR);
    c.requestLookup('conn-off', UNCACHED);
    await vi.waitFor(() => expect(vi.mocked(fetchImpl).mock.calls.some(([u]) => String(u).includes(`/ip/${UNCACHED}`))).toBe(true));
    // The lookup waits for its entry rather than showing a result without one.
    await new Promise((r) => setTimeout(r, 50));
    expect(results).not.toContainEqual(expect.objectContaining({ connectionId: 'conn-off' }));
    release();
    await vi.waitFor(() => expect(results).toContainEqual(expect.objectContaining({ connectionId: 'conn-off' })));
    expect(logLines()).toContainEqual(expect.objectContaining({ target: UNCACHED, endpoint: 'rdap.arin.net', cacheStatus: 'miss' }));
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
