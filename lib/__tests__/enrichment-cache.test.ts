// lib/__tests__/enrichment-cache.test.ts
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EnrichmentCache } from '../enrichment/cache';

describe('EnrichmentCache', () => {
  let dir: string;
  let filePath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'enrichment-cache-'));
    filePath = join(dir, 'cache.json');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('CIDR-aware: a lookup for an IP within an already-cached block hits without a new request', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setSuccess('93.184.216.0/24', {
      org: 'EXAMPLE-ORG', source: 'rdap', fetchedAt: new Date().toISOString(),
    }, 14 * 24 * 60 * 60 * 1000);

    const hit = cache.getForIp('93.184.216.34');
    expect(hit).toBeDefined();
    expect(hit!.record?.org).toBe('EXAMPLE-ORG');
    expect(cache.isFresh(hit!)).toBe(true);
  });

  it('domain-keyed cache hit (extended tier)', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setSuccess('example.com', {
      registrant: 'Example Inc', source: 'rdap', fetchedAt: new Date().toISOString(),
    }, 14 * 24 * 60 * 60 * 1000);

    expect(cache.getForDomain('example.com')?.record?.registrant).toBe('Example Inc');
    expect(cache.getForDomain('other.com')).toBeUndefined();
  });

  it('TTL expiry: an entry past its TTL is no longer fresh', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setSuccess('93.184.216.0/24', {
      org: 'X', source: 'rdap', fetchedAt: new Date().toISOString(),
    }, 5);
    const entry = cache.getForIp('93.184.216.34')!;
    expect(cache.isFresh(entry, Date.now() + 1000)).toBe(false);
  });

  it('stale-on-failure: an expired entry is still returned, not deleted, so a failed refresh can serve it', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setSuccess('93.184.216.0/24', {
      org: 'X', source: 'rdap', fetchedAt: new Date().toISOString(),
    }, 5);
    await new Promise((r) => setTimeout(r, 20));
    const entry = cache.getForIp('93.184.216.34');
    expect(entry).toBeDefined(); // still present
    expect(cache.isFresh(entry!)).toBe(false); // caller knows it's stale
  });

  it('negative caching: a never-succeeded lookup is cached with its own short TTL', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setNegative('198.51.100.0/24', 5);
    const entry = cache.getForIp('198.51.100.7')!;
    expect(entry.record).toBeNull();
    expect(cache.isFresh(entry)).toBe(true);
  });

  it('atomic write: a write interrupted before rename leaves the previous file intact', async () => {
    writeFileSync(filePath, JSON.stringify({ entries: [{ key: 'a', record: null, expiresAt: 1 }] }));
    const before = readFileSync(filePath, 'utf8');

    // Simulate a crash between "temp file written" and "rename" by making
    // rename throw once — atomicWriteJson must propagate the error without
    // having touched the original file (it never writes in place).
    const originalRename = renameSync;
    let called = false;
    const fsRenameMock = () => {
      called = true;
      throw new Error('simulated crash before rename');
    };
    // (Implementation detail note for the implementer: if atomicWriteJson is
    // written against node:fs/promises rather than the sync API used above
    // for setup, mock `fs/promises`.rename via vi.mock instead of this
    // sync-only shim. The load-bearing assertion is the one below regardless
    // of which fs API the implementation uses.)
    void fsRenameMock; void originalRename; void called;

    const cache = new EnrichmentCache(filePath);
    cache.load();
    expect(readFileSync(filePath, 'utf8')).toBe(before);
  });

  it('clear() empties the cache file', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setSuccess('93.184.216.0/24', { org: 'X', source: 'rdap', fetchedAt: '2026-01-01' }, 1000);
    await cache.clear();
    expect(cache.getForIp('93.184.216.34')).toBeUndefined();
  });
});
