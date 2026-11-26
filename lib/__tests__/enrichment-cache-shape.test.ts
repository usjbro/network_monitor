// lib/__tests__/enrichment-cache-shape.test.ts
//
// KAN-322: a cache file of the wrong shape is a cache miss, never a crash,
// for both the ownership and the GeoIP caches.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EnrichmentCache, isEnrichmentRecord } from '../enrichment/cache';
import { EnrichmentClient } from '../enrichment';
import { QueryLog } from '../enrichment/query-log';
import { GeoIpClient } from '../geoip';

const ADDR = '93.184.216.34';
const GOOD = { key: '93.184.216.0/24', record: { org: 'EXAMPLE-ORG', source: 'rdap', fetchedAt: '2026-01-01' }, expiresAt: Date.now() + 60_000 };

const BAD_FILES: Array<[string, unknown]> = [
  ['entries as an object', { entries: {} }],
  ['a null entry', { entries: [null] }],
  ['an entry with no key', { entries: [{}] }],
  ['an entry with a number key', { entries: [{ key: 7, record: null, expiresAt: 1 }] }],
  ['an entry with no expiry', { entries: [{ key: '93.184.216.0/24', record: null }] }],
  ['an entry with a string record', { entries: [{ key: '93.184.216.0/24', record: 'x', expiresAt: Date.now() + 60_000 }] }],
  ['an entry with an array record', { entries: [{ key: '93.184.216.0/24', record: [], expiresAt: Date.now() + 60_000 }] }],
  ['entries as a string', { entries: 'abc' }],
  ['a top-level array', [GOOD]],
  ['a number', 5],
  ['null', null],
];

describe('cache files of the wrong shape', () => {
  let dir: string;
  let file: string;
  let error: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'cache-shape-'));
    file = join(dir, 'cache.json');
    error = vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  const write = (value: unknown) => writeFileSync(file, JSON.stringify(value));

  it.each(BAD_FILES)('%s loads as a miss', (_name, value) => {
    write(value);
    const cache = new EnrichmentCache(file);
    expect(() => cache.load()).not.toThrow();
    expect(cache.getForIp(ADDR)).toBeUndefined();
    expect(cache.getForDomain('93.184.216.0/24')).toBeUndefined();
  });

  it('keeps the good entries of a partly bad file and counts the bad ones', () => {
    write({ entries: [null, {}, GOOD, { key: 'example.com', record: null, expiresAt: 1 }, 'x'] });
    const cache = new EnrichmentCache(file);
    expect(cache.load()).toEqual({ file: false, entries: 3 });
    expect(cache.getForIp(ADDR)?.record?.org).toBe('EXAMPLE-ORG');
    expect(cache.getForDomain('example.com')).toEqual({ key: 'example.com', record: null, expiresAt: 1 });
  });

  it('a reload of a bad file keeps nothing from the earlier load', () => {
    write({ entries: [GOOD] });
    const cache = new EnrichmentCache(file);
    cache.load();
    write({ entries: {} });
    cache.load();
    expect(cache.getForIp(ADDR)).toBeUndefined();
  });

  it.each([
    ['an org that is an object', { org: { x: 1 }, source: 'rdap', fetchedAt: '2026-01-01' }],
    ['an asn that is a number', { asn: 5, source: 'rdap', fetchedAt: '2026-01-01' }],
    ['no source', { org: 'X', fetchedAt: '2026-01-01' }],
    ['an unknown source', { org: 'X', source: 'evil', fetchedAt: '2026-01-01' }],
    ['no fetch time', { org: 'X', source: 'rdap' }],
    ['an empty record', {}],
  ])('an ownership record with %s is unreadable', (_name, record) => {
    write({ entries: [{ ...GOOD, record }] });
    const cache = new EnrichmentCache(file, { label: 'enrichment', isRecord: isEnrichmentRecord, maxTtlMs: 60_000 });
    expect(cache.load()).toEqual({ file: false, entries: 1 });
    expect(cache.getForIp(ADDR)).toBeUndefined();
  });

  it.each([
    ['a truncated file', '{"entries":[{"key"'],
    ['an empty file', ''],
  ])('%s is ignored and reported', (_name, text) => {
    writeFileSync(file, text);
    const cache = new EnrichmentCache(file, { label: 'enrichment', isRecord: isEnrichmentRecord, maxTtlMs: 60_000 });
    expect(cache.load()).toEqual({ file: true, entries: 0 });
    expect(error.mock.calls).toEqual([['[enrichment] ignored the unreadable cache file']]);
  });

  it('a file it may not read is ignored and reported', () => {
    write({ entries: [GOOD] });
    chmodSync(file, 0o000);
    const cache = new EnrichmentCache(file, { label: 'geoip', isRecord: () => true, maxTtlMs: 60_000 });
    expect(cache.load()).toEqual({ file: true, entries: 0 });
    expect(error.mock.calls).toEqual([['[geoip] ignored the unreadable cache file']]);
  });

  it('an entry expiring after the longest TTL is cut back to it', () => {
    write({ entries: [{ ...GOOD, expiresAt: 1e15 }] });
    const cache = new EnrichmentCache(file, { label: 'enrichment', isRecord: isEnrichmentRecord, maxTtlMs: 60_000 });
    cache.load();
    const entry = cache.getForIp(ADDR)!;
    expect(cache.isFresh(entry, Date.now() + 59_000)).toBe(true);
    expect(cache.isFresh(entry, Date.now() + 61_000)).toBe(false);
  });

  it('counts nothing for a missing or well-formed file', () => {
    expect(new EnrichmentCache(file).load()).toEqual({ file: false, entries: 0 });
    write({ entries: [GOOD] });
    expect(new EnrichmentCache(file).load()).toEqual({ file: false, entries: 0 });
  });

  it('the enrichment client starts and prunes the query log with a bad cache, and logs a count only', async () => {
    write({ entries: [null, { key: ADDR, record: 'secret' }, GOOD] });
    const prune = vi.spyOn(QueryLog.prototype, 'prune');
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl: vi.fn() as unknown as typeof fetch });
    await client.startPruning();
    expect(prune).toHaveBeenCalledTimes(1);
    expect(error.mock.calls).toEqual([['[enrichment] ignored 2 unreadable cache entries']]);
  });

  it('the enrichment client treats a record with a wrong field as unreadable', () => {
    write({ entries: [{ ...GOOD, record: { org: { x: 1 }, source: 'rdap', fetchedAt: '2026-01-01' } }] });
    new EnrichmentClient({ dataDir: dir, fetchImpl: vi.fn() as unknown as typeof fetch });
    expect(error.mock.calls).toEqual([['[enrichment] ignored 1 unreadable cache entry']]);
  });

  it('the GeoIP client starts with a bad cache, and logs a count only', () => {
    write({ entries: {} });
    expect(() => new GeoIpClient({ fetchImpl: vi.fn() as unknown as typeof fetch, cachePath: file })).not.toThrow();
    expect(error.mock.calls).toEqual([['[geoip] ignored the unreadable cache file']]);
  });

  it('the GeoIP client treats a location with a wrong field as unreadable', () => {
    write({ entries: [{ key: `${ADDR}/32`, record: { city: 'X', lat: 'north', source: 'geoip' }, expiresAt: Date.now() + 60_000 }] });
    new GeoIpClient({ fetchImpl: vi.fn() as unknown as typeof fetch, cachePath: file });
    expect(error.mock.calls).toEqual([['[geoip] ignored 1 unreadable cache entry']]);
  });

  it('the GeoIP client logs a count of bad entries', () => {
    write({ entries: [{ key: ADDR }] });
    new GeoIpClient({ fetchImpl: vi.fn() as unknown as typeof fetch, cachePath: file });
    expect(error.mock.calls).toEqual([['[geoip] ignored 1 unreadable cache entry']]);
  });
});
