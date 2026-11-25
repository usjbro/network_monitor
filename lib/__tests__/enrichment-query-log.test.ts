// lib/__tests__/enrichment-query-log.test.ts
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { promises as fs, chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { QueryLog } from '../enrichment/query-log';

describe('QueryLog', () => {
  let dir: string;
  let filePath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'enrichment-qlog-'));
    filePath = join(dir, 'query-log.ndjson');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('appends newline-delimited entries without response bodies', async () => {
    const log = new QueryLog(filePath);
    await log.append({ target: '93.184.216.0/24', endpoint: 'rdap.arin.net', cacheStatus: 'miss' });
    await log.append({ target: '93.184.216.0/24', endpoint: 'rdap.arin.net', cacheStatus: 'hit' });

    const entries = log.readAll();
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ target: '93.184.216.0/24', cacheStatus: 'miss' });
    expect(Object.keys(entries[0]).sort()).toEqual(['cacheStatus', 'endpoint', 'target', 'timestamp']);
  });

  it('prune() removes entries older than the retention window', async () => {
    const log = new QueryLog(filePath);
    const old = new Date('2026-01-01T00:00:00.000Z');
    const recent = new Date('2026-08-20T00:00:00.000Z');
    const now = new Date('2026-08-27T00:00:00.000Z');

    // append() always stamps "now", so backdated fixture rows are written
    // directly to the NDJSON file rather than round-tripped through the
    // public API — this exercises prune()'s date-comparison logic in
    // isolation without contorting QueryLog's public interface for it.
    const rows = [
      { target: 'old.example', endpoint: 'e', cacheStatus: 'miss', timestamp: old.toISOString() },
      { target: 'recent.example', endpoint: 'e', cacheStatus: 'miss', timestamp: recent.toISOString() },
    ];
    writeFileSync(filePath, rows.map((r) => JSON.stringify(r)).join('\n') + '\n', { mode: 0o600 });

    await log.prune(30, now);
    const remaining = log.readAll();
    expect(remaining.some((e) => e.target === 'old.example')).toBe(false);
    expect(remaining.some((e) => e.target === 'recent.example')).toBe(true);
  });

  it('clear() empties the log', async () => {
    const log = new QueryLog(filePath);
    await log.append({ target: 'x', endpoint: 'e', cacheStatus: 'miss' });
    await log.clear();
    expect(log.readAll()).toHaveLength(0);
  });

  it('creates the file with 0600 permissions', async () => {
    const log = new QueryLog(filePath);
    await log.append({ target: 'x', endpoint: 'e', cacheStatus: 'miss' });
    if (process.platform !== 'win32') {
      const mode = statSync(filePath).mode & 0o777;
      expect(mode).toBe(0o600);
    }
  });

  // KAN-286: the client starts prune() without waiting for it, so a write
  // here outlives its caller, and clear() or append() can overlap it.
  const row = (target: string, timestamp = new Date().toISOString()) =>
    JSON.stringify({ target, endpoint: 'e', cacheStatus: 'miss', timestamp }) + '\n';
  const EXPIRED = '2020-01-01T00:00:00.000Z';

  it('prune() writes nothing when there is no log', async () => {
    await new QueryLog(filePath).prune(30);
    expect(readdirSync(dir)).toEqual([]);
  });

  it('prune() restores 0600 even when nothing has expired', async () => {
    if (process.platform === 'win32') return;
    writeFileSync(filePath, row('recent.example'));
    chmodSync(filePath, 0o644);
    await new QueryLog(filePath).prune(30);
    expect(statSync(filePath).mode & 0o777).toBe(0o600);
  });

  it('prune() restores a missing final newline, so the next append stays readable', async () => {
    writeFileSync(filePath, row('recent.example').trimEnd(), { mode: 0o600 });
    const log = new QueryLog(filePath);
    await log.prune(30);
    await log.append({ target: 'new.example', endpoint: 'e', cacheStatus: 'miss' });
    expect(log.readAll().map((e) => e.target)).toEqual(['recent.example', 'new.example']);
  });

  it('prune() replaces a symlink and leaves its target alone', async () => {
    if (process.platform === 'win32') return;
    const target = join(dir, 'elsewhere');
    const before = row('recent.example');
    writeFileSync(target, before);
    chmodSync(target, 0o644);
    symlinkSync(target, filePath);
    await new QueryLog(filePath).prune(30);
    expect(lstatSync(filePath).isFile()).toBe(true);
    expect(statSync(target).mode & 0o777).toBe(0o644);
    expect(readFileSync(target, 'utf8')).toBe(before);
    expect(readFileSync(filePath, 'utf8')).toBe(before);
  });

  it('prune() replaces a symlink whose target does not exist', async () => {
    if (process.platform === 'win32') return;
    symlinkSync(join(dir, 'missing'), filePath);
    await new QueryLog(filePath).prune(30);
    expect(lstatSync(filePath).isFile()).toBe(true);
    expect(readdirSync(dir)).toEqual(['query-log.ndjson']);
  });

  it('prune() detaches a hard-linked log', async () => {
    const other = join(dir, 'other');
    const before = row('recent.example');
    writeFileSync(filePath, before, { mode: 0o600 });
    linkSync(filePath, other);
    await new QueryLog(filePath).prune(30);
    expect(statSync(other).nlink).toBe(1);
    expect(readFileSync(other, 'utf8')).toBe(before);
    expect(readFileSync(filePath, 'utf8')).toBe(before);
  });

  it('stamps an entry when append() is called, not when its write runs', async () => {
    writeFileSync(filePath, row('old.example', EXPIRED));
    const log = new QueryLog(filePath);
    const called = new Date('2030-01-01T00:00:00.000Z');
    try {
      await duringPrune(log, () => {
        vi.useFakeTimers({ toFake: ['Date'], now: called });
        const write = log.append({ target: 'new.example', endpoint: 'e', cacheStatus: 'miss' });
        vi.setSystemTime('2030-01-01T01:00:00.000Z');
        return write;
      });
    } finally {
      vi.useRealTimers();
    }
    expect(log.readAll().map((e) => e.timestamp)).toEqual([called.toISOString()]);
  });

  // Holds prune() just before it replaces the file, so `during` runs at the
  // point where an unserialized write would be lost.
  const duringPrune = async (log: QueryLog, during: () => Promise<void>) => {
    const rename = fs.rename;
    let release = () => {};
    const held = new Promise<void>((resolve) => { release = resolve; });
    const spy = vi.spyOn(fs, 'rename').mockImplementationOnce(async (from, to) => {
      await held;
      await rename(from, to);
    });
    try {
      const pruned = log.prune(30);
      await vi.waitFor(() => expect(spy).toHaveBeenCalled());
      const write = during();
      await new Promise((r) => setTimeout(r, 30));
      release();
      await Promise.all([pruned, write]);
    } finally {
      release();
      spy.mockRestore();
    }
  };

  it('keeps an entry appended while prune() is running', async () => {
    writeFileSync(filePath, row('old.example', EXPIRED) + row('recent.example'));
    const log = new QueryLog(filePath);
    await duringPrune(log, () => log.append({ target: 'new.example', endpoint: 'e', cacheStatus: 'miss' }));
    expect(log.readAll().map((e) => e.target)).toEqual(['recent.example', 'new.example']);
  });

  it('clear() called while prune() is running leaves the log empty', async () => {
    writeFileSync(filePath, row('old.example', EXPIRED) + row('recent.example'));
    const log = new QueryLog(filePath);
    await duringPrune(log, () => log.clear());
    expect(readFileSync(filePath, 'utf8')).toBe('');
  });

  it('clear() called while append() is running leaves the log empty', async () => {
    const log = new QueryLog(filePath);
    const appended = log.append({ target: 'x', endpoint: 'e', cacheStatus: 'miss' });
    await log.clear();
    await appended;
    expect(readFileSync(filePath, 'utf8')).toBe('');
  });

  it('a failed write rejects and does not block the next one', async () => {
    mkdirSync(filePath);
    const log = new QueryLog(filePath);
    await expect(log.append({ target: 'x', endpoint: 'e', cacheStatus: 'miss' })).rejects.toThrow();
    rmSync(filePath, { recursive: true });
    await log.append({ target: 'y', endpoint: 'e', cacheStatus: 'miss' });
    expect(log.readAll().map((e) => e.target)).toEqual(['y']);
  });

  // KAN-316: an unreadable line has no usable timestamp, so keeping it would
  // mean keeping it forever; prune() drops it and carries on.
  const entry = (over: Record<string, unknown>) =>
    JSON.stringify({ target: 'odd.example', endpoint: 'e', cacheStatus: 'miss', timestamp: new Date().toISOString(), ...over }) + '\n';
  it.each([
    ['a torn line', '{"target":"odd.example","endp\n'],
    ['two joined entries', entry({}).trimEnd() + entry({})],
    ['NUL bytes', '\u0000\u0000\n'],
    ['a bare null', 'null\n'],
    ['a bare number', '5\n'],
    ['an array', '[]\n'],
    ['a missing timestamp', entry({ timestamp: undefined })],
    ['an unreadable timestamp', entry({ timestamp: 'nope' })],
    ['a null timestamp', entry({ timestamp: null })],
    ['a boolean timestamp', entry({ timestamp: true })],
  ])('prune() drops %s, counts it, and still prunes and repairs the rest', async (_name, bad) => {
    writeFileSync(filePath, row('old.example', EXPIRED) + bad + row('recent.example'));
    chmodSync(filePath, 0o644);
    const log = new QueryLog(filePath);
    expect(log.readAll().map((e) => e.target)).toEqual(['old.example', 'recent.example']);
    expect(await log.prune(30)).toBe(1);
    expect(readFileSync(filePath, 'utf8').split('\n').map((l) => l && JSON.parse(l).target)).toEqual(['recent.example', '']);
    if (process.platform !== 'win32') expect(statSync(filePath).mode & 0o777).toBe(0o600);
  });

  // A line with a date can expire normally, so nothing else about it matters.
  it.each([
    ['a missing target', { target: undefined }],
    ['a non-string endpoint', { endpoint: 1 }],
    ['an unknown cache status', { cacheStatus: 'odd' }],
    ['an extra field', { extra: 'kept' }],
    ['a numeric timestamp', { timestamp: Date.now() }],
  ])('prune() keeps a dated line with %s until it expires', async (_name, over) => {
    writeFileSync(filePath, entry(over));
    const log = new QueryLog(filePath);
    expect(await log.prune(30)).toBe(0);
    expect(readFileSync(filePath, 'utf8')).toBe(entry({ timestamp: JSON.parse(readFileSync(filePath, 'utf8')).timestamp, ...over }));
    expect(await log.prune(30, new Date(Date.now() + 31 * 24 * 60 * 60 * 1000))).toBe(0);
    expect(readFileSync(filePath, 'utf8')).toBe('');
  });

  it('prune() drops a torn last line, so the next append stays readable', async () => {
    writeFileSync(filePath, row('recent.example') + '{"target":"odd.exa');
    const log = new QueryLog(filePath);
    expect(await log.prune(30)).toBe(1);
    await log.append({ target: 'new.example', endpoint: 'e', cacheStatus: 'hit' });
    expect(log.readAll().map((e) => e.target)).toEqual(['recent.example', 'new.example']);
  });

  it('prune() keeps a first entry behind a byte order mark', async () => {
    writeFileSync(filePath, '\uFEFF' + row('recent.example'));
    const log = new QueryLog(filePath);
    expect(await log.prune(30)).toBe(0);
    expect(readFileSync(filePath, 'utf8')).toMatch(/^\{"target":"recent\.example"/);
  });

  it('prune() counts only unreadable lines, not expired or blank ones', async () => {
    const log = new QueryLog(filePath);
    expect(await log.prune(30)).toBe(0);
    writeFileSync(filePath, row('old.example', EXPIRED) + '\n \n' + row('recent.example'));
    expect(await log.prune(30)).toBe(0);
  });
});
