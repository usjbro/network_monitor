// lib/__tests__/enrichment-query-log.test.ts
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { promises as fs, chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
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

  it('prune() does not rewrite a log with nothing to remove', async () => {
    writeFileSync(filePath, row('recent.example'), { mode: 0o600 });
    const before = statSync(filePath).ino;
    await new QueryLog(filePath).prune(30);
    expect(statSync(filePath).ino).toBe(before);
    expect(readFileSync(filePath, 'utf8')).toContain('recent.example');
  });

  it('prune() restores 0600 on a log it does not rewrite', async () => {
    if (process.platform === 'win32') return;
    writeFileSync(filePath, row('recent.example'));
    chmodSync(filePath, 0o644);
    await new QueryLog(filePath).prune(30);
    expect(statSync(filePath).mode & 0o777).toBe(0o600);
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
});
