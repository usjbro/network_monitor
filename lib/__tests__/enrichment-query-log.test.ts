// lib/__tests__/enrichment-query-log.test.ts
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
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
});
