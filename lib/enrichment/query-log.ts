// lib/enrichment/query-log.ts
//
// Outbound query audit log: one NDJSON line per lookup attempt (cache hit or
// miss), per the enrichment spec's egress hygiene requirement that "outbound
// queries are logged ... never full response bodies" — entries carry only
// the target, the endpoint queried, and hit/miss status.
import { promises as fs, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { QueryLogEntry } from './types';

export class QueryLog {
  private tail: Promise<void> = Promise.resolve();

  constructor(private filePath: string) {}

  // Writes run one at a time, in call order: prune() replaces the whole file
  // with what it read, so an append() or clear() overlapping it would be
  // undone (KAN-286). A failed write rejects for its own caller only.
  private serialize(write: () => Promise<void>): Promise<void> {
    const result = this.tail.then(write);
    this.tail = result.catch(() => {});
    return result;
  }

  append(entry: { target: string; endpoint: string; cacheStatus: 'hit' | 'miss' }): Promise<void> {
    return this.serialize(() => this.appendNow(entry));
  }

  prune(retentionDays: number, now: Date = new Date()): Promise<void> {
    return this.serialize(() => this.pruneNow(retentionDays, now));
  }

  clear(): Promise<void> {
    return this.serialize(() => this.clearNow());
  }

  private async appendNow(entry: { target: string; endpoint: string; cacheStatus: 'hit' | 'miss' }): Promise<void> {
    mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
    const line: QueryLogEntry = {
      target: entry.target,
      endpoint: entry.endpoint,
      cacheStatus: entry.cacheStatus,
      timestamp: new Date().toISOString(),
    };
    const isNew = !existsSync(this.filePath);
    await fs.appendFile(this.filePath, JSON.stringify(line) + '\n', { mode: 0o600 });
    // Belt-and-suspenders: appendFile's `mode` option only applies when it
    // creates the file, and even then isn't honored on every platform/umask
    // combination, so force the permission explicitly for a freshly created
    // file rather than trusting the option alone.
    if (isNew) await fs.chmod(this.filePath, 0o600);
  }

  readAll(): QueryLogEntry[] {
    if (!existsSync(this.filePath)) return [];
    const raw = readFileSync(this.filePath, 'utf8');
    return raw
      .split('\n')
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l) as QueryLogEntry);
  }

  private async pruneNow(retentionDays: number, now: Date): Promise<void> {
    if (!existsSync(this.filePath)) return;
    const cutoff = now.getTime() - retentionDays * 24 * 60 * 60 * 1000;
    const entries = this.readAll();
    const kept = entries.filter((e) => new Date(e.timestamp).getTime() >= cutoff);
    if (kept.length === entries.length) {
      // Nothing to remove, so no rewrite; still force the permission the
      // rewrite below would have given the file.
      await fs.chmod(this.filePath, 0o600);
      return;
    }
    // Rewritten via temp-file-then-rename for the same atomic-replace
    // guarantee as EnrichmentCache.persist() (Task 2's atomicWriteJson) —
    // not reused verbatim because this file is NDJSON, one entry per line,
    // not a single JSON document.
    const tmpPath = `${this.filePath}.tmp-${randomBytes(6).toString('hex')}`;
    const body = kept.map((e) => JSON.stringify(e)).join('\n') + (kept.length ? '\n' : '');
    await fs.writeFile(tmpPath, body, { mode: 0o600 });
    await fs.rename(tmpPath, this.filePath);
  }

  private async clearNow(): Promise<void> {
    mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
    await fs.writeFile(this.filePath, '', { mode: 0o600 });
  }
}
