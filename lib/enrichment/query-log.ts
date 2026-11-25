// lib/enrichment/query-log.ts
//
// Outbound query audit log: one NDJSON line per lookup attempt (cache hit or
// miss), per the enrichment spec's egress hygiene requirement that "outbound
// queries are logged ... never full response bodies" — entries carry only
// the target, the endpoint queried, and hit/miss status.
import { promises as fs, existsSync, lstatSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { QueryLogEntry } from './types';

type QueryLogInput = Omit<QueryLogEntry, 'timestamp'>;

// An entry, or null when the line is not one. Without a readable timestamp a
// line could never expire.
function parseEntry(line: string): QueryLogEntry | null {
  let value: Partial<QueryLogEntry> | null;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (typeof value?.target !== 'string' || typeof value.endpoint !== 'string') return null;
  if (value.cacheStatus !== 'hit' && value.cacheStatus !== 'miss') return null;
  if (typeof value.timestamp !== 'string' || Number.isNaN(Date.parse(value.timestamp))) return null;
  return value as QueryLogEntry;
}

export class QueryLog {
  private tail: Promise<void> = Promise.resolve();

  constructor(private filePath: string) {}

  // Writes run one at a time, in call order: prune() replaces the whole file
  // with what it read, so an append() or clear() overlapping it would be
  // undone (KAN-286). A failed write rejects for its own caller only.
  private serialize<T>(write: () => Promise<T>): Promise<T> {
    const result = this.tail.then(write);
    this.tail = result.then(() => {}, () => {});
    return result;
  }

  append(entry: QueryLogInput): Promise<void> {
    const timestamp = new Date().toISOString();
    return this.serialize(() => this.appendNow(entry, timestamp));
  }

  /** Resolves with how many unreadable lines it dropped (KAN-316). */
  prune(retentionDays: number, now: Date = new Date()): Promise<number> {
    return this.serialize(() => this.pruneNow(retentionDays, now));
  }

  clear(): Promise<void> {
    return this.serialize(() => this.clearNow());
  }

  private async appendNow(entry: QueryLogInput, timestamp: string): Promise<void> {
    mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
    const line: QueryLogEntry = {
      target: entry.target,
      endpoint: entry.endpoint,
      cacheStatus: entry.cacheStatus,
      timestamp,
    };
    const isNew = !existsSync(this.filePath);
    await fs.appendFile(this.filePath, JSON.stringify(line) + '\n', { mode: 0o600 });
    // Belt-and-suspenders: appendFile's `mode` option only applies when it
    // creates the file, and even then isn't honored on every platform/umask
    // combination, so force the permission explicitly for a freshly created
    // file rather than trusting the option alone.
    if (isNew) await fs.chmod(this.filePath, 0o600);
  }

  /** Every readable entry; unreadable lines are skipped. */
  readAll(): QueryLogEntry[] {
    return this.read().entries;
  }

  private read(): { entries: QueryLogEntry[]; unreadable: number } {
    if (!existsSync(this.filePath)) return { entries: [], unreadable: 0 };
    const raw = readFileSync(this.filePath, 'utf8');
    const parsed = raw
      .split('\n')
      .filter((l) => l.trim().length > 0)
      .map(parseEntry);
    const entries = parsed.filter((e) => e !== null);
    return { entries, unreadable: parsed.length - entries.length };
  }

  private async pruneNow(retentionDays: number, now: Date): Promise<number> {
    // No log, nothing to write. A readable log is always rewritten, which
    // also restores its newline, 0600 and ownership and detaches links.
    // lstat, not existsSync: a symlink to nothing is still there to replace.
    if (!lstatSync(this.filePath, { throwIfNoEntry: false })) return 0;
    const cutoff = now.getTime() - retentionDays * 24 * 60 * 60 * 1000;
    const { entries, unreadable } = this.read();
    const kept = entries.filter((e) => new Date(e.timestamp).getTime() >= cutoff);
    const body = kept.map((e) => JSON.stringify(e) + '\n').join('');
    // Rewritten via temp-file-then-rename for the same atomic-replace
    // guarantee as EnrichmentCache.persist() (Task 2's atomicWriteJson) —
    // not reused verbatim because this file is NDJSON, one entry per line,
    // not a single JSON document.
    const tmpPath = `${this.filePath}.tmp-${randomBytes(6).toString('hex')}`;
    await fs.writeFile(tmpPath, body, { mode: 0o600 });
    await fs.rename(tmpPath, this.filePath);
    return unreadable;
  }

  private async clearNow(): Promise<void> {
    mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
    await fs.writeFile(this.filePath, '', { mode: 0o600 });
  }
}
