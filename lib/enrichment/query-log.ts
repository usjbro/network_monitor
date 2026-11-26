// lib/enrichment/query-log.ts
//
// Outbound query audit log: one NDJSON line per lookup attempt (cache hit or
// miss), per the enrichment spec's egress hygiene requirement that "outbound
// queries are logged ... never full response bodies" — entries carry only
// the target, the endpoint queried, and hit/miss status.
import { promises as fs, existsSync, lstatSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { removeTempFiles, tempPathFor } from './cache';
import { QueryLogEntry } from './types';

type QueryLogInput = Omit<QueryLogEntry, 'timestamp'>;

const READ_CHUNK_BYTES = 64 * 1024;

// Null when the line has no readable date and so could never expire. Nothing
// else is checked: a dated line is kept until it expires, whatever it holds.
function parseEntry(line: string): QueryLogEntry | null {
  let value: { timestamp?: unknown } | null;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  const timestamp = value?.timestamp;
  if (typeof timestamp !== 'string' && typeof timestamp !== 'number') return null;
  return Number.isNaN(new Date(timestamp).getTime()) ? null : (value as QueryLogEntry);
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
    const handle = await fs.open(this.filePath, 'a+', 0o600);
    try {
      // After a cut-off write the file ends mid-line; joining that line would
      // lose this entry along with it (KAN-320).
      const { size } = await handle.stat();
      const last = Buffer.alloc(1);
      if (size > 0) await handle.read(last, 0, 1, size - 1);
      const separator = size > 0 && last[0] !== 0x0a ? '\n' : '';
      await handle.appendFile(separator + JSON.stringify(line) + '\n');
    } finally {
      await handle.close();
    }
    // Belt-and-suspenders: open's `mode` argument only applies when it
    // creates the file, and even then isn't honored on every platform/umask
    // combination, so force the permission explicitly for a freshly created
    // file rather than trusting the option alone.
    if (isNew) await fs.chmod(this.filePath, 0o600);
  }

  /** Every dated entry; unreadable lines are skipped. */
  readAll(): QueryLogEntry[] {
    if (!existsSync(this.filePath)) return [];
    return readFileSync(this.filePath, 'utf8')
      .split('\n')
      .map((l) => parseEntry(l.trim()))
      .filter((e) => e !== null);
  }

  // Batches of complete lines, one read at a time, so a large log neither
  // blocks the server nor sits in memory. A symlink to nothing has no lines.
  private async *readLines(): AsyncGenerator<string[]> {
    if (!existsSync(this.filePath)) return;
    const handle = await fs.open(this.filePath, 'r');
    try {
      const buffer = Buffer.alloc(READ_CHUNK_BYTES);
      const decoder = new StringDecoder('utf8');
      let partial: string[] = [];
      for (;;) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
        if (bytesRead === 0) break;
        const lines = decoder.write(buffer.subarray(0, bytesRead)).split('\n');
        // Joined only once complete: re-splitting a long line on every read
        // would take time quadratic in its length.
        partial.push(lines[0]);
        if (lines.length === 1) continue;
        lines[0] = partial.join('');
        partial = [lines.pop()!];
        yield lines;
      }
      partial.push(decoder.end());
      yield [partial.join('')];
    } finally {
      await handle.close();
    }
  }

  private async pruneNow(retentionDays: number, now: Date): Promise<number> {
    // No log, nothing to write. A readable log is always rewritten, which
    // also restores its newline, 0600 and ownership and detaches links.
    // lstat, not existsSync: a symlink to nothing is still there to replace.
    if (!lstatSync(this.filePath, { throwIfNoEntry: false })) return 0;
    const cutoff = now.getTime() - retentionDays * 24 * 60 * 60 * 1000;
    // Rewritten via temp-file-then-rename for the same atomic-replace
    // guarantee as EnrichmentCache.persist() (Task 2's atomicWriteJson) —
    // not reused verbatim because this file is NDJSON, one entry per line,
    // not a single JSON document.
    const tmpPath = tempPathFor(this.filePath);
    let unreadable = 0;
    try {
      const out = await fs.open(tmpPath, 'wx', 0o600);
      try {
        for await (const lines of this.readLines()) {
          let kept = '';
          for (const raw of lines) {
            const line = raw.trim();
            if (line.length === 0) continue;
            const entry = parseEntry(line);
            if (!entry) unreadable += 1;
            else if (new Date(entry.timestamp).getTime() >= cutoff) kept += JSON.stringify(entry) + '\n';
          }
          if (kept) await out.appendFile(kept);
        }
        await out.sync();
      } finally {
        await out.close();
      }
      await fs.rename(tmpPath, this.filePath);
    } catch (err) {
      await fs.rm(tmpPath, { force: true }).catch(() => {});
      throw err;
    }
    return unreadable;
  }

  private async clearNow(): Promise<void> {
    mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
    await fs.writeFile(this.filePath, '', { mode: 0o600 });
    await removeTempFiles(this.filePath);
  }
}
