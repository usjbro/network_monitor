// lib/enrichment/cache.ts
import { promises as fs, mkdirSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { cidrContains } from './scope-filter';
import { CacheEntry, EnrichmentRecord } from './types';

const TEMP_SUFFIX = /^\.tmp-[0-9a-f]{12}$/;

// The temp file a rewrite of `filePath` goes through; removeTempFiles finds
// what a crash leaves of these.
export function tempPathFor(filePath: string): string {
  return `${filePath}.tmp-${randomBytes(6).toString('hex')}`;
}

export async function atomicWriteJson(filePath: string, data: unknown): Promise<void> {
  mkdirSync(dirname(filePath), { recursive: true, mode: 0o700 });
  const tmpPath = tempPathFor(filePath);
  try {
    await fs.writeFile(tmpPath, JSON.stringify(data), { mode: 0o600 });
    await fs.rename(tmpPath, filePath); // atomic on the same filesystem — no partial-write window on `filePath`
  } catch (err) {
    await fs.rm(tmpPath, { force: true }).catch(() => {});
    throw err;
  }
}

// Removes temp files a crash left for `filePath` (KAN-317).
export async function removeTempFiles(filePath: string): Promise<void> {
  const base = basename(filePath);
  let names: string[];
  try {
    names = await fs.readdir(dirname(filePath));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw err;
  }
  for (const name of names) {
    if (name.startsWith(base) && TEMP_SUFFIX.test(name.slice(base.length))) {
      await fs.rm(join(dirname(filePath), name), { force: true });
    }
  }
}

export function readJsonIfExists<T>(filePath: string): T | undefined {
  try {
    // Synchronous on purpose: load() runs once at EnrichmentClient
    // construction, not on any request-serving path.
    const raw = require('node:fs').readFileSync(filePath, 'utf8');
    return JSON.parse(raw) as T;
  } catch {
    // Missing or corrupt file is a full cache miss, not a crash (spec's
    // Error handling & lifecycle: "Cache ... corruption/unreadable ...
    // treated as a full cache miss ... not a crash").
    return undefined;
  }
}

interface CacheFile {
  entries: CacheEntry[];
}

export class EnrichmentCache {
  private entries = new Map<string, CacheEntry>();
  private tail: Promise<void> = Promise.resolve();

  constructor(private filePath: string) {}

  load(): void {
    const file = readJsonIfExists<CacheFile>(this.filePath);
    this.entries = new Map((file?.entries ?? []).map((e) => [e.key, e]));
  }

  // Writes run one at a time, each saving the entries as they are when it
  // runs, so a write that began before clear() cannot land after it and
  // restore what clear() removed (KAN-317). A failed write rejects for its
  // own caller only.
  private serialize(write: () => Promise<void>): Promise<void> {
    const result = this.tail.then(write);
    this.tail = result.then(() => {}, () => {});
    return result;
  }

  private persist(): Promise<void> {
    return this.serialize(() => atomicWriteJson(this.filePath, { entries: [...this.entries.values()] } satisfies CacheFile));
  }

  getForIp(ip: string): CacheEntry | undefined {
    for (const entry of this.entries.values()) {
      if (entry.key.includes('/') && cidrContains(entry.key, ip)) return entry;
    }
    return undefined;
  }

  getForDomain(domain: string): CacheEntry | undefined {
    return this.entries.get(domain);
  }

  isFresh(entry: CacheEntry, now: number = Date.now()): boolean {
    return now < entry.expiresAt;
  }

  async setSuccess(key: string, record: EnrichmentRecord, ttlMs: number): Promise<void> {
    this.entries.set(key, { key, record, expiresAt: Date.now() + ttlMs });
    await this.persist();
  }

  async setNegative(key: string, ttlMs: number): Promise<void> {
    this.entries.set(key, { key, record: null, expiresAt: Date.now() + ttlMs });
    await this.persist();
  }

  clear(): Promise<void> {
    this.entries.clear();
    return this.serialize(async () => {
      await atomicWriteJson(this.filePath, { entries: [] } satisfies CacheFile);
      await removeTempFiles(this.filePath);
    });
  }
}
