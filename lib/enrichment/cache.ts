// lib/enrichment/cache.ts
import { atomicWriteJson, removeTempFiles, SerialWrites } from './fs-util';
import { cidrContains } from './scope-filter';
import { CacheEntry, EnrichmentRecord } from './types';

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
  private writes = new SerialWrites();

  constructor(private filePath: string) {}

  load(): void {
    const file = readJsonIfExists<CacheFile>(this.filePath);
    this.entries = new Map((file?.entries ?? []).map((e) => [e.key, e]));
  }

  // Writes run one at a time, each saving the entries as they are when it
  // runs, so a write that began before clear() cannot land after it and
  // restore what clear() removed (KAN-317).
  private persist(): Promise<void> {
    return this.writes.run(() => atomicWriteJson(this.filePath, { entries: [...this.entries.values()] } satisfies CacheFile));
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
    return this.writes.run(async () => {
      await atomicWriteJson(this.filePath, { entries: [] } satisfies CacheFile);
      await removeTempFiles(this.filePath);
    });
  }
}
