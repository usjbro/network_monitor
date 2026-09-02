// lib/enrichment/cache.ts
import { promises as fs, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { cidrContains } from './scope-filter';
import { CacheEntry, EnrichmentRecord } from './types';

export async function atomicWriteJson(filePath: string, data: unknown): Promise<void> {
  mkdirSync(dirname(filePath), { recursive: true, mode: 0o700 });
  const tmpPath = `${filePath}.tmp-${randomBytes(6).toString('hex')}`;
  await fs.writeFile(tmpPath, JSON.stringify(data), { mode: 0o600 });
  await fs.rename(tmpPath, filePath); // atomic on the same filesystem — no partial-write window on `filePath`
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

  constructor(private filePath: string) {}

  load(): void {
    const file = readJsonIfExists<CacheFile>(this.filePath);
    this.entries = new Map((file?.entries ?? []).map((e) => [e.key, e]));
  }

  private async persist(): Promise<void> {
    await atomicWriteJson(this.filePath, { entries: [...this.entries.values()] } satisfies CacheFile);
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

  async clear(): Promise<void> {
    this.entries.clear();
    await this.persist();
  }
}
