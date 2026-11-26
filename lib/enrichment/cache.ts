// lib/enrichment/cache.ts
import { readFileSync } from 'node:fs';
import { atomicWriteJson, removeTempFiles, SerialWrites } from './fs-util';
import { cidrContains } from './scope-filter';
import { CacheEntry, EnrichmentRecord } from './types';

export function readJsonIfExists<T>(filePath: string): T | undefined {
  try {
    // Synchronous on purpose: callers read once at startup, not on a
    // request-serving path.
    const raw = readFileSync(filePath, 'utf8');
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

/** What load() could not use: the whole file, or some of its entries. */
export interface CacheLoadReport {
  file: boolean;
  entries: number;
}

export interface CacheOptions {
  /** Log prefix for what load() ignores; without one nothing is logged. */
  label?: string;
  /** Checks a stored record's fields; a record that fails is unreadable. */
  isRecord?: (record: object) => boolean;
  /** An entry loaded with a later expiry is cut back to now plus this. */
  maxTtlMs?: number;
}

const RECORD_TEXT_FIELDS = ['org', 'asn', 'asnOrg', 'country', 'registrant'] as const;

/** True for a stored record of the shape EnrichmentRecord describes. */
export function isEnrichmentRecord(record: object): boolean {
  const fields = record as Record<string, unknown>;
  return (
    RECORD_TEXT_FIELDS.every((name) => fields[name] === undefined || typeof fields[name] === 'string') &&
    (fields.source === 'rdap' || fields.source === 'whois' || fields.source === 'cache') &&
    typeof fields.fetchedAt === 'string'
  );
}

function isCacheEntry(value: unknown, isRecord: (record: object) => boolean): value is CacheEntry {
  if (typeof value !== 'object' || value === null) return false;
  const { key, record, expiresAt } = value as Partial<CacheEntry>;
  const recordOk = record === null || (typeof record === 'object' && !Array.isArray(record) && isRecord(record));
  return typeof key === 'string' && Number.isFinite(expiresAt) && recordOk;
}

function readCacheFile(filePath: string): { missing: true } | { missing: false; value: unknown } | null {
  let raw: string;
  try {
    raw = readFileSync(filePath, 'utf8');
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'ENOENT' ? { missing: true } : null;
  }
  try {
    return { missing: false, value: JSON.parse(raw) };
  } catch {
    return null;
  }
}

/** A log line for a load report, naming no entry; null when nothing was ignored. */
export function describeCacheLoad(report: CacheLoadReport): string | null {
  if (report.file) return 'ignored the unreadable cache file';
  if (report.entries === 0) return null;
  return `ignored ${report.entries} unreadable cache ${report.entries === 1 ? 'entry' : 'entries'}`;
}

export class EnrichmentCache {
  private entries = new Map<string, CacheEntry>();
  private writes = new SerialWrites();

  constructor(private filePath: string, private opts: CacheOptions = {}) {}

  // A file or entry that can't be read or has the wrong shape is a cache
  // miss, not a crash, and is reported by count only (KAN-322).
  load(): CacheLoadReport {
    const report = this.loadEntries();
    const ignored = describeCacheLoad(report);
    if (ignored && this.opts.label) console.error(`[${this.opts.label}] ${ignored}`);
    return report;
  }

  private loadEntries(): CacheLoadReport {
    this.entries = new Map();
    const file = readCacheFile(this.filePath);
    if (file?.missing) return { file: false, entries: 0 };
    const entries = (file?.value as { entries?: unknown } | null | undefined)?.entries;
    if (!Array.isArray(entries)) return { file: true, entries: 0 };
    const isRecord = this.opts.isRecord ?? (() => true);
    const latest = this.opts.maxTtlMs === undefined ? Infinity : Date.now() + this.opts.maxTtlMs;
    let unreadable = 0;
    for (const entry of entries) {
      if (isCacheEntry(entry, isRecord)) this.entries.set(entry.key, { ...entry, expiresAt: Math.min(entry.expiresAt, latest) });
      else unreadable += 1;
    }
    return { file: false, entries: unreadable };
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
