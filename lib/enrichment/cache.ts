// lib/enrichment/cache.ts
import { readFileSync } from 'node:fs';
import { atomicWriteJson, removeTempFiles, SerialWrites } from './fs-util';
import { cidrContains, MIN_CIDR_PREFIX_LEN } from './scope-filter';
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
  /** Log prefix for what load() ignores. */
  label: string;
  /** Checks a stored record's fields; a record that fails is unreadable. */
  isRecord: (record: object) => boolean;
  /** A loaded entry is fresh for at most this long. */
  ttlMs: number;
  /** A loaded negative (null) entry is fresh for at most this long. Without
   *  it, a negative entry is unreadable. */
  negativeTtlMs?: number;
}

// The same limit asString (lib/enrichment-mapping.ts) puts on what is saved.
const MAX_TEXT_LENGTH = 4096;

/** True for a record field that is absent or a string of a sane length. */
export function isOptionalText(value: unknown): boolean {
  return value === undefined || (typeof value === 'string' && value.length < MAX_TEXT_LENGTH);
}

/** True when `record` has no field outside `allowed`. */
export function hasOnlyFields(record: object, allowed: readonly string[]): boolean {
  return Object.keys(record).every((name) => allowed.includes(name));
}

const RECORD_TEXT_FIELDS = ['org', 'asn', 'asnOrg', 'country', 'registrant'] as const;
const RECORD_FIELDS = [...RECORD_TEXT_FIELDS, 'source', 'fetchedAt'];

/** True for a stored record of the shape EnrichmentRecord describes. */
export function isEnrichmentRecord(record: object): boolean {
  const fields = record as Record<string, unknown>;
  return (
    hasOnlyFields(record, RECORD_FIELDS) &&
    RECORD_TEXT_FIELDS.every((name) => isOptionalText(fields[name])) &&
    (fields.source === 'rdap' || fields.source === 'whois' || fields.source === 'cache') &&
    typeof fields.fetchedAt === 'string' &&
    isOptionalText(fields.fetchedAt)
  );
}

// A domain, or a CIDR block no wider than MIN_CIDR_PREFIX_LEN: a wider one
// would answer for much of the internet.
function isUsableKey(key: unknown): key is string {
  if (typeof key !== 'string' || key.length === 0 || !isOptionalText(key)) return false;
  const slash = key.indexOf('/');
  if (slash < 0) return true;
  const bits = Number(key.slice(slash + 1));
  return Number.isInteger(bits) && bits >= MIN_CIDR_PREFIX_LEN && bits <= 128;
}

function isCacheEntry(value: unknown, opts: CacheOptions): value is CacheEntry {
  if (typeof value !== 'object' || value === null) return false;
  const { key, record, expiresAt } = value as Partial<CacheEntry>;
  const recordOk =
    record === null
      ? opts.negativeTtlMs !== undefined
      : typeof record === 'object' && !Array.isArray(record) && opts.isRecord(record);
  return isUsableKey(key) && Number.isFinite(expiresAt) && recordOk;
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

  constructor(private filePath: string, private opts: CacheOptions) {}

  /** Resolves once no cache-file write is queued. */
  drained(): Promise<void> {
    return this.writes.drained();
  }

  // A file or entry that can't be read or has the wrong shape is a cache
  // miss, not a crash, and is reported by count only (KAN-322).
  load(): CacheLoadReport {
    const report = this.loadEntries();
    const ignored = describeCacheLoad(report);
    if (ignored) console.error(`[${this.opts.label}] ${ignored}`);
    return report;
  }

  private loadEntries(): CacheLoadReport {
    this.entries = new Map();
    const file = readCacheFile(this.filePath);
    if (file?.missing) return { file: false, entries: 0 };
    const entries = (file?.value as { entries?: unknown } | null | undefined)?.entries;
    if (!Array.isArray(entries)) return { file: true, entries: 0 };
    const now = Date.now();
    let unreadable = 0;
    for (const entry of entries) {
      if (!isCacheEntry(entry, this.opts)) {
        unreadable += 1;
        continue;
      }
      const ttlMs = entry.record === null ? this.opts.negativeTtlMs! : this.opts.ttlMs;
      this.entries.set(entry.key, { ...entry, expiresAt: Math.min(entry.expiresAt, now + ttlMs) });
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
