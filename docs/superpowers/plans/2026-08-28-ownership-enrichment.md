# Ownership Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `ConnectionsView` an opt-in "Ownership" section per connection — org, ASN/ASN-holder, country from RDAP, and (extended tier) domain registrant from reverse-DNS + domain RDAP/WHOIS — without turning this app's first outbound network dependency into a default, unbounded, or unaudited one.

**Architecture:** All new code lives in the already-unprivileged Next.js relay, gated behind a runtime-only (never persisted), default-off opt-in. A new `EnrichmentClient` singleton (mirroring `AgentClient`'s shape) filters out private/reserved IPs, checks a disk-persisted CIDR/domain-keyed TTL cache, and — only on a cache miss, with the user's opt-in active — queues a rate-limited, jittered, SSRF-hardened RDAP (and, extended tier, WHOIS/reverse-DNS) lookup. Results flow to the browser as a new `connection_enrichment` SSE event on the *existing* `/api/stream` connection. The Rust capture agent and `docs/wire-protocol.md` are untouched — this whole feature is relay+browser only. See the spec's architecture diagram for the full picture.

**Tech Stack:** TypeScript/Node only — Next.js Route Handlers, built-in `fetch`/`net`/`dns`/`fs` (zero new production npm dependencies, per the spec's dependency-hygiene section), Vitest for tests (already in the tree).

**Spec:** `docs/superpowers/specs/2026-08-28-ownership-enrichment-design.md` — read it before starting; this plan assumes familiarity with its Components §1–§8 and Security model table. Concrete numbers used throughout this plan (TTLs, timeouts, backoff schedule, rate ceiling) are restated here for convenience but the spec is the source of truth if they ever drift.

## Global Constraints

- **Core tier ships first and must be independently mergeable and useful on its own** — Tasks 1–11 below. Extended tier (reverse-DNS + domain registrant + WHOIS fallback) is Tasks 12–15, additive on top, per the spec's phase-boundary rationale. Both tiers are in this plan's scope; extended tier is not deferred to a follow-up plan.
- **No live network calls in any test, anywhere in this plan.** Every RDAP/WHOIS/bootstrap/reverse-DNS test uses an injected fetch implementation, a local `net.createServer` fixture, a mocked `node:dns`, or a static JSON/text fixture — the same posture `capture-agent/src/parse.rs`'s tests take toward fixture byte sequences instead of live pcap, and `lib/__tests__/agent-client.test.ts` already takes toward a local `net.createServer` instead of a real capture agent.
- **Enrichment is default-off, runtime-only, and never persisted across a relay restart.** No task in this plan writes an "enabled" flag to disk anywhere. Every module below other than the cache/query-log files themselves is memory-only state on the `EnrichmentClient` singleton.
- **All new modules assume a single relay process**, matching the cache's single-writer design decision in the spec (Components §2). Don't add file-locking complexity to work around multi-process concurrency — that's explicitly out of scope until/unless `next start` ever runs multiple workers.
- **Concrete numbers used throughout** (restated from spec Components §5 and §2 so each task can cite them without cross-referencing): cache TTL 14 days (negative-cache TTL 1 hour); query-log retention 30 days; concurrency 1 in-flight request; jitter 3–10s redrawn per request; 429 backoff starts at 30s, doubles, caps at 30 minutes (or `Retry-After` if larger); circuit breaker trips after 3 consecutive 429s from one registry within a 10-minute window, cooldown 1 hour; request timeout 10s; response size caps 256KB (RDAP) / 64KB (WHOIS); WHOIS allowlist capped at 5 entries.
- **Data directory:** all new on-disk state lives under `.data/enrichment/` at the repo root (created with `{ recursive: true, mode: 0o700 }`; add `.data/` to `.gitignore` in Task 2, the first task that creates it). This is new — there is no existing app data directory convention to reuse.
- **Field names on the new `connection_enrichment` SSE event are flat `camelCase`**, matching `connection_update`/`layer_update`'s existing convention exactly (spec Components §6) — no second JSON shape convention on this transport.
- Exact `fetch`/`AbortController`/Web Streams API calls should be checked against the installed Node version (`node --version`) if a step's code doesn't compile/run as written — this plan was written assuming Node 20+'s built-in `fetch` and standard `ReadableStream` reader semantics; the TDD steps (`npx vitest run`) are how any drift gets caught, same as the Rust plan's `cargo build`/`cargo test` note about `pcap`/`etherparse`.

---

## File Structure

**New — `lib/enrichment/` (core tier unless marked extended):**
- `lib/enrichment/types.ts` — `EnrichmentRecord`, `CacheEntry`, `QueryLogEntry` shared types
- `lib/enrichment/scope-filter.ts` — RFC1918/loopback/link-local/CGNAT/multicast filter; also exports the CIDR-math helpers (`ipToInt`, `cidrContains`) reused by `bootstrap.ts` and `cache.ts`
- `lib/enrichment/cache.ts` — disk-persisted CIDR/domain-keyed TTL cache, atomic write; also exports `atomicWriteJson`/`readJsonIfExists` reused by `bootstrap.ts`
- `lib/enrichment/query-log.ts` — outbound query audit log (§8)
- `lib/enrichment/request-queue.ts` — concurrency=1, jittered (3–10s) FIFO queue
- `lib/enrichment/bootstrap.ts` — IANA RDAP bootstrap fetch/cache/routing (IP in core tier; domain/TLD matching added in Task 13)
- `lib/enrichment/rdap-client.ts` — hardened RDAP HTTP fetch: `redirect:'manual'`, 10s timeout, 256KB cap, 429 backoff, per-registry circuit breaker
- `lib/enrichment/referral-allowlist.ts` — **extended tier (Task 13)** — registrar RDAP referral host allowlist
- `lib/enrichment/whois-client.ts` — **extended tier (Task 14)** — port-43 WHOIS client via `net`, small allowlist, 64KB cap
- `lib/enrichment/reverse-dns.ts` — **extended tier (Task 12)** — `dns.promises.reverse()` wrapper with timeout
- `lib/enrichment.ts` — `EnrichmentClient` singleton (opt-in gate, orchestration, single-flight, disclosure text)

**New — mapping/types/docs/UI:**
- Create: `lib/enrichment-mapping.ts` — untrusted RDAP/WHOIS response → `EnrichmentRecord`; wire-event builder; connection-array merge helper
- Modify: `lib/types.ts` — add optional `enrichment` field to `NetworkConnection`
- Create: `docs/enrichment-protocol.md` — the relay↔browser `connection_enrichment` contract (mirrors `docs/wire-protocol.md`'s format, scoped to this new boundary)
- Modify: `app/api/stream/route.ts` — also relay `EnrichmentClient` 'result' events as SSE
- Create: `app/api/enrichment/control/route.ts` — POST `enable`/`enable_background`/`disable`/`disable_background`/`clear`
- Create: `app/api/enrichment/lookup/route.ts` — POST on-demand lookup trigger
- Modify: `components/ConnectionsView.tsx` — "Ownership" section, 5-state machine
- Modify: `app/page.tsx` — enrichment mode state, disclosure display, SSE merge, command-bar wiring
- Modify: `components/CommandLineBar.tsx` — help text for `enrich ...` commands
- Modify: `docs/security.md` — replace the stale "no ownership enrichment" bullet (Task 16)

**New — tests (`lib/__tests__/`, all Vitest, `node` environment unless noted):**
- `enrichment-scope-filter.test.ts`, `enrichment-cache.test.ts`, `enrichment-query-log.test.ts`, `enrichment-request-queue.test.ts`, `enrichment-bootstrap.test.ts`, `enrichment-rdap-client.test.ts`, `enrichment-mapping.test.ts`, `enrichment-client.test.ts`, `enrichment-stream.test.ts`, `no-dangerous-html.test.ts`, `enrichment-reverse-dns.test.ts`, `enrichment-referral-allowlist.test.ts`, `enrichment-whois-client.test.ts`, `connections-view-ownership.test.tsx` (**`jsdom` environment** — see Task 10)

---

### Task 1: Private/reserved-range scope filter

**Files:**
- Create: `lib/enrichment/scope-filter.ts`
- Create: `lib/__tests__/enrichment-scope-filter.test.ts`

**Interfaces:**
- Produces:
  ```typescript
  export function ipToInt(ip: string): number | null;           // IPv4 only; null for unparseable/IPv6 input
  export function cidrContains(cidr: string, ip: string): boolean;
  export function isPrivateOrReserved(ip: string): boolean;
  ```
  `ipToInt`/`cidrContains` are re-exported from here and reused by `lib/enrichment/bootstrap.ts` (Task 5) for IANA bootstrap CIDR matching, and `ipToInt` is reused again by `lib/enrichment.ts` (Task 8) to derive a cache key's CIDR block from an RDAP response's `startAddress`/`endAddress` — one CIDR-math implementation, not three. `isPrivateOrReserved` is consumed by `lib/enrichment.ts` (Task 8) as the very first check before any lookup is ever queued, in both on-demand and background mode.

- [ ] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/enrichment-scope-filter.test.ts
import { describe, expect, it } from 'vitest';
import { cidrContains, isPrivateOrReserved } from '../enrichment/scope-filter';

describe('cidrContains', () => {
  it('matches an IP inside a /24', () => {
    expect(cidrContains('93.184.216.0/24', '93.184.216.34')).toBe(true);
  });
  it('rejects an IP outside the block', () => {
    expect(cidrContains('93.184.216.0/24', '93.184.217.1')).toBe(false);
  });
});

describe('isPrivateOrReserved', () => {
  const cases: Array<[string, boolean]> = [
    ['10.0.0.5', true],          // RFC1918
    ['172.16.4.4', true],        // RFC1918
    ['192.168.1.10', true],      // RFC1918
    ['127.0.0.1', true],         // loopback
    ['169.254.1.1', true],       // link-local
    ['100.64.0.5', true],        // CGNAT
    ['224.0.0.1', true],         // multicast
    ['::1', true],               // loopback v6
    ['fe80::1', true],           // link-local v6
    ['ff02::1', true],           // multicast v6
    ['93.184.216.34', false],    // public (example.com)
    ['8.8.8.8', false],          // public
  ];
  it.each(cases)('isPrivateOrReserved(%s) === %s', (ip, expected) => {
    expect(isPrivateOrReserved(ip)).toBe(expected);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-scope-filter.test.ts`
Expected: FAIL — `lib/enrichment/scope-filter.ts` doesn't exist yet.

- [ ] **Step 3: Implement `lib/enrichment/scope-filter.ts`**

```typescript
// lib/enrichment/scope-filter.ts

export function ipToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

export function cidrContains(cidr: string, ip: string): boolean {
  const [base, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const baseInt = ipToInt(base);
  const ipInt = ipToInt(ip);
  if (baseInt === null || ipInt === null || !Number.isInteger(bits)) return false;
  if (bits === 0) return true;
  const mask = bits >= 32 ? 0xffffffff : (~0 << (32 - bits)) >>> 0;
  return (baseInt & mask) === (ipInt & mask);
}

// IPv4 ranges that can never resolve to a meaningful RIR/registrar record —
// short-circuited before any lookup is even queued (spec Components §1).
const IPV4_RESERVED: string[] = [
  '10.0.0.0/8',       // RFC1918
  '172.16.0.0/12',    // RFC1918
  '192.168.0.0/16',   // RFC1918
  '127.0.0.0/8',       // loopback
  '169.254.0.0/16',    // link-local
  '100.64.0.0/10',     // CGNAT
  '224.0.0.0/4',        // multicast
];

function isIPv6PrivateOrReserved(ip: string): boolean {
  const lower = ip.toLowerCase();
  return (
    lower === '::1' ||
    lower.startsWith('fe80:') ||       // link-local
    lower.startsWith('fc') || lower.startsWith('fd') || // unique local
    lower.startsWith('ff')             // multicast
  );
}

export function isPrivateOrReserved(ip: string): boolean {
  if (ip.includes(':')) return isIPv6PrivateOrReserved(ip);
  return IPV4_RESERVED.some((cidr) => cidrContains(cidr, ip));
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/enrichment-scope-filter.test.ts`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/enrichment/scope-filter.ts lib/__tests__/enrichment-scope-filter.test.ts
git commit -m "feat(enrichment): add private/reserved IP range scope filter"
```

---

### Task 2: Disk-persisted CIDR/domain-keyed TTL cache

**Files:**
- Create: `lib/enrichment/types.ts`
- Create: `lib/enrichment/cache.ts`
- Create: `lib/__tests__/enrichment-cache.test.ts`
- Modify: `.gitignore` (add `.data/`)

**Interfaces:**
- Consumes: nothing from earlier tasks (foundational).
- Produces:
  ```typescript
  // lib/enrichment/types.ts
  export interface EnrichmentRecord {
    org?: string;
    asn?: string;
    asnOrg?: string;
    country?: string;
    registrant?: string;
    source: 'rdap' | 'whois' | 'cache';
    fetchedAt: string; // ISO 8601
  }
  export interface CacheEntry {
    key: string;               // CIDR block (IP lookups) or registered domain (domain lookups)
    record: EnrichmentRecord | null; // null = negative-cache entry
    expiresAt: number;         // epoch ms
  }

  // lib/enrichment/cache.ts
  export async function atomicWriteJson(filePath: string, data: unknown): Promise<void>;
  export function readJsonIfExists<T>(filePath: string): T | undefined;
  export class EnrichmentCache {
    constructor(filePath: string);
    load(): void;
    getForIp(ip: string): CacheEntry | undefined;      // CIDR-aware
    getForDomain(domain: string): CacheEntry | undefined;
    isFresh(entry: CacheEntry, now?: number): boolean;
    setSuccess(key: string, record: EnrichmentRecord, ttlMs: number): Promise<void>;
    setNegative(key: string, ttlMs: number): Promise<void>;
    clear(): Promise<void>;
  }
  ```
  `atomicWriteJson`/`readJsonIfExists` are reused by `lib/enrichment/bootstrap.ts` (Task 5) to cache the IANA bootstrap files, and by `lib/enrichment/query-log.ts` (Task 3) for its own atomic rewrite-on-prune. `EnrichmentCache` is consumed by `lib/enrichment.ts` (Task 8).

- [ ] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/enrichment-cache.test.ts
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EnrichmentCache } from '../enrichment/cache';

describe('EnrichmentCache', () => {
  let dir: string;
  let filePath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'enrichment-cache-'));
    filePath = join(dir, 'cache.json');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('CIDR-aware: a lookup for an IP within an already-cached block hits without a new request', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setSuccess('93.184.216.0/24', {
      org: 'EXAMPLE-ORG', source: 'rdap', fetchedAt: new Date().toISOString(),
    }, 14 * 24 * 60 * 60 * 1000);

    const hit = cache.getForIp('93.184.216.34');
    expect(hit).toBeDefined();
    expect(hit!.record?.org).toBe('EXAMPLE-ORG');
    expect(cache.isFresh(hit!)).toBe(true);
  });

  it('domain-keyed cache hit (extended tier)', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setSuccess('example.com', {
      registrant: 'Example Inc', source: 'rdap', fetchedAt: new Date().toISOString(),
    }, 14 * 24 * 60 * 60 * 1000);

    expect(cache.getForDomain('example.com')?.record?.registrant).toBe('Example Inc');
    expect(cache.getForDomain('other.com')).toBeUndefined();
  });

  it('TTL expiry: an entry past its TTL is no longer fresh', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setSuccess('93.184.216.0/24', {
      org: 'X', source: 'rdap', fetchedAt: new Date().toISOString(),
    }, 5);
    const entry = cache.getForIp('93.184.216.34')!;
    expect(cache.isFresh(entry, Date.now() + 1000)).toBe(false);
  });

  it('stale-on-failure: an expired entry is still returned, not deleted, so a failed refresh can serve it', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setSuccess('93.184.216.0/24', {
      org: 'X', source: 'rdap', fetchedAt: new Date().toISOString(),
    }, 5);
    await new Promise((r) => setTimeout(r, 20));
    const entry = cache.getForIp('93.184.216.34');
    expect(entry).toBeDefined(); // still present
    expect(cache.isFresh(entry!)).toBe(false); // caller knows it's stale
  });

  it('negative caching: a never-succeeded lookup is cached with its own short TTL', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setNegative('198.51.100.0/24', 5);
    const entry = cache.getForIp('198.51.100.7')!;
    expect(entry.record).toBeNull();
    expect(cache.isFresh(entry)).toBe(true);
  });

  it('atomic write: a write interrupted before rename leaves the previous file intact', async () => {
    writeFileSync(filePath, JSON.stringify({ entries: [{ key: 'a', record: null, expiresAt: 1 }] }));
    const before = readFileSync(filePath, 'utf8');

    // Simulate a crash between "temp file written" and "rename" by making
    // rename throw once — atomicWriteJson must propagate the error without
    // having touched the original file (it never writes in place).
    const originalRename = renameSync;
    let called = false;
    const fsRenameMock = () => {
      called = true;
      throw new Error('simulated crash before rename');
    };
    // (Implementation detail note for the implementer: if atomicWriteJson is
    // written against node:fs/promises rather than the sync API used above
    // for setup, mock `fs/promises`.rename via vi.mock instead of this
    // sync-only shim. The load-bearing assertion is the one below regardless
    // of which fs API the implementation uses.)
    void fsRenameMock; void originalRename; void called;

    const cache = new EnrichmentCache(filePath);
    cache.load();
    expect(readFileSync(filePath, 'utf8')).toBe(before);
  });

  it('clear() empties the cache file', async () => {
    const cache = new EnrichmentCache(filePath);
    cache.load();
    await cache.setSuccess('93.184.216.0/24', { org: 'X', source: 'rdap', fetchedAt: '2026-01-01' }, 1000);
    await cache.clear();
    expect(cache.getForIp('93.184.216.34')).toBeUndefined();
  });
});
```

Note on the atomic-write test: writing a true "kill mid-rename" simulation requires mocking `node:fs`'s `rename`/`renameSync`; the skeleton above documents the intent precisely so the implementer wires the actual `vi.mock('node:fs/promises', ...)` (or sync equivalent) against whichever API `atomicWriteJson` is built on — pick one API and keep the mock and implementation consistent. The load-bearing assertion (previous file byte-identical after a failed write attempt) must be real, not commented out.

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-cache.test.ts`
Expected: FAIL — `lib/enrichment/cache.ts` doesn't exist yet.

- [ ] **Step 3: Implement `lib/enrichment/types.ts` and `lib/enrichment/cache.ts`**

```typescript
// lib/enrichment/types.ts
export interface EnrichmentRecord {
  org?: string;
  asn?: string;
  asnOrg?: string;
  country?: string;
  registrant?: string;
  source: 'rdap' | 'whois' | 'cache';
  fetchedAt: string;
}

export interface CacheEntry {
  key: string;
  record: EnrichmentRecord | null;
  expiresAt: number;
}

export interface QueryLogEntry {
  target: string;
  endpoint: string;
  cacheStatus: 'hit' | 'miss';
  timestamp: string;
}
```

```typescript
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
    // eslint-disable-next-line @typescript-eslint/no-var-requires
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/enrichment-cache.test.ts`
Expected: all tests PASS.

- [ ] **Step 5: Add `.data/` to `.gitignore` and commit**

```bash
# append `.data/` to .gitignore
git add lib/enrichment/types.ts lib/enrichment/cache.ts lib/__tests__/enrichment-cache.test.ts .gitignore
git commit -m "feat(enrichment): add disk-persisted CIDR/domain-keyed TTL cache"
```

---

### Task 3: Outbound query audit log

**Files:**
- Create: `lib/enrichment/query-log.ts`
- Create: `lib/__tests__/enrichment-query-log.test.ts`

**Interfaces:**
- Consumes: `atomicWriteJson`-style atomicity pattern from Task 2 (a fresh append-then-optionally-rewrite, not a shared function — appends don't need atomic rename, but `prune()`'s rewrite does).
- Produces:
  ```typescript
  export class QueryLog {
    constructor(filePath: string);
    append(entry: { target: string; endpoint: string; cacheStatus: 'hit' | 'miss' }): Promise<void>;
    prune(retentionDays: number, now?: Date): Promise<void>;
    clear(): Promise<void>;
    readAll(): QueryLogEntry[]; // test/ops helper
  }
  ```
  Consumed by `lib/enrichment.ts` (Task 8) — every lookup attempt (cache hit or miss) gets one `append()` call, per Egress hygiene ("outbound queries are logged ... never full response bodies").

- [ ] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/enrichment-query-log.test.ts
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
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

    // Write directly to control timestamps precisely (append() always
    // stamps "now"); this exercises prune()'s filtering logic in isolation.
    await log.append({ target: 'old.example', endpoint: 'e', cacheStatus: 'miss' });
    await log.append({ target: 'recent.example', endpoint: 'e', cacheStatus: 'miss' });
    const entries = log.readAll();
    entries[0].timestamp = old.toISOString();
    entries[1].timestamp = recent.toISOString();
    // rewrite with the backdated timestamps (test-only direct manipulation)
    await log.clear();
    for (const e of entries) await log.append(e);
    // re-backdate after append() (which re-stamps "now") — append the raw
    // entries once more via the same backdating trick isn't circular here:
    // the point under test is prune()'s date comparison, so directly write
    // the file in this shape instead of round-tripping through append().

    await log.prune(30, now);
    const remaining = log.readAll();
    expect(remaining.some((e) => e.target === 'old.example')).toBe(false);
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
```

The second test's timestamp-backdating dance is awkward through the public API alone — flag this for the implementer: **either** expose a narrow test-only seam (e.g. an optional `timestampOverride` param on `append()`, clearly commented as test-only) **or** have the test write the NDJSON file directly with `fs.writeFileSync` for that one case and call `log.prune()` against it. Pick whichever keeps `QueryLog`'s public interface honest; don't leave the awkward double-append-then-mutate version from the draft above as the final test.

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-query-log.test.ts`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `lib/enrichment/query-log.ts`**

```typescript
// lib/enrichment/query-log.ts
import { promises as fs, mkdirSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { QueryLogEntry } from './types';
import { atomicWriteJson } from './cache';

export class QueryLog {
  constructor(private filePath: string) {}

  async append(entry: { target: string; endpoint: string; cacheStatus: 'hit' | 'miss'; timestampOverride?: string }): Promise<void> {
    mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
    const line: QueryLogEntry = {
      target: entry.target,
      endpoint: entry.endpoint,
      cacheStatus: entry.cacheStatus,
      timestamp: entry.timestampOverride ?? new Date().toISOString(),
    };
    const isNew = !existsSync(this.filePath);
    await fs.appendFile(this.filePath, JSON.stringify(line) + '\n', { mode: 0o600 });
    if (isNew) await fs.chmod(this.filePath, 0o600); // belt-and-suspenders: appendFile's mode option doesn't chmod an existing file
  }

  readAll(): QueryLogEntry[] {
    if (!existsSync(this.filePath)) return [];
    const raw = require('node:fs').readFileSync(this.filePath, 'utf8') as string;
    return raw
      .split('\n')
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l) as QueryLogEntry);
  }

  async prune(retentionDays: number, now: Date = new Date()): Promise<void> {
    const cutoff = now.getTime() - retentionDays * 24 * 60 * 60 * 1000;
    const kept = this.readAll().filter((e) => new Date(e.timestamp).getTime() >= cutoff);
    // Rewritten via the JSON-file atomic-rename helper even though this file
    // is logically NDJSON, not JSON — reused here for its
    // temp-file-then-rename safety, not its JSON.stringify formatting; write
    // the NDJSON body directly instead of calling atomicWriteJson verbatim.
    const tmpPath = `${this.filePath}.tmp-prune`;
    await fs.writeFile(tmpPath, kept.map((e) => JSON.stringify(e)).join('\n') + (kept.length ? '\n' : ''), { mode: 0o600 });
    await fs.rename(tmpPath, this.filePath);
    void atomicWriteJson; // (import kept for reference to the shared pattern; see comment above)
  }

  async clear(): Promise<void> {
    await fs.writeFile(this.filePath, '', { mode: 0o600 });
  }
}
```

(The `void atomicWriteJson;` line and its comment are a placeholder for the implementer to clean up — either actually reuse a shared "atomic rewrite" helper extracted from `cache.ts` for both JSON and NDJSON bodies, or drop the unused import. Don't ship the placeholder as-is.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/enrichment-query-log.test.ts`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/enrichment/query-log.ts lib/__tests__/enrichment-query-log.test.ts
git commit -m "feat(enrichment): add outbound query audit log with 30-day retention"
```

---

### Task 4: Request queue — concurrency=1, jittered spacing, background-mode shuffle helper

**Files:**
- Create: `lib/enrichment/request-queue.ts`
- Create: `lib/__tests__/enrichment-request-queue.test.ts`

**Interfaces:**
- Produces:
  ```typescript
  export interface RequestQueueOptions { minDelayMs?: number; maxDelayMs?: number; random?: () => number }
  export class RequestQueue {
    constructor(opts?: RequestQueueOptions); // defaults: minDelayMs=3000, maxDelayMs=10000
    enqueue<T>(fn: () => Promise<T>): Promise<T>;
    get pending(): number; // test/ops introspection
  }
  export function shuffle<T>(items: T[], random?: () => number): T[]; // Fisher-Yates, injectable RNG for deterministic tests
  ```
  Consumed by `lib/enrichment/rdap-client.ts` (Task 6) and `lib/enrichment/whois-client.ts` (Task 14) for the concurrency/spacing ceiling; `shuffle` is consumed by `lib/enrichment.ts` (Task 8) for background-mode dispatch ordering.

- [ ] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/enrichment-request-queue.test.ts
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { RequestQueue, shuffle } from '../enrichment/request-queue';

describe('RequestQueue', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('never runs more than 1 task concurrently', async () => {
    const queue = new RequestQueue({ minDelayMs: 3000, maxDelayMs: 3000 });
    let inFlight = 0;
    let maxInFlight = 0;
    const task = () => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          inFlight -= 1;
          resolve();
        }, 100);
      });
    };

    const results = [queue.enqueue(task), queue.enqueue(task), queue.enqueue(task)];
    await vi.runAllTimersAsync();
    await Promise.all(results);

    expect(maxInFlight).toBe(1);
  });

  it('enforces the minimum spacing floor between dispatches', async () => {
    const queue = new RequestQueue({ minDelayMs: 3000, maxDelayMs: 3000 }); // fixed delay for a deterministic assertion
    const dispatchTimes: number[] = [];
    const task = () => {
      dispatchTimes.push(Date.now());
      return Promise.resolve();
    };

    const p1 = queue.enqueue(task);
    const p2 = queue.enqueue(task);
    const p3 = queue.enqueue(task);
    await vi.runAllTimersAsync();
    await Promise.all([p1, p2, p3]);

    expect(dispatchTimes[0]).toBe(0); // first dispatch is immediate — nothing to space against yet
    expect(dispatchTimes[1] - dispatchTimes[0]).toBeGreaterThanOrEqual(3000);
    expect(dispatchTimes[2] - dispatchTimes[1]).toBeGreaterThanOrEqual(3000);
  });

  it('redraws jitter within the 3–10s band for each dispatch, not a fixed interval', async () => {
    const draws: number[] = [];
    const random = () => {
      const v = draws.length % 2 === 0 ? 0 : 0.999; // alternate min/max ends of the band
      draws.push(v);
      return v;
    };
    const queue = new RequestQueue({ minDelayMs: 3000, maxDelayMs: 10000, random });
    const gaps: number[] = [];
    let last = 0;
    const task = () => {
      gaps.push(Date.now() - last);
      last = Date.now();
      return Promise.resolve();
    };
    const ps = [queue.enqueue(task), queue.enqueue(task), queue.enqueue(task)];
    await vi.runAllTimersAsync();
    await Promise.all(ps);

    // Not asserting exact values (that's `random`'s job to determine) — just
    // that consecutive gaps differ, proving the delay is redrawn per
    // dispatch rather than a single fixed interval reused every time.
    expect(gaps[1]).not.toBe(gaps[2]);
  });
});

describe('shuffle', () => {
  it('produces a permutation (same elements, order changed for a non-trivial input)', () => {
    const input = [1, 2, 3, 4, 5, 6, 7, 8];
    let call = 0;
    const random = () => {
      // deterministic sequence that is not the identity permutation
      const seq = [0.9, 0.1, 0.8, 0.2, 0.7, 0.3, 0.6];
      return seq[call++ % seq.length];
    };
    const result = shuffle(input, random);
    expect(result.slice().sort((a, b) => a - b)).toEqual(input);
    expect(result).not.toEqual(input);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-request-queue.test.ts`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `lib/enrichment/request-queue.ts`**

```typescript
// lib/enrichment/request-queue.ts

export function shuffle<T>(items: T[], random: () => number = Math.random): T[] {
  const result = [...items];
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

export interface RequestQueueOptions {
  minDelayMs?: number;
  maxDelayMs?: number;
  random?: () => number;
}

interface QueuedTask {
  run: () => Promise<unknown>;
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
}

export class RequestQueue {
  private minDelayMs: number;
  private maxDelayMs: number;
  private random: () => number;
  private queue: QueuedTask[] = [];
  private running = false;
  private hasDispatchedOnce = false;

  constructor(opts: RequestQueueOptions = {}) {
    this.minDelayMs = opts.minDelayMs ?? 3000;
    this.maxDelayMs = opts.maxDelayMs ?? 10000;
    this.random = opts.random ?? Math.random;
  }

  get pending(): number {
    return this.queue.length;
  }

  enqueue<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push({ run: fn, resolve: resolve as (v: unknown) => void, reject });
      this.drain();
    });
  }

  private async drain(): Promise<void> {
    if (this.running) return;
    this.running = true;
    while (this.queue.length > 0) {
      if (this.hasDispatchedOnce) {
        const delay = this.minDelayMs + this.random() * (this.maxDelayMs - this.minDelayMs);
        await new Promise((r) => setTimeout(r, delay));
      }
      this.hasDispatchedOnce = true;
      const task = this.queue.shift()!;
      try {
        task.resolve(await task.run());
      } catch (err) {
        task.reject(err);
      }
    }
    this.running = false;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/enrichment-request-queue.test.ts`
Expected: all tests PASS. (If `vi.runAllTimersAsync()` doesn't drain a `setTimeout` scheduled *inside* an already-pending promise chain on the installed Vitest version, use `await vi.advanceTimersByTimeAsync(15000)` per assertion block instead — check `npx vitest --version` behavior if this hangs.)

- [ ] **Step 5: Commit**

```bash
git add lib/enrichment/request-queue.ts lib/__tests__/enrichment-request-queue.test.ts
git commit -m "feat(enrichment): add concurrency=1 jittered request queue and shuffle helper"
```

---

### Task 5: IANA IP RDAP bootstrap fetch, cache, and CIDR routing

**Files:**
- Create: `lib/enrichment/bootstrap.ts`
- Create: `lib/__tests__/enrichment-bootstrap.test.ts`

**Interfaces:**
- Consumes: `cidrContains` (Task 1), `atomicWriteJson`/`readJsonIfExists` (Task 2).
- Produces:
  ```typescript
  export interface BootstrapService { prefixes: string[]; url: string }
  export function parseIpBootstrap(json: unknown): BootstrapService[]; // validates + drops non-allowlisted RIR hosts
  export function resolveRdapBaseForIp(ip: string, services: BootstrapService[]): string | null;
  export async function loadIpBootstrap(
    cachePath: string,
    fetchImpl: typeof fetch,
    ttlMs?: number,
  ): Promise<BootstrapService[]>; // fetches ipv4.json + ipv6.json once, long-TTL cached on disk
  ```
  Consumed by `lib/enrichment/rdap-client.ts` (Task 6, indirectly via `lib/enrichment.ts` in Task 8) to pick the authoritative RIR base URL for a queried IP before ever making the actual RDAP request.

- [ ] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/enrichment-bootstrap.test.ts
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadIpBootstrap, parseIpBootstrap, resolveRdapBaseForIp } from '../enrichment/bootstrap';

// Fixture shaped like IANA's real ipv4.json (RFC 7484 bootstrap format):
// { "services": [ [ [prefixes...], [urls...] ], ... ] }
const FIXTURE_IPV4_BOOTSTRAP = {
  services: [
    [['93.184.216.0/24', '198.51.100.0/24'], ['https://rdap.arin.net/registry/']],
    [['192.0.2.0/24'], ['https://rdap.db.ripe.net/']],
    // A malicious/compromised-CDN entry: not a real RIR host. Must be
    // dropped by parseIpBootstrap, not trusted just because it came back in
    // IANA's response body (spec Components §5, response-controlled SSRF).
    [['203.0.113.0/24'], ['https://attacker.example/rdap/']],
  ],
};

describe('parseIpBootstrap', () => {
  it('extracts prefix->url mappings and drops non-allowlisted RIR hosts', () => {
    const services = parseIpBootstrap(FIXTURE_IPV4_BOOTSTRAP);
    expect(services).toHaveLength(2);
    expect(services.some((s) => s.url.includes('attacker.example'))).toBe(false);
  });

  it('tolerates malformed entries without throwing', () => {
    expect(() => parseIpBootstrap({ services: [null, [], ['only one element'], { not: 'an array' }] })).not.toThrow();
    expect(parseIpBootstrap({})).toEqual([]);
    expect(parseIpBootstrap(null)).toEqual([]);
  });
});

describe('resolveRdapBaseForIp', () => {
  const services = parseIpBootstrap(FIXTURE_IPV4_BOOTSTRAP);

  it('routes to the correct RIR base URL for an IP inside a listed prefix', () => {
    expect(resolveRdapBaseForIp('93.184.216.34', services)).toBe('https://rdap.arin.net/registry/');
    expect(resolveRdapBaseForIp('192.0.2.5', services)).toBe('https://rdap.db.ripe.net/');
  });

  it('returns null for an IP not covered by any listed prefix', () => {
    expect(resolveRdapBaseForIp('8.8.8.8', services)).toBeNull();
  });
});

describe('loadIpBootstrap', () => {
  let dir: string;
  let cachePath: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'bootstrap-')); cachePath = join(dir, 'bootstrap-ipv4.json'); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('fetches once and reuses the disk cache on a second call within TTL', async () => {
    let fetchCount = 0;
    const fetchImpl = (async () => {
      fetchCount += 1;
      return new Response(JSON.stringify(FIXTURE_IPV4_BOOTSTRAP), { status: 200 });
    }) as typeof fetch;

    const first = await loadIpBootstrap(cachePath, fetchImpl, 30 * 24 * 60 * 60 * 1000);
    const second = await loadIpBootstrap(cachePath, fetchImpl, 30 * 24 * 60 * 60 * 1000);

    expect(fetchCount).toBe(1);
    expect(first).toEqual(second);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-bootstrap.test.ts`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `lib/enrichment/bootstrap.ts`**

```typescript
// lib/enrichment/bootstrap.ts
import { cidrContains } from './scope-filter';
import { atomicWriteJson, readJsonIfExists } from './cache';

export interface BootstrapService {
  prefixes: string[];
  url: string;
}

// Request-controlled: this list of known RIR RDAP hosts is static and never
// derived from request input. Response-controlled hardening happens in
// parseIpBootstrap below, which drops any URL whose host isn't in this set —
// the bootstrap *response body* is third-party network data and is never
// trusted just because IANA's server returned it (spec Components §5).
const KNOWN_RIR_HOSTS = new Set([
  'rdap.arin.net',
  'rdap.db.ripe.net',
  'rdap.apnic.net',
  'rdap.lacnic.net',
  'rdap.afrinic.net',
]);

export function parseIpBootstrap(json: unknown): BootstrapService[] {
  const obj = json as { services?: unknown } | null;
  if (!obj || !Array.isArray(obj.services)) return [];
  const out: BootstrapService[] = [];
  for (const entry of obj.services) {
    if (!Array.isArray(entry) || entry.length < 2) continue;
    const [prefixes, urls] = entry;
    if (!Array.isArray(prefixes) || !Array.isArray(urls)) continue;
    const url = urls.find((u: unknown): u is string => typeof u === 'string' && u.startsWith('https://'));
    if (!url) continue;
    let host: string;
    try {
      host = new URL(url).host;
    } catch {
      continue;
    }
    if (!KNOWN_RIR_HOSTS.has(host)) continue;
    out.push({ prefixes: prefixes.filter((p: unknown): p is string => typeof p === 'string'), url });
  }
  return out;
}

export function resolveRdapBaseForIp(ip: string, services: BootstrapService[]): string | null {
  for (const service of services) {
    for (const prefix of service.prefixes) {
      if (cidrContains(prefix, ip)) return service.url;
    }
  }
  return null;
}

interface BootstrapCacheFile {
  fetchedAt: number;
  services: BootstrapService[];
}

const IANA_IPV4_BOOTSTRAP_URL = 'https://data.iana.org/rdap/ipv4.json';
const IANA_IPV6_BOOTSTRAP_URL = 'https://data.iana.org/rdap/ipv6.json';

export async function loadIpBootstrap(
  cachePath: string,
  fetchImpl: typeof fetch,
  ttlMs: number = 30 * 24 * 60 * 60 * 1000,
): Promise<BootstrapService[]> {
  const cached = readJsonIfExists<BootstrapCacheFile>(cachePath);
  if (cached && Date.now() - cached.fetchedAt < ttlMs) {
    return cached.services;
  }

  const [v4, v6] = await Promise.all([
    fetchImpl(IANA_IPV4_BOOTSTRAP_URL, { redirect: 'manual' }),
    fetchImpl(IANA_IPV6_BOOTSTRAP_URL, { redirect: 'manual' }),
  ]);
  const services = [...parseIpBootstrap(await v4.json()), ...parseIpBootstrap(await v6.json())];
  await atomicWriteJson(cachePath, { fetchedAt: Date.now(), services } satisfies BootstrapCacheFile);
  return services;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/enrichment-bootstrap.test.ts`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/enrichment/bootstrap.ts lib/__tests__/enrichment-bootstrap.test.ts
git commit -m "feat(enrichment): add IANA IP RDAP bootstrap fetch/cache/routing with RIR-host allowlist"
```

---

### Task 6: Hardened RDAP HTTP client — timeout, size cap, redirect lock, 429 backoff, circuit breaker

**Files:**
- Create: `lib/enrichment/rdap-client.ts`
- Create: `lib/__tests__/enrichment-rdap-client.test.ts`

**Interfaces:**
- Consumes: nothing structurally from earlier tasks (the request queue is applied by the caller in Task 8, not inside this client, so this client's own concurrency/backoff bookkeeping stays testable in isolation).
- Produces:
  ```typescript
  export type RdapResult =
    | { ok: true; json: unknown }
    | { ok: false; reason: 'timeout' | 'too_large' | 'http_error' | 'redirect' | 'circuit_open' | 'backoff' | 'network'; status?: number };

  export function computeBackoffDelayMs(consecutive429s: number, retryAfterSec?: number): number;

  export class RdapClient {
    constructor(fetchImpl?: typeof fetch, now?: () => number);
    fetch(url: string): Promise<RdapResult>;
  }
  ```
  Consumed by `lib/enrichment.ts` (Task 8), which wraps `RdapClient#fetch` calls in the `RequestQueue` from Task 4 — the queue provides cross-request spacing/concurrency, this client provides per-request hardening and per-registry-host backoff/circuit-breaker state.

- [ ] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/enrichment-rdap-client.test.ts
import { describe, expect, it, vi } from 'vitest';
import { RdapClient, computeBackoffDelayMs } from '../enrichment/rdap-client';

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers });
}

describe('computeBackoffDelayMs', () => {
  it('follows the 30s-start, doubling, 30min-cap schedule', () => {
    expect(computeBackoffDelayMs(1)).toBe(30_000);
    expect(computeBackoffDelayMs(2)).toBe(60_000);
    expect(computeBackoffDelayMs(3)).toBe(120_000);
    expect(computeBackoffDelayMs(10)).toBe(30 * 60_000); // capped
  });
  it('honors Retry-After when it is larger than the computed default', () => {
    expect(computeBackoffDelayMs(1, 90)).toBe(90_000);
    expect(computeBackoffDelayMs(1, 5)).toBe(30_000); // default still wins if larger
  });
});

describe('RdapClient', () => {
  it('never follows a 3xx redirect — redirect:"manual" is honored, not just configured', async () => {
    const fetchImpl = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(init?.redirect).toBe('manual');
      return new Response(null, { status: 0, statusText: '', headers: {} }) as Response & { type: string };
    });
    // Simulate what Node's fetch actually returns for redirect:'manual': an
    // opaqueredirect response (status 0, type 'opaqueredirect'), not a thrown
    // error and not the 3xx status directly.
    Object.defineProperty(fetchImpl.mock.results, 'x', { value: undefined, configurable: true }); // no-op, keep TS quiet
    const client = new RdapClient(async (url, init) => {
      expect(init?.redirect).toBe('manual');
      const r = new Response(null, { status: 302 });
      Object.defineProperty(r, 'type', { value: 'opaqueredirect' });
      return r;
    });

    const result = await client.fetch('https://rdap.arin.net/registry/ip/93.184.216.34');
    expect(result).toEqual({ ok: false, reason: 'redirect', status: undefined });
  });

  it('aborts a response exceeding the 256KB cap and treats it as a failure', async () => {
    const bigChunk = new Uint8Array(300 * 1024); // 300KB > 256KB cap
    const fetchImpl = (async () => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bigChunk);
          controller.close();
        },
      });
      return new Response(stream, { status: 200 });
    }) as typeof fetch;

    const client = new RdapClient(fetchImpl);
    const result = await client.fetch('https://rdap.arin.net/registry/ip/93.184.216.34');
    expect(result).toEqual({ ok: false, reason: 'too_large' });
  });

  it('aborts at the 10-second timeout when the registry never responds', async () => {
    vi.useFakeTimers();
    const fetchImpl = ((_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      })) as typeof fetch;

    const client = new RdapClient(fetchImpl);
    const resultPromise = client.fetch('https://rdap.arin.net/registry/ip/93.184.216.34');
    await vi.advanceTimersByTimeAsync(10_000);
    const result = await resultPromise;
    expect(result).toEqual({ ok: false, reason: 'timeout' });
    vi.useRealTimers();
  });

  it('trips the circuit breaker after 3 consecutive 429s within 10 minutes and holds the 1hr cooldown', async () => {
    let now = 0;
    const fetchImpl = (async () => jsonResponse({}, 429)) as typeof fetch;
    const client = new RdapClient(fetchImpl, () => now);

    await client.fetch('https://rdap.arin.net/x'); // 429 #1
    now += 60_000;
    await client.fetch('https://rdap.arin.net/x'); // 429 #2 (backoff window may block the *dispatch* in the real queue, but this client's own state machine is what's under test here — advance past any self-imposed backoffUntil too)
    now += 200_000;
    const third = await client.fetch('https://rdap.arin.net/x'); // 429 #3, within the 10-minute window
    expect(third).toMatchObject({ reason: 'http_error', status: 429 });

    now += 1000; // still well within the 1hr cooldown
    const duringCooldown = await client.fetch('https://rdap.arin.net/x');
    expect(duringCooldown).toEqual({ ok: false, reason: 'circuit_open' });

    now += 60 * 60_000 + 1;
    const afterCooldown = await client.fetch('https://rdap.arin.net/x');
    expect(afterCooldown).not.toEqual({ ok: false, reason: 'circuit_open' });
  });

  it('returns parsed JSON on a normal 200 response', async () => {
    const fetchImpl = (async () => jsonResponse({ objectClassName: 'ip network' })) as typeof fetch;
    const client = new RdapClient(fetchImpl);
    const result = await client.fetch('https://rdap.arin.net/registry/ip/93.184.216.34');
    expect(result).toEqual({ ok: true, json: { objectClassName: 'ip network' } });
  });
});
```

Note for the implementer: the redirect test's exact mechanics depend on how the installed Node version's `fetch` actually surfaces `redirect: 'manual'` (an `opaqueredirect` `Response` with `status: 0`, per the Fetch spec, is Node's documented behavior — verify against `node --version` if this test doesn't match reality, same "adjust against the installed runtime" caveat the Rust plan gives `etherparse`).

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-rdap-client.test.ts`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `lib/enrichment/rdap-client.ts`**

```typescript
// lib/enrichment/rdap-client.ts

export type RdapResult =
  | { ok: true; json: unknown }
  | { ok: false; reason: 'timeout' | 'too_large' | 'http_error' | 'redirect' | 'circuit_open' | 'backoff' | 'network'; status?: number };

const REQUEST_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 256 * 1024;
const BACKOFF_START_MS = 30_000;
const BACKOFF_CAP_MS = 30 * 60_000;
const BREAKER_WINDOW_MS = 10 * 60_000;
const BREAKER_TRIP_COUNT = 3;
const BREAKER_COOLDOWN_MS = 60 * 60_000;

export function computeBackoffDelayMs(consecutive429s: number, retryAfterSec?: number): number {
  const exp = BACKOFF_START_MS * Math.pow(2, Math.max(0, consecutive429s - 1));
  const capped = Math.min(exp, BACKOFF_CAP_MS);
  const retryAfterMs = retryAfterSec ? retryAfterSec * 1000 : 0;
  return Math.max(capped, retryAfterMs);
}

interface HostState {
  consecutive429s: number;
  backoffUntil: number;
  trip429Timestamps: number[];
  circuitOpenUntil: number;
}

export class RdapClient {
  private hostState = new Map<string, HostState>();

  constructor(
    private fetchImpl: typeof fetch = fetch,
    private now: () => number = Date.now,
  ) {}

  private stateFor(host: string): HostState {
    let s = this.hostState.get(host);
    if (!s) {
      s = { consecutive429s: 0, backoffUntil: 0, trip429Timestamps: [], circuitOpenUntil: 0 };
      this.hostState.set(host, s);
    }
    return s;
  }

  async fetch(url: string): Promise<RdapResult> {
    const host = new URL(url).host;
    const state = this.stateFor(host);
    const now = this.now();
    if (now < state.circuitOpenUntil) return { ok: false, reason: 'circuit_open' };
    if (now < state.backoffUntil) return { ok: false, reason: 'backoff' };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await this.fetchImpl(url, {
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': 'osi-netstriker-enrichment/1.0' },
      });

      if ((response as Response & { type?: string }).type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
        return { ok: false, reason: 'redirect', status: response.status || undefined };
      }

      if (response.status === 429) {
        state.consecutive429s += 1;
        state.trip429Timestamps = [...state.trip429Timestamps, now].filter((t) => now - t <= BREAKER_WINDOW_MS);
        const retryAfterHeader = response.headers.get('retry-after');
        const retryAfterSec = retryAfterHeader ? Number(retryAfterHeader) : undefined;
        state.backoffUntil = now + computeBackoffDelayMs(state.consecutive429s, retryAfterSec);
        if (state.trip429Timestamps.length >= BREAKER_TRIP_COUNT) {
          state.circuitOpenUntil = now + BREAKER_COOLDOWN_MS;
        }
        return { ok: false, reason: 'http_error', status: 429 };
      }

      state.consecutive429s = 0;

      if (!response.ok) {
        return { ok: false, reason: 'http_error', status: response.status };
      }

      const reader = response.body?.getReader();
      if (!reader) return { ok: false, reason: 'network' };
      let received = 0;
      const chunks: Uint8Array[] = [];
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > MAX_RESPONSE_BYTES) {
          controller.abort();
          return { ok: false, reason: 'too_large' };
        }
        chunks.push(value);
      }
      const text = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
      return { ok: true, json: JSON.parse(text) };
    } catch {
      if (controller.signal.aborted) return { ok: false, reason: 'timeout' };
      return { ok: false, reason: 'network' };
    } finally {
      clearTimeout(timer);
    }
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/enrichment-rdap-client.test.ts`
Expected: all tests PASS. Adjust the redirect-handling branch and the streaming-read branch against the installed Node `fetch`/Web Streams behavior if they don't match (see the note in Step 1).

- [ ] **Step 5: Commit**

```bash
git add lib/enrichment/rdap-client.ts lib/__tests__/enrichment-rdap-client.test.ts
git commit -m "feat(enrichment): add hardened RDAP client with timeout/size-cap/redirect-lock/backoff/circuit-breaker"
```

---

### Task 7: `NetworkConnection.enrichment` type + RDAP response mapping (untrusted-input parsing)

**Files:**
- Modify: `lib/types.ts`
- Create: `lib/enrichment-mapping.ts`
- Create: `lib/__tests__/enrichment-mapping.test.ts`

**Interfaces:**
- Consumes: `EnrichmentRecord` (Task 2).
- Produces:
  ```typescript
  // lib/types.ts addition
  export interface NetworkConnection {
    // ...existing fields unchanged...
    enrichment?: {
      org?: string;
      asn?: string;   // best-effort registry data, NOT BGP routing data — see spec Scope
      asnOrg?: string;
      country?: string;
      registrant?: string; // extended tier only
      source: 'rdap' | 'whois' | 'cache';
      fetchedAt: string;
    };
  }

  // lib/enrichment-mapping.ts
  export function extractIpRdap(json: unknown): Omit<import('./enrichment/types').EnrichmentRecord, 'source' | 'fetchedAt'>;
  export function buildEnrichmentEvent(
    connectionId: string,
    remoteAddr: string,
    record: import('./enrichment/types').EnrichmentRecord,
  ): { type: 'connection_enrichment'; connectionId: string; remoteAddr: string; enrichment: NetworkConnection['enrichment'] };
  export function applyEnrichmentEvent(connections: NetworkConnection[], event: ReturnType<typeof buildEnrichmentEvent>): NetworkConnection[];
  ```
  `extractIpRdap` is consumed by `lib/enrichment.ts` (Task 8) after a successful `RdapClient#fetch`. `buildEnrichmentEvent`/`applyEnrichmentEvent` are consumed by `app/api/stream/route.ts` (Task 9) and `app/page.tsx` (Task 10) respectively.

- [ ] **Step 1: Add the `enrichment` field to `lib/types.ts`**

```typescript
// lib/types.ts — inside NetworkConnection, after `sparkline: number[];`
  // Populated only when the user has opted into ownership enrichment
  // (docs/superpowers/specs/2026-08-28-ownership-enrichment-design.md).
  // `undefined` unambiguously means "never looked up" — a single presence
  // check gates whether the Ownership section shows anything but its
  // disabled/not-yet-looked-up state.
  enrichment?: {
    org?: string;
    asn?: string;    // best-effort RIR registry data, NOT BGP-observed routing data — see spec Scope
    asnOrg?: string;
    country?: string;
    registrant?: string; // extended tier only (domain registrant)
    source: 'rdap' | 'whois' | 'cache';
    fetchedAt: string;
  };
```

- [ ] **Step 2: Write the failing tests**

```typescript
// lib/__tests__/enrichment-mapping.test.ts
import { describe, expect, it } from 'vitest';
import { applyEnrichmentEvent, buildEnrichmentEvent, extractIpRdap } from '../enrichment-mapping';
import { NetworkConnection } from '../types';

const VALID_RDAP_IP_NETWORK = {
  objectClassName: 'ip network',
  handle: 'NET-93-184-216-0-1',
  name: 'EXAMPLE-NET',
  country: 'US',
  entities: [
    {
      objectClassName: 'entity',
      roles: ['registrant'],
      vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Org, Inc.']]],
    },
  ],
};

describe('extractIpRdap', () => {
  it('extracts org/country from a well-formed RDAP ip-network response', () => {
    const record = extractIpRdap(VALID_RDAP_IP_NETWORK);
    expect(record.org).toBe('Example Org, Inc.');
    expect(record.country).toBe('US');
  });

  it('never throws on malformed/oversized/wrong-shaped input — untrusted third-party JSON', () => {
    const hostileInputs: unknown[] = [
      null,
      undefined,
      42,
      'a string, not an object',
      {},
      { entities: 'not an array' },
      { entities: [{ vcardArray: 'not an array' }] },
      { entities: [{ vcardArray: ['vcard', 'not an array'] }] },
      { country: { nested: 'object where a string was expected' } },
      { name: 'x'.repeat(1_000_000) }, // pathologically long string
      JSON.parse('{"a":' + '[1,'.repeat(50) + '1' + ']'.repeat(50) + '}'), // deep nesting
    ];
    for (const input of hostileInputs) {
      expect(() => extractIpRdap(input)).not.toThrow();
    }
  });

  it('returns an empty-ish record (all fields undefined) when nothing usable is present', () => {
    const record = extractIpRdap({ objectClassName: 'ip network' });
    expect(record.org).toBeUndefined();
    expect(record.country).toBeUndefined();
  });
});

describe('buildEnrichmentEvent / applyEnrichmentEvent', () => {
  it('upserts onto an existing connection by id without disturbing other fields', () => {
    const base: NetworkConnection = {
      id: 'conn-1', protocol: 'HTTPS/TLS', appLayerProtocol: 'HTTPS/TLS', transportProtocol: 'TCP',
      osiStack: 'x', localAddr: '192.168.1.10', localPort: 51000, remoteAddr: '93.184.216.34', remotePort: 443,
      processName: 'Safari', pid: 1234, rxSpeed: 0, txSpeed: 0, rxBytesTotal: 0, txBytesTotal: 0,
      latencyMs: 0, packetLoss: 0, status: 'ESTABLISHED', encryption: 'TLS', sparkline: [],
    };
    const event = buildEnrichmentEvent('conn-1', '93.184.216.34', {
      org: 'Example Org', source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z',
    });
    const result = applyEnrichmentEvent([base], event);

    expect(result).toHaveLength(1);
    expect(result[0].enrichment?.org).toBe('Example Org');
    expect(result[0].processName).toBe('Safari'); // untouched — owned by connection_update
  });

  it('is a no-op (returns the array unchanged in content) when the connection id is not present', () => {
    const event = buildEnrichmentEvent('conn-missing', '1.2.3.4', { source: 'rdap', fetchedAt: 'x' });
    const result = applyEnrichmentEvent([], event);
    expect(result).toEqual([]);
  });
});
```

- [ ] **Step 3: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-mapping.test.ts`
Expected: FAIL — `lib/enrichment-mapping.ts` doesn't exist yet.

- [ ] **Step 4: Implement `lib/enrichment-mapping.ts`**

```typescript
// lib/enrichment-mapping.ts
import { EnrichmentRecord } from './enrichment/types';
import { NetworkConnection } from './types';

function asString(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 && v.length < 4096 ? v : undefined;
}

/**
 * Extracts org/country (and, where present, ASN fields) from a raw RDAP
 * "ip network" response object. Treated as untrusted third-party input —
 * mirrors the posture capture-agent/src/parse.rs takes toward untrusted
 * packet bytes: never throw, always return *something* usable even from
 * hostile/malformed/wrong-shaped JSON.
 */
export function extractIpRdap(json: unknown): Omit<EnrichmentRecord, 'source' | 'fetchedAt'> {
  try {
    const obj = json as Record<string, unknown>;
    if (!obj || typeof obj !== 'object') return {};

    const country = asString(obj.country);

    let org: string | undefined;
    const entities = Array.isArray(obj.entities) ? obj.entities : [];
    for (const entity of entities) {
      const vcardArray = (entity as Record<string, unknown>)?.vcardArray;
      if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) continue;
      const fields = vcardArray[1] as unknown[];
      const fn = fields.find((f) => Array.isArray(f) && f[0] === 'fn');
      if (Array.isArray(fn) && typeof fn[3] === 'string') {
        org = asString(fn[3]);
        if (org) break;
      }
    }
    // Fall back to the top-level `name`/`handle` if no vCard org was found —
    // some RIR responses only carry a network block name, no entities.
    if (!org) org = asString(obj.name) ?? asString(obj.handle);

    return { org, country };
  } catch {
    // Belt-and-suspenders: the try/catch above should never be reached given
    // the defensive checks, but untrusted-input code gets this guarantee
    // unconditionally, not "as long as I didn't miss a case."
    return {};
  }
}

export function buildEnrichmentEvent(
  connectionId: string,
  remoteAddr: string,
  record: EnrichmentRecord,
): { type: 'connection_enrichment'; connectionId: string; remoteAddr: string; enrichment: NetworkConnection['enrichment'] } {
  return {
    type: 'connection_enrichment',
    connectionId,
    remoteAddr,
    enrichment: { ...record },
  };
}

export function applyEnrichmentEvent(
  connections: NetworkConnection[],
  event: { connectionId: string; enrichment: NetworkConnection['enrichment'] },
): NetworkConnection[] {
  const idx = connections.findIndex((c) => c.id === event.connectionId);
  if (idx === -1) return connections;
  const next = [...connections];
  next[idx] = { ...next[idx], enrichment: event.enrichment };
  return next;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/enrichment-mapping.test.ts`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add lib/types.ts lib/enrichment-mapping.ts lib/__tests__/enrichment-mapping.test.ts
git commit -m "feat(enrichment): add NetworkConnection.enrichment field and RDAP response mapping"
```

---

### Task 8: `EnrichmentClient` — opt-in gate, disclosure, orchestration, single-flight

**Files:**
- Create: `lib/enrichment.ts`
- Create: `lib/__tests__/enrichment-client.test.ts`

**Interfaces:**
- Consumes: `isPrivateOrReserved` (Task 1), `EnrichmentCache` (Task 2), `QueryLog` (Task 3), `RequestQueue`/`shuffle` (Task 4), `loadIpBootstrap`/`resolveRdapBaseForIp` (Task 5), `RdapClient` (Task 6), `extractIpRdap` (Task 7).
- Produces:
  ```typescript
  export type EnrichmentMode = 'off' | 'on-demand' | 'background';
  export const DISCLOSURE_TEXT: string; // shown before every `enable()` — see Task 10
  export const DISCLOSURE_TEXT_BACKGROUND: string; // separately-worded, shown before every `enableBackground()` — spec Components §1 requires background mode's confirmation to be "its own separately-worded confirmation," not a reuse of the on-demand text
  export class EnrichmentClient extends EventEmitter {
    constructor(opts: { dataDir: string; fetchImpl?: typeof fetch });
    getMode(): EnrichmentMode;
    enable(): { disclosureText: string };
    enableBackground(): { disclosureText: string };
    disable(): void;
    disableBackground(): void;
    clear(): Promise<void>;
    requestLookup(connectionId: string, remoteAddr: string): void; // on-demand trigger, no-op if mode === 'off'
    notifyObservedConnections(conns: Array<{ id: string; remoteAddr: string }>): void; // background trigger
    // emits: 'result' with the shape from buildEnrichmentEvent (Task 7)
  }
  ```
  Consumed by `app/api/stream/route.ts` and the new `app/api/enrichment/*` routes (Task 9).

- [ ] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/enrichment-client.test.ts
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EnrichmentClient } from '../enrichment';

function fakeFetch(status = 200, body: unknown = { objectClassName: 'ip network', name: 'EXAMPLE-ORG' }) {
  return vi.fn(async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;
}

describe('EnrichmentClient', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'enrichment-client-')); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('makes zero HTTP calls when disabled', async () => {
    const fetchImpl = vi.fn();
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl: fetchImpl as unknown as typeof fetch });
    client.requestLookup('conn-1', '93.184.216.34');
    await new Promise((r) => setTimeout(r, 50));
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('starts in "off" mode on every fresh instance — opt-in never survives a simulated restart', () => {
    const client = new EnrichmentClient({ dataDir: dir });
    expect(client.getMode()).toBe('off');
    client.enable();
    expect(client.getMode()).toBe('on-demand');

    // Simulate a relay restart: a brand new instance, same data directory.
    const restarted = new EnrichmentClient({ dataDir: dir });
    expect(restarted.getMode()).toBe('off');
  });

  it('returns non-empty disclosure text on every activation, not only the first', () => {
    const client = new EnrichmentClient({ dataDir: dir });
    const first = client.enable();
    client.disable();
    const second = client.enable();
    expect(first.disclosureText.length).toBeGreaterThan(0);
    expect(second.disclosureText).toBe(first.disclosureText);
  });

  it('background mode gets its own, separately-worded disclosure text, not a reuse of the on-demand text', () => {
    const client = new EnrichmentClient({ dataDir: dir });
    const onDemand = client.enable();
    client.disable();
    const background = client.enableBackground();
    expect(background.disclosureText.length).toBeGreaterThan(0);
    expect(background.disclosureText).not.toBe(onDemand.disclosureText);
  });

  it('never queries a private/reserved IP', async () => {
    const fetchImpl = fakeFetch();
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl });
    client.enable();
    client.requestLookup('conn-1', '192.168.1.50');
    await new Promise((r) => setTimeout(r, 50));
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('on-demand lookup emits a "result" event with mapped org data on success', async () => {
    const fetchImpl = fakeFetch();
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl });
    client.enable();

    const resultPromise = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-1', '93.184.216.34');
    const result = (await resultPromise) as { connectionId: string; enrichment: { org?: string } };

    expect(result.connectionId).toBe('conn-1');
    expect(result.enrichment.org).toBe('EXAMPLE-ORG');
  }, 15_000);

  it('single-flight: two requests for the same key before the first resolves trigger only one fetch', async () => {
    let calls = 0;
    const fetchImpl = vi.fn(async () => {
      calls += 1;
      await new Promise((r) => setTimeout(r, 20));
      return new Response(JSON.stringify({ name: 'X' }), { status: 200 });
    }) as unknown as typeof fetch;
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl });
    client.enable();

    client.requestLookup('conn-1', '93.184.216.34');
    client.requestLookup('conn-1', '93.184.216.34'); // same connection, in flight already
    await new Promise((r) => setTimeout(r, 100));
    expect(calls).toBeLessThanOrEqual(1);
  }, 15_000);

  it('caches a successful RDAP result at the allocation\'s CIDR block, not just the queried /32 — the spec\'s "primary privacy control"', async () => {
    const fetchImpl = fakeFetch(200, {
      objectClassName: 'ip network',
      name: 'EXAMPLE-ORG',
      startAddress: '93.184.216.0',
      endAddress: '93.184.216.255',
    });
    const client = new EnrichmentClient({ dataDir: dir, fetchImpl });
    client.enable();

    const first = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-1', '93.184.216.34');
    await first;

    // A second, different address inside the same /24 must now resolve from
    // cache — i.e. without a second fetch — proving the entry was actually
    // keyed by the derived 93.184.216.0/24 block and not by the single
    // queried address.
    const callsBefore = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls.length;
    const second = new Promise((resolve) => client.once('result', resolve));
    client.requestLookup('conn-2', '93.184.216.200');
    const secondResult = (await second) as { enrichment: { org?: string; source?: string } };

    expect((fetchImpl as ReturnType<typeof vi.fn>).mock.calls.length).toBe(callsBefore);
    expect(secondResult.enrichment.source).toBe('cache');
    expect(secondResult.enrichment.org).toBe('EXAMPLE-ORG');
  }, 15_000);

  it('background mode dispatch order is not a deterministic function of input order (randomized, per spec §5)', () => {
    const client = new EnrichmentClient({ dataDir: dir });
    client.enableBackground();
    const dispatched: string[] = [];
    // Inject a spy on the internal enqueue path via the public surface: since
    // notifyObservedConnections is fire-and-forget, assert indirectly by
    // checking the queue was NOT fed in strict input order for a large-enough
    // sample. Implementer note: expose a test-only injection point (e.g. an
    // optional `random` in the constructor, mirroring RequestQueue's own
    // `random` option) so this can be asserted deterministically instead of
    // statistically — a statistical assertion here would be flaky.
    void dispatched;
    expect(true).toBe(true); // placeholder — see note above
  });
});
```

The last test is intentionally left as a stub with an explicit implementer note: **do not ship a placeholder `expect(true).toBe(true)` test.** Wire an injectable `random` option through `EnrichmentClient`'s constructor down to the internal `shuffle()` call (Task 4), then assert the resulting dispatch order against a known permutation for a fixed deterministic `random`, the same pattern already used for `RequestQueue`'s and `shuffle`'s own tests in Task 4. This is called out explicitly rather than left for the implementer to notice, since "background-mode ordering is randomized, not activity-ranked" is one of the spec's named required tests.

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-client.test.ts`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `lib/enrichment.ts`**

```typescript
// lib/enrichment.ts
import { EventEmitter } from 'node:events';
import { join } from 'node:path';
import { isPrivateOrReserved } from './enrichment/scope-filter';
import { EnrichmentCache } from './enrichment/cache';
import { QueryLog } from './enrichment/query-log';
import { RequestQueue, shuffle } from './enrichment/request-queue';
import { loadIpBootstrap, resolveRdapBaseForIp } from './enrichment/bootstrap';
import { RdapClient } from './enrichment/rdap-client';
import { extractIpRdap, buildEnrichmentEvent } from './enrichment-mapping';
import { EnrichmentRecord } from './enrichment/types';
import { ipToInt } from './enrichment/scope-filter';

export type EnrichmentMode = 'off' | 'on-demand' | 'background';

const CACHE_TTL_MS = 14 * 24 * 60 * 60 * 1000;
const NEGATIVE_TTL_MS = 60 * 60 * 1000;
const QUERY_LOG_RETENTION_DAYS = 30;

export const DISCLOSURE_TEXT =
  'Enabling ownership lookups sends the remote IP addresses this Mac talks to ' +
  'to public internet registries (ARIN, RIPE, APNIC, LACNIC, AFRINIC) over RDAP, ' +
  'so they learn that this Mac queried that address. Because results are cached ' +
  'for up to 14 days from one stable home IP, a registry could also infer this ' +
  'household\'s general usage rhythm and the breadth of destinations investigated ' +
  'over time — not just a single query. Lookups only happen for connections you ' +
  'select. Use "enrich clear" at any time to wipe the local cache and query log ' +
  'and turn this off.';

// Deliberately separately worded from DISCLOSURE_TEXT, not a shared template
// with a substituted clause — spec Components §1: background mode "requires
// its own separately-worded confirmation, since it multiplies the number of
// registries contacted and the correlatable query volume." Re-using the
// on-demand string here (even with a mode-specific sentence appended) would
// undercut the reason the spec asks for a second, distinct confirmation in
// the first place: that a person re-reading it should register it as a
// materially bigger step, not a checkbox variant of the same text.
export const DISCLOSURE_TEXT_BACKGROUND =
  'Background ownership lookups query EVERY connection currently visible in ' +
  'the table automatically — not just ones you select — in random order, on ' +
  'the same schedule as on-demand mode (one lookup at a time, several seconds ' +
  'apart). This multiplies how many remote addresses public internet registries ' +
  '(ARIN, RIPE, APNIC, LACNIC, AFRINIC) learn this Mac queried, and how much ' +
  'those registries can infer about this household\'s usage rhythm and the ' +
  'breadth of destinations investigated, compared to looking up connections ' +
  'one at a time. Results are still cached for up to 14 days. Use "enrich ' +
  'clear" at any time to wipe the local cache and query log and turn this off.';

export class EnrichmentClient extends EventEmitter {
  private mode: EnrichmentMode = 'off';
  private cache: EnrichmentCache;
  private queryLog: QueryLog;
  private queue = new RequestQueue();
  private rdap: RdapClient;
  private fetchImpl: typeof fetch;
  private inFlight = new Set<string>();
  private bootstrapPromise: ReturnType<typeof loadIpBootstrap> | null = null;
  private random: () => number;

  constructor(opts: { dataDir: string; fetchImpl?: typeof fetch; random?: () => number }) {
    super();
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.random = opts.random ?? Math.random;
    this.cache = new EnrichmentCache(join(opts.dataDir, 'cache.json'));
    this.cache.load();
    this.queryLog = new QueryLog(join(opts.dataDir, 'query-log.ndjson'));
    this.rdap = new RdapClient(this.fetchImpl);
    void this.queryLog.prune(QUERY_LOG_RETENTION_DAYS).catch(() => {});
    this.bootstrapCachePath = join(opts.dataDir, 'bootstrap-ipv4.json');
  }
  private bootstrapCachePath: string;

  getMode(): EnrichmentMode {
    return this.mode;
  }

  enable(): { disclosureText: string } {
    this.mode = 'on-demand';
    return { disclosureText: DISCLOSURE_TEXT };
  }

  enableBackground(): { disclosureText: string } {
    this.mode = 'background';
    return { disclosureText: DISCLOSURE_TEXT_BACKGROUND };
  }

  disable(): void {
    if (this.mode !== 'off') this.mode = 'off';
  }

  disableBackground(): void {
    if (this.mode === 'background') this.mode = 'on-demand';
  }

  async clear(): Promise<void> {
    await this.cache.clear();
    await this.queryLog.clear();
    this.mode = 'off';
  }

  requestLookup(connectionId: string, remoteAddr: string): void {
    if (this.mode === 'off') return;
    void this.lookup(connectionId, remoteAddr);
  }

  notifyObservedConnections(conns: Array<{ id: string; remoteAddr: string }>): void {
    if (this.mode !== 'background') return;
    // Randomized order, not activity-ranked — spec Components §5. `conns` is
    // whatever the caller currently has observed; it's the caller's job
    // (app/api/stream/route.ts, Task 9) to only pass connections not already
    // cached/in-flight, so this doesn't re-shuffle-and-requeue every tick.
    for (const conn of shuffle(conns, this.random)) {
      void this.lookup(conn.id, conn.remoteAddr);
    }
  }

  private async lookup(connectionId: string, remoteAddr: string): Promise<void> {
    if (isPrivateOrReserved(remoteAddr)) return;
    const flightKey = remoteAddr;
    if (this.inFlight.has(flightKey)) return;

    const cached = this.cache.getForIp(remoteAddr);
    if (cached && this.cache.isFresh(cached)) {
      await this.queryLog.append({ target: remoteAddr, endpoint: 'cache', cacheStatus: 'hit' });
      if (cached.record) {
        this.emit('result', buildEnrichmentEvent(connectionId, remoteAddr, { ...cached.record, source: 'cache' }));
      }
      return;
    }

    this.inFlight.add(flightKey);
    try {
      if (!this.bootstrapPromise) {
        this.bootstrapPromise = loadIpBootstrap(this.bootstrapCachePath, this.fetchImpl);
      }
      const services = await this.bootstrapPromise;
      const base = resolveRdapBaseForIp(remoteAddr, services);
      if (!base) {
        await this.queryLog.append({ target: remoteAddr, endpoint: 'bootstrap', cacheStatus: 'miss' });
        await this.cache.setNegative(cidrKeyFor(remoteAddr), NEGATIVE_TTL_MS);
        return;
      }
      const url = `${base.replace(/\/$/, '')}/ip/${remoteAddr}`;
      const result = await this.queue.enqueue(() => this.rdap.fetch(url));
      await this.queryLog.append({ target: remoteAddr, endpoint: new URL(url).host, cacheStatus: 'miss' });

      if (!result.ok) {
        // Stale-on-failure: leave any existing (expired) cache entry alone —
        // it's already what getForIp would return next time — rather than
        // overwriting it with a negative result. Only cache negative when
        // there is nothing at all yet.
        if (!cached) await this.cache.setNegative(cidrKeyFor(remoteAddr), NEGATIVE_TTL_MS);
        return;
      }

      const extracted = extractIpRdap(result.json);
      const record: EnrichmentRecord = { ...extracted, source: 'rdap', fetchedAt: new Date().toISOString() };
      const key = cidrKeyFromRdap(result.json) ?? cidrKeyFor(remoteAddr);
      await this.cache.setSuccess(key, record, CACHE_TTL_MS);
      this.emit('result', buildEnrichmentEvent(connectionId, remoteAddr, record));
    } finally {
      this.inFlight.delete(flightKey);
    }
  }
}

// Falls back to a /32 "block" (i.e. just this one address) only when the
// RDAP response doesn't carry a usable, exact CIDR for the allocation — the
// spec (Components §2) treats CIDR-block keying as "the primary privacy
// control," not an optional refinement, so cidrKeyFromRdap below is the
// normal path and this is genuinely a fallback, not the common case.
function cidrKeyFor(ip: string): string {
  return `${ip}/32`;
}

function intToIp(n: number): string {
  return [24, 16, 8, 0].map((shift) => (n >>> shift) & 0xff).join('.');
}

// Derives the allocation's actual CIDR block from an RDAP "ip network"
// response, so a single real query caches an entire /24 or /20 the way the
// spec's caching design assumes (Components §2: "RDAP responses cover whole
// allocations, so caching at the returned prefix means an entire /24 or /20
// of future connections resolves from cache after one real query"). Returns
// null — and lets the caller fall back to cidrKeyFor's per-address /32 key —
// only when the response doesn't carry a block we can derive exactly; it
// never guesses at a wider block than the data actually supports.
function cidrKeyFromRdap(json: unknown): string | null {
  const obj = json as {
    startAddress?: string;
    endAddress?: string;
    cidr0_cidrs?: Array<{ v4prefix?: string; v6prefix?: string; length?: number }>;
  } | null;
  if (!obj || typeof obj !== 'object') return null;

  // Prefer the RDAP cidr0 extension when present — it states the block
  // directly rather than requiring it to be inferred from a range.
  const cidrs = obj.cidr0_cidrs;
  if (Array.isArray(cidrs) && cidrs.length > 0) {
    const first = cidrs[0];
    const prefix = first?.v4prefix; // IPv6 (v6prefix) is out of scope for this IPv4-only cache-key helper
    if (typeof prefix === 'string' && typeof first?.length === 'number') {
      return `${prefix}/${first.length}`;
    }
  }

  // Otherwise, derive a CIDR from startAddress/endAddress — but only when
  // the range is an exact, power-of-two-aligned block (the common case for
  // RIR allocations). An irregular, non-CIDR-aligned range (legitimate in
  // RDAP; some allocations are described as a raw address range rather than
  // a single block) is not force-fit into a wider prefix that would
  // over-claim addresses outside the actual allocation — it falls through to
  // the /32 fallback instead.
  if (typeof obj.startAddress !== 'string' || typeof obj.endAddress !== 'string') return null;
  const start = ipToInt(obj.startAddress);
  const end = ipToInt(obj.endAddress);
  if (start === null || end === null || end < start) return null;

  for (let prefixLen = 32; prefixLen >= 0; prefixLen--) {
    const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
    const blockSize = prefixLen === 32 ? 1 : Math.pow(2, 32 - prefixLen);
    if ((start & mask) >>> 0 === start && start + blockSize - 1 === end) {
      return `${intToIp(start)}/${prefixLen}`;
    }
  }
  return null;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/enrichment-client.test.ts`
Expected: all tests PASS once the background-ordering test (Step 1's flagged placeholder) has been rewritten against a real injectable `random`, per the note above — do not leave the placeholder assertion in the committed test file.

- [ ] **Step 5: Commit**

```bash
git add lib/enrichment.ts lib/__tests__/enrichment-client.test.ts
git commit -m "feat(enrichment): add EnrichmentClient — opt-in gate, single-flight orchestration, disclosure text"
```

---

### Task 9: Wire/event integration — `docs/enrichment-protocol.md`, SSE relay, control + lookup API routes

**Files:**
- Create: `docs/enrichment-protocol.md`
- Modify: `app/api/stream/route.ts`
- Create: `app/api/enrichment/control/route.ts`
- Create: `app/api/enrichment/lookup/route.ts`
- Create: `lib/__tests__/enrichment-stream.test.ts`

**Interfaces:**
- Consumes: `EnrichmentClient` (Task 8).
- Produces: `GET /api/stream` now also emits `connection_enrichment` SSE lines; `POST /api/enrichment/control` `{action}`; `POST /api/enrichment/lookup` `{connectionId, remoteAddr}`. Consumed by `app/page.tsx` (Task 10).

- [ ] **Step 1: Write `docs/enrichment-protocol.md`**

```markdown
# Enrichment Protocol Reference

The relay→browser contract for ownership enrichment — a separate, newer
boundary from `docs/wire-protocol.md` (agent↔relay), which this feature does
not touch at all. Source of truth: `lib/enrichment.ts` (produces the event)
and `lib/enrichment-mapping.ts` / `lib/types.ts` (consume it).

## Transport

Reuses the existing `GET /api/stream` SSE connection — not a new port or
endpoint. `connection_enrichment` lines are interleaved with
`connection_update`/`packet`/`layer_update`/`connection_status` lines on the
same stream.

## `connection_enrichment`

Emitted only when enrichment is enabled and a lookup (cache hit or fresh
RDAP/WHOIS result) resolves for a connection currently on the wire.

```json
{
  "type": "connection_enrichment",
  "connectionId": "Tcp-192.168.1.10:51000-93.184.216.34:443",
  "remoteAddr": "93.184.216.34",
  "enrichment": {
    "org": "EXAMPLE-ORG",
    "asn": "AS15133",
    "asnOrg": "EDGECAST",
    "country": "US",
    "registrant": "Example Inc",
    "source": "rdap",
    "fetchedAt": "2026-08-28T00:00:00.000Z"
  }
}
```

Field notes:
- `asn`/`asnOrg` are **best-effort RIR registry data, not BGP-observed routing
  data** — legitimately absent for many address blocks. See the design spec's
  Scope section.
- `registrant` is populated only by the extended tier (domain-level lookup);
  absent for core-tier (IP-only) results.
- `source` is `'cache'` for a cache hit, `'rdap'`/`'whois'` for a fresh
  lookup that actually reached a registry.

## Control: `POST /api/enrichment/control`

```json
{ "action": "enable" }        // on-demand mode; response includes disclosureText
{ "action": "enable_background" } // background mode; response includes disclosureText
{ "action": "disable" }
{ "action": "disable_background" } // drops back to on-demand, not fully off
{ "action": "clear" }          // wipes cache + query log, disables
```

## On-demand trigger: `POST /api/enrichment/lookup`

```json
{ "connectionId": "Tcp-192.168.1.10:51000-93.184.216.34:443", "remoteAddr": "93.184.216.34" }
```

No-op (200, no lookup queued) if enrichment is currently disabled.
```

- [ ] **Step 2: Write the failing SSE integration test**

```typescript
// lib/__tests__/enrichment-stream.test.ts
import { describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';

// This test exercises the *route's* SSE-forwarding behavior in isolation by
// constructing a minimal fake EnrichmentClient (an EventEmitter with the
// same 'result'/'status' surface) rather than importing the real Next.js
// route module directly — Next.js route handlers close over module-level
// globals (`global.__agentClient`/`global.__enrichmentClient`) that are hard
// to reset between tests. Implementer note: if the actual route file's
// `GET()` is written in a way that's directly unit-testable (e.g. by
// accepting an injected client), prefer testing it directly instead of this
// reimplementation. Either way, the assertion below — a `connection_enrichment`
// event reaching an SSE `data:` line unchanged — is the one that must hold
// against the real route.

class FakeEnrichmentClient extends EventEmitter {}

function buildStreamHandler(client: FakeEnrichmentClient) {
  return () => {
    const encoder = new TextEncoder();
    let onResult: ((e: unknown) => void) | null = null;
    const stream = new ReadableStream({
      start(controller) {
        onResult = (event) => controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
        client.on('result', onResult);
      },
      cancel() {
        if (onResult) client.off('result', onResult);
      },
    });
    return new Response(stream);
  };
}

describe('connection_enrichment reaches the SSE stream unchanged', () => {
  it('forwards an EnrichmentClient "result" event as a data: line', async () => {
    const client = new FakeEnrichmentClient();
    const GET = buildStreamHandler(client);
    const response = GET();
    const reader = response.body!.getReader();

    const event = {
      type: 'connection_enrichment',
      connectionId: 'conn-1',
      remoteAddr: '93.184.216.34',
      enrichment: { org: 'EXAMPLE-ORG', source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' },
    };
    client.emit('result', event);

    const { value } = await reader.read();
    const text = new TextDecoder().decode(value);
    expect(text).toContain('data: ');
    expect(JSON.parse(text.replace('data: ', '').trim())).toEqual(event);
  });
});
```

- [ ] **Step 3: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-stream.test.ts`
Expected: PASS against the fake handler as written (it's self-contained) — this step's real value is Step 5's manual end-to-end check against the actual route. If the implementer instead makes `app/api/stream/route.ts`'s `GET` directly testable (preferred, per the note in Step 2), rewrite this test to import and call it directly, and it should FAIL until Step 4 wires the real `EnrichmentClient` in.

- [ ] **Step 4: Modify `app/api/stream/route.ts`**

```typescript
// app/api/stream/route.ts — additions alongside the existing AgentClient wiring
import { EnrichmentClient } from '@/lib/enrichment';
import { join } from 'node:path';

declare global {
  var __enrichmentClient: EnrichmentClient | undefined;
}

export function getEnrichmentClient(): EnrichmentClient {
  if (!global.__enrichmentClient) {
    global.__enrichmentClient = new EnrichmentClient({ dataDir: join(process.cwd(), '.data', 'enrichment') });
  }
  return global.__enrichmentClient;
}

// Inside GET()'s `start(controller)`, alongside the existing onEvent/onStatus registration:
//   const enrichmentClient = getEnrichmentClient();
//   let onResult: ((event: unknown) => void) | null = (event: unknown) => {
//     try {
//       controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
//     } catch {
//       // stream already closed/closing — ignore, same as the existing onEvent/onStatus handlers
//     }
//   };
//   enrichmentClient.on('result', onResult);
//
// And in cancel():
//   if (onResult) enrichmentClient.off('result', onResult);
//
// Also: when a connection_update event comes through the AgentClient's
// existing 'event' handler and the enrichment client is currently in
// background mode, feed the observed connection into it:
//   if (event && (event as { type?: string }).type === 'connection_update') {
//     const conn = (event as { connection?: { id?: string; remoteAddr?: string } }).connection;
//     if (conn?.id && conn?.remoteAddr && enrichmentClient.getMode() === 'background') {
//       enrichmentClient.notifyObservedConnections([{ id: conn.id, remoteAddr: conn.remoteAddr }]);
//     }
//   }
```

Fold these additions into the existing `onEvent`/`onStatus` registration block and the `start(controller)`/`cancel()` callbacks already in the file (Task 11 of `2026-08-26-live-capture-core.md` is the file this modifies) — don't duplicate the `ReadableStream` construction, extend it in place. `EnrichmentClient.notifyObservedConnections` (Task 8) already no-ops outside background mode and already filters private/reserved IPs internally, so this call site doesn't need its own guard beyond the mode check shown (avoiding a redundant `isPrivateOrReserved` check at two layers).

- [ ] **Step 5: Implement the control and lookup routes**

```typescript
// app/api/enrichment/control/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getEnrichmentClient } from '@/app/api/stream/route';

const VALID_ACTIONS = ['enable', 'enable_background', 'disable', 'disable_background', 'clear'] as const;

export async function POST(request: NextRequest) {
  const body = await request.json();
  if (!VALID_ACTIONS.includes(body.action)) {
    return NextResponse.json({ error: 'invalid action' }, { status: 400 });
  }
  const client = getEnrichmentClient();
  switch (body.action) {
    case 'enable':
      return NextResponse.json({ ok: true, ...client.enable() });
    case 'enable_background':
      return NextResponse.json({ ok: true, ...client.enableBackground() });
    case 'disable':
      client.disable();
      return NextResponse.json({ ok: true });
    case 'disable_background':
      client.disableBackground();
      return NextResponse.json({ ok: true });
    case 'clear':
      await client.clear();
      return NextResponse.json({ ok: true });
  }
}
```

```typescript
// app/api/enrichment/lookup/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getEnrichmentClient } from '@/app/api/stream/route';

export async function POST(request: NextRequest) {
  const body = await request.json();
  if (typeof body.connectionId !== 'string' || typeof body.remoteAddr !== 'string') {
    return NextResponse.json({ error: 'connectionId and remoteAddr are required' }, { status: 400 });
  }
  getEnrichmentClient().requestLookup(body.connectionId, body.remoteAddr);
  return NextResponse.json({ ok: true });
}
```

(Exporting `getEnrichmentClient` from the stream route so the other two routes share the exact same singleton — mirrors how `global.__agentClient` is already shared across `stream`/`control` today, just made explicit via an export instead of each route re-deriving it from the bare global.)

- [ ] **Step 6: Run tests, then manually verify against the real routes**

Run: `npx vitest run lib/__tests__/enrichment-stream.test.ts`
Expected: PASS.

Run: `npm run dev`, then in another terminal:
```bash
curl -X POST http://localhost:3000/api/enrichment/control -H 'Content-Type: application/json' -d '{"action":"enable"}'
curl -X POST http://localhost:3000/api/enrichment/lookup -H 'Content-Type: application/json' -d '{"connectionId":"test","remoteAddr":"93.184.216.34"}'
curl -N http://localhost:3000/api/stream | grep connection_enrichment
```
Expected: the control call returns `{"ok":true,"disclosureText":"..."}`; within a few seconds (queue spacing) the stream prints a `connection_enrichment` line for `93.184.216.34` (a real outbound RDAP call happens here — this is the one deliberate live-network check in this plan, analogous to Task 12 Step 6 in the live-capture-core plan hitting a real interface; every automated test stays offline per this plan's Global Constraints).

- [ ] **Step 7: Commit**

```bash
git add docs/enrichment-protocol.md app/api/stream/route.ts app/api/enrichment/control/route.ts app/api/enrichment/lookup/route.ts lib/__tests__/enrichment-stream.test.ts
git commit -m "feat(enrichment): relay connection_enrichment over SSE; add control/lookup API routes"
```

---

### Task 10: UI surface — Ownership section, command-bar controls, disclosure display

**Files:**
- Modify: `components/ConnectionsView.tsx`
- Modify: `app/page.tsx`
- Modify: `components/CommandLineBar.tsx`
- Modify: `package.json` (add `@testing-library/react`, `@testing-library/dom`, `jsdom` devDependencies)
- Create: `lib/__tests__/connections-view-ownership.test.tsx`

**Interfaces:**
- Consumes: `NetworkConnection.enrichment` (Task 7), `POST /api/enrichment/control`/`lookup` (Task 9), `applyEnrichmentEvent` (Task 7).
- Produces: the Ownership section state machine described in spec Components §7 (five states); `enrich on/off/background on/off/clear` command-bar commands.

- [ ] **Step 1: Add test tooling**

```bash
npm install --save-exact --save-dev @testing-library/react@16.3.0 @testing-library/dom@10.4.0 jsdom@25.0.1
```

- [ ] **Step 2: Write the failing component test**

```typescript
// lib/__tests__/connections-view-ownership.test.tsx
// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ConnectionsView } from '../../components/ConnectionsView';
import { THEMES } from '../osi-engine';
import { NetworkConnection } from '../types';

const theme = THEMES.sophisticated;

function baseConn(overrides: Partial<NetworkConnection> = {}): NetworkConnection {
  return {
    id: 'conn-1', protocol: 'HTTPS/TLS', appLayerProtocol: 'HTTPS/TLS', transportProtocol: 'TCP',
    osiStack: 'x', localAddr: '192.168.1.10', localPort: 51000, remoteAddr: '93.184.216.34', remotePort: 443,
    processName: 'Safari', pid: 1234, rxSpeed: 0, txSpeed: 0, rxBytesTotal: 0, txBytesTotal: 0,
    latencyMs: 0, packetLoss: 0, status: 'ESTABLISHED', encryption: 'TLS', sparkline: [],
    ...overrides,
  };
}

describe('ConnectionsView Ownership section', () => {
  it('shows "Enrichment disabled" when enrichmentMode is off', () => {
    render(<ConnectionsView connections={[baseConn()]} theme={theme} enrichmentMode="off" onRequestLookup={() => {}} />);
    expect(screen.getByText(/enrichment disabled/i)).toBeInTheDocument();
  });

  it('shows "Not yet looked up" for a selected connection with no enrichment field, mode on', () => {
    render(<ConnectionsView connections={[baseConn()]} theme={theme} enrichmentMode="on-demand" onRequestLookup={() => {}} />);
    expect(screen.getByText(/not yet looked up/i)).toBeInTheDocument();
  });

  it('shows org/ASN/as-of when enrichment data is present', () => {
    render(
      <ConnectionsView
        connections={[baseConn({ enrichment: { org: 'EXAMPLE-ORG', asn: 'AS15133', source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' } })]}
        theme={theme}
        enrichmentMode="on-demand"
        onRequestLookup={() => {}}
      />,
    );
    expect(screen.getByText(/EXAMPLE-ORG/)).toBeInTheDocument();
    expect(screen.getByText(/AS15133/)).toBeInTheDocument();
  });

  it('shows a blank/"—" ASN, not an error, when the registry record has no ASN (best-effort field)', () => {
    render(
      <ConnectionsView
        connections={[baseConn({ enrichment: { org: 'EXAMPLE-ORG', source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' } })]}
        theme={theme}
        enrichmentMode="on-demand"
        onRequestLookup={() => {}}
      />,
    );
    expect(screen.queryByText(/error/i)).not.toBeInTheDocument();
  });

  it('renders org/registrant strings as plain text, never via dangerouslySetInnerHTML', () => {
    const hostileOrg = '<img src=x onerror="window.__pwned=true">';
    render(
      <ConnectionsView
        connections={[baseConn({ enrichment: { org: hostileOrg, source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' } })]}
        theme={theme}
        enrichmentMode="on-demand"
        onRequestLookup={() => {}}
      />,
    );
    // If this were rendered as raw HTML, there would be no literal text node
    // containing the tag characters — they'd have been parsed into a DOM
    // element instead. Finding the literal string proves JSX text
    // interpolation (auto-escaped), not an HTML sink.
    expect(screen.getByText(hostileOrg)).toBeInTheDocument();
    expect(document.querySelector('img[src="x"]')).toBeNull();
  });
});
```

- [ ] **Step 3: Run to verify failure**

Run: `npx vitest run lib/__tests__/connections-view-ownership.test.tsx`
Expected: FAIL — `ConnectionsView` doesn't yet accept `enrichmentMode`/`onRequestLookup` props or render an Ownership section.

- [ ] **Step 4: Add the Ownership section to `components/ConnectionsView.tsx`**

Extend the props and add a new section inside the existing "Selected Connection" panel (after the OSI Stack Path block, same `p-3.5 rounded border` card):

```typescript
// components/ConnectionsView.tsx — prop additions
interface ConnectionsViewProps {
  connections: NetworkConnection[];
  theme: ThemeConfig;
  enrichmentMode?: 'off' | 'on-demand' | 'background'; // default 'off' if omitted
  onRequestLookup?: (connectionId: string, remoteAddr: string) => void;
}
```

```tsx
{/* Ownership section — appended inside the existing selected-connection card, after the OSI Stack Path block */}
<div className="pt-2 border-t border-slate-800 space-y-1.5">
  <div className="text-[11px] font-bold text-slate-400 uppercase">Ownership</div>
  {(!enrichmentMode || enrichmentMode === 'off') ? (
    <div className="text-slate-500">Enrichment disabled — enable with <code>enrich on</code> in the command bar.</div>
  ) : !selectedConn.enrichment ? (
    <button
      onClick={() => onRequestLookup?.(selectedConn.id, selectedConn.remoteAddr)}
      className="px-2 py-1 rounded text-[11px] font-bold bg-slate-800 hover:bg-slate-700 text-slate-200"
    >
      Not yet looked up — click to look up
    </button>
  ) : (
    <div className="text-slate-300">
      Org: {selectedConn.enrichment.org ?? '—'} · ASN: {selectedConn.enrichment.asn ?? '—'}
      {selectedConn.enrichment.registrant && <> · Registrant: {selectedConn.enrichment.registrant}</>}
      <span className="text-slate-500"> · as of {selectedConn.enrichment.fetchedAt}</span>
    </div>
  )}
</div>
```

(The "Looking up…" and "Unavailable" states from the spec's five-state list are driven by two additional pieces of client state this task also wires in `app/page.tsx` — a `lookingUpIds: Set<string>` set while a lookup is in flight for a connection, cleared on the matching `connection_enrichment` event or a timeout, and an `unavailableIds: Set<string>` set when a lookup completes with no usable `enrichment` object returned within a reasonable window. Thread both down as additional optional props and branch on them ahead of the `!selectedConn.enrichment` check above; the exact timeout/unavailable-detection wiring is an `app/page.tsx` concern, covered in Step 5.)

- [ ] **Step 5: Wire `app/page.tsx`**

Add state and handlers:

```typescript
const [enrichmentMode, setEnrichmentMode] = useState<'off' | 'on-demand' | 'background'>('off');
const [disclosureText, setDisclosureText] = useState<string | null>(null);

const enrichmentControl = async (action: string) => {
  const res = await fetch('/api/enrichment/control', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  });
  const body = await res.json();
  if (body.disclosureText) setDisclosureText(body.disclosureText); // re-shown on every enable, per spec §1
  if (action === 'enable') setEnrichmentMode('on-demand');
  if (action === 'enable_background') setEnrichmentMode('background');
  if (action === 'disable') setEnrichmentMode('off');
  if (action === 'disable_background') setEnrichmentMode('on-demand');
  if (action === 'clear') setEnrichmentMode('off');
};

const requestLookup = (connectionId: string, remoteAddr: string) => {
  fetch('/api/enrichment/lookup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ connectionId, remoteAddr }),
  });
};
```

In the SSE `onmessage` handler, add:

```typescript
if (data.type === 'connection_enrichment') {
  setConnections((prev) => applyEnrichmentEvent(prev, data));
}
```

(import `applyEnrichmentEvent` from `@/lib/enrichment-mapping`)

In `handleExecuteCommand`, add branches:

```typescript
} else if (cmdStr.toLowerCase() === 'enrich on') {
  enrichmentControl('enable');
} else if (cmdStr.toLowerCase() === 'enrich off') {
  enrichmentControl('disable');
} else if (cmdStr.toLowerCase() === 'enrich background on') {
  enrichmentControl('enable_background');
} else if (cmdStr.toLowerCase() === 'enrich background off') {
  enrichmentControl('disable_background');
} else if (cmdStr.toLowerCase() === 'enrich clear') {
  enrichmentControl('clear');
```

(Note: `handleExecuteCommand` currently splits `cmdStr` on spaces and lowercases just `mainCmd`/`arg1` — since `enrich background on/off` is a three-token command, either extend the parsing to check `parts[1] === 'background'` and branch on `parts[2]`, or match against the full lowercased `cmdStr` as shown above; either is fine, but don't silently only support two-token commands and leave `enrich background on` unreachable.)

Render the disclosure text (simple dismissible banner, not a full modal — consistent with the existing "agent not connected" banner's styling) whenever `disclosureText` is non-null, with a close button that sets it back to `null`. Pass `enrichmentMode` and `requestLookup` down to `<ConnectionsView />`.

- [ ] **Step 6: Add command-bar help text**

In `components/CommandLineBar.tsx`'s help grid, add:

```tsx
<div><strong className="text-emerald-400">enrich on / off</strong>: Toggle on-demand ownership lookups (RDAP)</div>
<div><strong className="text-emerald-400">enrich background on / off</strong>: Toggle whole-table background lookups</div>
<div><strong className="text-emerald-400">enrich clear</strong>: Wipe enrichment cache + query log, disable</div>
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/connections-view-ownership.test.tsx`
Expected: all tests PASS.

Run: `npx vitest run` (full suite) and `npm run build`
Expected: no regressions.

- [ ] **Step 8: Commit**

```bash
git add components/ConnectionsView.tsx app/page.tsx components/CommandLineBar.tsx package.json package-lock.json lib/__tests__/connections-view-ownership.test.tsx
git commit -m "feat(enrichment): add Ownership UI section, command-bar controls, and disclosure display"
```

---

### Task 11: Repo-wide HTML-escaping regression test

**Files:**
- Create: `lib/__tests__/no-dangerous-html.test.ts`

**Interfaces:**
- Produces: a Vitest test that fails the suite if any file under `app/`, `components/`, or `lib/` uses `dangerouslySetInnerHTML` or `.innerHTML =` — the two ways React's default JSX escaping could be bypassed for the RDAP/WHOIS org/ASN/registrant strings this sub-project newly renders (org, asnOrg, registrant — all attacker-influenceable third-party text, same posture 1a already established for `processName`/`pkt.summary`/etc).

This is the same regression-test shape the (not-yet-executed-in-this-tree) `2026-08-26-secure-lan-access.md` plan's Task 4 describes for its own scope — written independently here since that plan hasn't landed in this worktree yet and this sub-project needs its own coverage regardless of when/whether that one lands. If both land, this test and that one converge on an identical file (harmless — a second PR touching the same path will just find the file already present and skip re-adding it).

- [ ] **Step 1: Confirm the current audit finding (no code change yet)**

Run:
```bash
grep -rn "dangerouslySetInnerHTML\|\.innerHTML\s*=" app/ components/ lib/ 2>/dev/null
```
Expected: no matches, including after Task 10's Ownership section — it renders `org`/`asn`/`registrant` via plain `{...}` JSX interpolation (see Task 10 Step 4).

- [ ] **Step 2: Write the regression test**

```typescript
// lib/__tests__/no-dangerous-html.test.ts
import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SCAN_DIRS = ['app', 'components', 'lib'];
const DANGEROUS_PATTERN = /dangerouslySetInnerHTML|\.innerHTML\s*=/;

function collectSourceFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      if (entry === '__tests__' || entry === 'node_modules') continue;
      files.push(...collectSourceFiles(full));
    } else if (/\.(tsx?|jsx?)$/.test(entry)) {
      files.push(full);
    }
  }
  return files;
}

describe('network- and registry-sourced strings are never rendered as raw HTML', () => {
  it('no source file under app/, components/, or lib/ uses dangerouslySetInnerHTML or .innerHTML', () => {
    const offenders: string[] = [];
    for (const dir of SCAN_DIRS) {
      for (const file of collectSourceFiles(dir)) {
        const content = readFileSync(file, 'utf-8');
        if (DANGEROUS_PATTERN.test(content)) offenders.push(file);
      }
    }
    expect(offenders).toEqual([]);
  });
});
```

- [ ] **Step 3: Run it and verify it passes**

Run: `npx vitest run lib/__tests__/no-dangerous-html.test.ts`
Expected: PASS.

- [ ] **Step 4: Red-green check — prove the test actually catches a violation**

```bash
echo 'export const x = () => <div dangerouslySetInnerHTML={{__html: "x"}} />;' >> components/ConnectionsView.tsx
npx vitest run lib/__tests__/no-dangerous-html.test.ts; echo "exit code: $?"
git checkout -- components/ConnectionsView.tsx
npx vitest run lib/__tests__/no-dangerous-html.test.ts
```
Expected: first run FAILs listing `components/ConnectionsView.tsx`; after revert, PASSes again.

- [ ] **Step 5: Commit**

```bash
git add lib/__tests__/no-dangerous-html.test.ts
git commit -m "Add repo-wide HTML-escaping regression test covering enrichment-rendered strings"
```

---

## Extended tier (Tasks 12–15)

Everything below is additive on top of core tier — no core-tier file from Tasks 1–11 needs to change shape, only to gain new call sites. Ship Tasks 1–11 first; these can land in the same PR/branch or a follow-up one, per the spec's phase-boundary note (Scope: "not an escape hatch").

---

### Task 12: Reverse DNS resolution

**Files:**
- Create: `lib/enrichment/reverse-dns.ts`
- Create: `lib/__tests__/enrichment-reverse-dns.test.ts`
- Modify: `lib/enrichment.ts` (wire the extended-tier trigger)

**Interfaces:**
- Produces:
  ```typescript
  export async function reverseDnsLookup(ip: string, opts?: { timeoutMs?: number; resolveFn?: typeof import('node:dns').promises.reverse }): Promise<string | null>;
  ```
  Consumed by `lib/enrichment.ts`'s extended-tier lookup path (this task's Step 5) to populate `remoteHostname` before attempting a domain RDAP/WHOIS lookup.

- [x] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/enrichment-reverse-dns.test.ts
import { describe, expect, it, vi } from 'vitest';
import { reverseDnsLookup } from '../enrichment/reverse-dns';

describe('reverseDnsLookup', () => {
  it('returns the resolved hostname on success', async () => {
    const resolveFn = vi.fn(async () => ['example.com']);
    const result = await reverseDnsLookup('93.184.216.34', { resolveFn: resolveFn as never });
    expect(result).toBe('example.com');
  });

  it('returns null (not a thrown error) when the resolver has no PTR record', async () => {
    const resolveFn = vi.fn(async () => { throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' }); });
    const result = await reverseDnsLookup('93.184.216.34', { resolveFn: resolveFn as never });
    expect(result).toBeNull();
  });

  it('times out and returns null rather than hanging, when given a short timeout', async () => {
    const resolveFn = vi.fn(() => new Promise<string[]>(() => {})); // never resolves
    const result = await reverseDnsLookup('93.184.216.34', { timeoutMs: 20, resolveFn: resolveFn as never });
    expect(result).toBeNull();
  });
});
```

- [x] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-reverse-dns.test.ts`
Expected: FAIL — module doesn't exist.

- [x] **Step 3: Implement `lib/enrichment/reverse-dns.ts`**

```typescript
// lib/enrichment/reverse-dns.ts
import { promises as dns } from 'node:dns';

export async function reverseDnsLookup(
  ip: string,
  opts: { timeoutMs?: number; resolveFn?: typeof dns.reverse } = {},
): Promise<string | null> {
  const resolveFn = opts.resolveFn ?? dns.reverse;
  const timeoutMs = opts.timeoutMs ?? 10_000;

  try {
    const hostnames = await Promise.race([
      resolveFn(ip),
      new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error('reverse-dns timeout')), timeoutMs)),
    ]);
    return hostnames[0] ?? null;
  } catch {
    // Any failure (no PTR record, resolver error, timeout) is a normal,
    // expected outcome, not an error to surface — spec's Error handling
    // section: "remoteHostname stays unpopulated ... not surfaced as an error".
    return null;
  }
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/enrichment-reverse-dns.test.ts`
Expected: all tests PASS.

- [x] **Step 5: Wire the extended-tier trigger into `lib/enrichment.ts`**

In `EnrichmentClient`'s private `lookup()` method, after a successful core-tier RDAP result (or in parallel — implementer's call, but document the choice), add: if `record.org` resolved successfully and no domain-level data exists yet, call `reverseDnsLookup(remoteAddr)`; if it resolves, proceed to Task 13/14's domain RDAP/WHOIS chain (added in those tasks) and merge `registrant` onto the same `EnrichmentRecord` before emitting `'result'`. This task only adds the reverse-DNS step itself and a `remoteHostname` result field passthrough — the domain-RDAP call site is added in Task 13, so at the end of *this* task `lookup()` resolves a hostname but doesn't yet do anything further with it beyond making it available. Leave a `// TODO(Task 13): domain RDAP lookup goes here` comment marking the exact insertion point so Task 13's diff is a small, obvious addition rather than a rewrite.

- [x] **Step 6: Commit**

```bash
git add lib/enrichment/reverse-dns.ts lib/__tests__/enrichment-reverse-dns.test.ts lib/enrichment.ts
git commit -m "feat(enrichment): add reverse-DNS resolution (extended tier, step 1 of 3)"
```

---

### Task 13: Domain RDAP bootstrap + registrar referral allowlist (response-controlled SSRF hardening)

**Files:**
- Modify: `lib/enrichment/bootstrap.ts` (add domain/TLD matching)
- Create: `lib/enrichment/referral-allowlist.ts`
- Modify: `lib/enrichment-mapping.ts` (add `extractDomainRdap`, org-only field extraction)
- Modify: `lib/enrichment/rdap-client.ts` (optional referral-following, gated by the allowlist)
- Create: `lib/__tests__/enrichment-referral-allowlist.test.ts`
- Modify: `lib/__tests__/enrichment-bootstrap.test.ts` (add domain-bootstrap cases)
- Modify: `lib/__tests__/enrichment-mapping.test.ts` (add `extractDomainRdap` cases)

**Interfaces:**
- Produces:
  ```typescript
  // lib/enrichment/bootstrap.ts additions
  export interface DomainBootstrapService { tlds: string[]; url: string }
  export function parseDomainBootstrap(json: unknown): DomainBootstrapService[];
  export function resolveRdapBaseForDomain(domain: string, services: DomainBootstrapService[]): string | null;
  export async function loadDomainBootstrap(cachePath: string, fetchImpl: typeof fetch, ttlMs?: number): Promise<DomainBootstrapService[]>;

  // lib/enrichment/referral-allowlist.ts
  export function isAllowedReferralHost(url: string): boolean;

  // lib/enrichment-mapping.ts addition
  export function extractDomainRdap(json: unknown): { registrant?: string; country?: string }; // org-level fields ONLY
  ```

- [x] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/enrichment-referral-allowlist.test.ts
import { describe, expect, it } from 'vitest';
import { isAllowedReferralHost } from '../enrichment/referral-allowlist';

describe('isAllowedReferralHost', () => {
  it('allows a known registrar RDAP host', () => {
    expect(isAllowedReferralHost('https://rdap.verisign.com/com/v1/domain/example.com')).toBe(true);
  });
  it('rejects a host not on the allowlist', () => {
    expect(isAllowedReferralHost('https://attacker.example/rdap/')).toBe(false);
  });
  it('rejects a referral pointing at a loopback/internal address — the realistic SSRF target', () => {
    expect(isAllowedReferralHost('http://127.0.0.1:9990/pause')).toBe(false);
    expect(isAllowedReferralHost('http://localhost:9990/')).toBe(false);
    expect(isAllowedReferralHost('http://[::1]:9990/')).toBe(false);
  });
});
```

Add to `lib/__tests__/enrichment-bootstrap.test.ts`:

```typescript
import { loadDomainBootstrap, parseDomainBootstrap, resolveRdapBaseForDomain } from '../enrichment/bootstrap';

const FIXTURE_DNS_BOOTSTRAP = {
  services: [
    [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
    [['org'], ['https://rdap.publicinterestregistry.org/rdap/']],
  ],
};

describe('domain bootstrap (extended tier)', () => {
  it('routes to the correct registry base URL by TLD', () => {
    const services = parseDomainBootstrap(FIXTURE_DNS_BOOTSTRAP);
    expect(resolveRdapBaseForDomain('example.com', services)).toBe('https://rdap.verisign.com/com/v1/');
    expect(resolveRdapBaseForDomain('example.org', services)).toBe('https://rdap.publicinterestregistry.org/rdap/');
    expect(resolveRdapBaseForDomain('example.xyz', services)).toBeNull();
  });
});
```

Add to `lib/__tests__/enrichment-mapping.test.ts`:

```typescript
import { extractDomainRdap } from '../enrichment-mapping';

describe('extractDomainRdap — registrant extraction drops personal/vCard/postal fields', () => {
  it('extracts only organization-level fields, never name/email/phone/address', () => {
    const rdapDomainResponse = {
      objectClassName: 'domain',
      entities: [
        {
          roles: ['registrant'],
          vcardArray: ['vcard', [
            ['version', {}, 'text', '4.0'],
            ['fn', {}, 'text', 'Jane Doe'],                 // personal name — must NOT leak
            ['org', {}, 'text', 'Example Registrant Org'],   // org — should be extracted
            ['email', {}, 'text', 'jane@example.com'],       // personal — must NOT leak
            ['tel', {}, 'text', '+1.5551234567'],            // personal — must NOT leak
            ['adr', {}, 'text', ['', '', '123 Main St', 'Anytown', 'CA', '99999', 'US']], // postal — must NOT leak
          ]],
        },
      ],
    };
    const result = extractDomainRdap(rdapDomainResponse);
    expect(result.registrant).toBe('Example Registrant Org');
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain('Jane Doe');
    expect(serialized).not.toContain('jane@example.com');
    expect(serialized).not.toContain('555');
    expect(serialized).not.toContain('123 Main St');
  });
});
```

- [x] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-referral-allowlist.test.ts lib/__tests__/enrichment-bootstrap.test.ts lib/__tests__/enrichment-mapping.test.ts`
Expected: the new/added cases FAIL — the new exports don't exist yet.

- [x] **Step 3: Implement `lib/enrichment/referral-allowlist.ts`**

```typescript
// lib/enrichment/referral-allowlist.ts

// Small, maintained allowlist of registrar RDAP hosts for thin gTLDs that
// require a registry->registrar referral (spec Scope, "extended tier").
// Deliberately kept small — each addition is a reviewed, deliberate change,
// not grown opportunistically. A referral to any other host, including any
// loopback/private address, resolves to "unavailable" rather than being
// followed (see lib/enrichment/rdap-client.ts's referral-following code,
// Step 4 below).
const REGISTRAR_RDAP_ALLOWLIST = new Set([
  'rdap.verisign.com',
  'rdap.publicinterestregistry.org',
]);

export function isAllowedReferralHost(url: string): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  return REGISTRAR_RDAP_ALLOWLIST.has(host);
}
```

- [x] **Step 4: Extend `lib/enrichment/bootstrap.ts` with domain routing**

```typescript
// lib/enrichment/bootstrap.ts additions

export interface DomainBootstrapService {
  tlds: string[];
  url: string;
}

// Domain-name RDAP bootstrap uses a genuinely different set of hosts than
// the IP one (registries like Verisign, PIR, etc.) — a separate allowlist
// from KNOWN_RIR_HOSTS is deliberate, not an oversight (spec Scope: "an
// earlier draft ... was a factual error" about conflating the two).
const KNOWN_DOMAIN_REGISTRY_HOSTS = new Set([
  'rdap.verisign.com',
  'rdap.publicinterestregistry.org',
  // extend deliberately, same posture as KNOWN_RIR_HOSTS
]);

export function parseDomainBootstrap(json: unknown): DomainBootstrapService[] {
  const obj = json as { services?: unknown } | null;
  if (!obj || !Array.isArray(obj.services)) return [];
  const out: DomainBootstrapService[] = [];
  for (const entry of obj.services) {
    if (!Array.isArray(entry) || entry.length < 2) continue;
    const [tlds, urls] = entry;
    if (!Array.isArray(tlds) || !Array.isArray(urls)) continue;
    const url = urls.find((u: unknown): u is string => typeof u === 'string' && u.startsWith('https://'));
    if (!url) continue;
    let host: string;
    try { host = new URL(url).host; } catch { continue; }
    if (!KNOWN_DOMAIN_REGISTRY_HOSTS.has(host)) continue;
    out.push({ tlds: tlds.filter((t: unknown): t is string => typeof t === 'string').map((t) => t.toLowerCase()), url });
  }
  return out;
}

export function resolveRdapBaseForDomain(domain: string, services: DomainBootstrapService[]): string | null {
  const tld = domain.toLowerCase().split('.').pop() ?? '';
  for (const service of services) {
    if (service.tlds.includes(tld)) return service.url;
  }
  return null;
}

const IANA_DNS_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

export async function loadDomainBootstrap(
  cachePath: string,
  fetchImpl: typeof fetch,
  ttlMs: number = 30 * 24 * 60 * 60 * 1000,
): Promise<DomainBootstrapService[]> {
  const cached = readJsonIfExists<{ fetchedAt: number; services: DomainBootstrapService[] }>(cachePath);
  if (cached && Date.now() - cached.fetchedAt < ttlMs) return cached.services;

  const response = await fetchImpl(IANA_DNS_BOOTSTRAP_URL, { redirect: 'manual' });
  const services = parseDomainBootstrap(await response.json());
  await atomicWriteJson(cachePath, { fetchedAt: Date.now(), services });
  return services;
}
```

(`readJsonIfExists`/`atomicWriteJson` are already imported at the top of this file from Task 5 — no new import needed beyond what's already there.)

- [x] **Step 5: Add `extractDomainRdap` to `lib/enrichment-mapping.ts`**

```typescript
// lib/enrichment-mapping.ts addition

/**
 * Extracts ONLY organization-level registrant fields from a domain RDAP
 * response's vCard entities — deliberately never reads `fn` (personal name),
 * `email`, `tel`, or `adr` (postal address). This is a safety property of
 * *which vCard keys this function ever looks at*, not a redaction step
 * applied after the fact — there's no code path here that could
 * accidentally forward a personal field, because the personal fields are
 * never read into a variable in the first place.
 */
export function extractDomainRdap(json: unknown): { registrant?: string; country?: string } {
  try {
    const obj = json as Record<string, unknown>;
    if (!obj || typeof obj !== 'object') return {};
    const entities = Array.isArray(obj.entities) ? obj.entities : [];
    for (const entity of entities) {
      const roles = (entity as Record<string, unknown>)?.roles;
      if (!Array.isArray(roles) || !roles.includes('registrant')) continue;
      const vcardArray = (entity as Record<string, unknown>)?.vcardArray;
      if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) continue;
      const fields = vcardArray[1] as unknown[];
      const orgField = fields.find((f) => Array.isArray(f) && f[0] === 'org');
      if (Array.isArray(orgField) && typeof orgField[3] === 'string') {
        return { registrant: asString(orgField[3]) };
      }
    }
    return {};
  } catch {
    return {};
  }
}
```

- [x] **Step 6: Add referral-following to `lib/enrichment/rdap-client.ts`**

Add an optional second step to `RdapClient#fetch` (or a new `fetchWithReferral` method — implementer's choice, but keep the base `fetch` unchanged so Tasks 6/8's existing tests and call sites don't need to change): after a successful response, inspect `json.links` (RDAP `rel: 'related'` entries, per RFC 7484-style referral) and, separately, `json.port43`/`json.notices[].links` per the spec. For each candidate URL found, call `isAllowedReferralHost(url)`; if true, issue a second `fetch(url)` through the same hardened path (timeout/size-cap/backoff apply identically) and prefer its result; if false, treat the lookup as `unavailable` for registrant purposes without ever dialing that host. Add tests mirroring Task 6's structure:

```typescript
// addition to lib/__tests__/enrichment-rdap-client.test.ts (or a new enrichment-rdap-referral.test.ts)
it('follows a referral link only if its host is on the allowlist', async () => {
  const registryResponse = { objectClassName: 'domain', links: [{ rel: 'related', href: 'https://rdap.verisign.com/com/v1/domain/example.com' }] };
  const registrarResponse = { objectClassName: 'domain', entities: [] };
  const calls: string[] = [];
  const fetchImpl = (async (url: string) => {
    calls.push(url);
    if (calls.length === 1) return new Response(JSON.stringify(registryResponse), { status: 200 });
    return new Response(JSON.stringify(registrarResponse), { status: 200 });
  }) as typeof fetch;

  const client = new RdapClient(fetchImpl);
  await client.fetchWithReferral('https://rdap.example-registry.test/domain/example.com');
  expect(calls).toContain('https://rdap.verisign.com/com/v1/domain/example.com');
});

it('never dials a referral to a non-allowlisted host, including a loopback address', async () => {
  const registryResponse = { objectClassName: 'domain', links: [{ rel: 'related', href: 'http://127.0.0.1:9990/pause' }] };
  const calls: string[] = [];
  const fetchImpl = (async (url: string) => {
    calls.push(url);
    return new Response(JSON.stringify(registryResponse), { status: 200 });
  }) as typeof fetch;

  const client = new RdapClient(fetchImpl);
  const result = await client.fetchWithReferral('https://rdap.example-registry.test/domain/example.com');
  expect(calls).toEqual(['https://rdap.example-registry.test/domain/example.com']); // only the first call — the loopback referral was never dialed
  expect(result).toMatchObject({ referralFollowed: false });
});
```

- [x] **Step 7: Run all affected tests to verify they pass**

Run: `npx vitest run lib/__tests__/enrichment-referral-allowlist.test.ts lib/__tests__/enrichment-bootstrap.test.ts lib/__tests__/enrichment-mapping.test.ts lib/__tests__/enrichment-rdap-client.test.ts`
Expected: all PASS.

- [x] **Step 8: Commit**

```bash
git add lib/enrichment/bootstrap.ts lib/enrichment/referral-allowlist.ts lib/enrichment-mapping.ts lib/enrichment/rdap-client.ts lib/__tests__/enrichment-referral-allowlist.test.ts lib/__tests__/enrichment-bootstrap.test.ts lib/__tests__/enrichment-mapping.test.ts lib/__tests__/enrichment-rdap-client.test.ts
git commit -m "feat(enrichment): add domain RDAP bootstrap + registrar referral allowlist (extended tier, step 2 of 3)"
```

---

### Task 14: Legacy WHOIS fallback client

**Files:**
- Create: `lib/enrichment/whois-client.ts`
- Modify: `lib/enrichment-mapping.ts` (add `extractWhois`)
- Create: `lib/__tests__/enrichment-whois-client.test.ts`
- Modify: `lib/__tests__/enrichment-mapping.test.ts` (add `extractWhois` cases)

**Interfaces:**
- Produces:
  ```typescript
  export interface WhoisAllowlistEntry {
    matches: (target: string) => boolean;
    host: string;
    port?: number; // default 43
    fieldPatterns: Record<string, RegExp>; // ONLY org-level field names — see Step 5
  }
  export const WHOIS_ALLOWLIST: WhoisAllowlistEntry[]; // capped at 5 entries
  export function queryWhois(entry: WhoisAllowlistEntry, target: string, opts?: { timeoutMs?: number }): Promise<string | null>;

  // lib/enrichment-mapping.ts addition
  export function extractWhois(text: string, entry: WhoisAllowlistEntry): { org?: string; registrant?: string };
  ```

- [x] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/enrichment-whois-client.test.ts
import { describe, expect, it, afterEach } from 'vitest';
import net from 'node:net';
import { queryWhois, WHOIS_ALLOWLIST } from '../enrichment/whois-client';

describe('queryWhois', () => {
  let server: net.Server;
  afterEach(() => server?.close());

  it('returns response text under the 64KB cap', async () => {
    server = net.createServer((socket) => {
      socket.on('data', () => socket.end('Registrant Organization: Example Org\r\n'));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as net.AddressInfo).port;

    const entry = { matches: () => true, host: '127.0.0.1', port, fieldPatterns: {} };
    const text = await queryWhois(entry, 'example.test');
    expect(text).toContain('Example Org');
  });

  it('aborts and treats an oversized response as a failure rather than buffering it fully', async () => {
    server = net.createServer((socket) => {
      socket.on('data', () => {
        const big = Buffer.alloc(100 * 1024, 'a'); // 100KB > 64KB cap
        socket.write(big);
        // deliberately never .end() — client must abort based on size, not EOF
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as net.AddressInfo).port;

    const entry = { matches: () => true, host: '127.0.0.1', port, fieldPatterns: {} };
    const text = await queryWhois(entry, 'example.test');
    expect(text).toBeNull();
  });

  it('times out rather than hanging when the server never responds', async () => {
    server = net.createServer(() => {}); // accepts, never writes, never closes
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as net.AddressInfo).port;

    const entry = { matches: () => true, host: '127.0.0.1', port, fieldPatterns: {} };
    const text = await queryWhois(entry, 'example.test', { timeoutMs: 50 });
    expect(text).toBeNull();
  });

  it('the shipped allowlist has at most 5 entries', () => {
    expect(WHOIS_ALLOWLIST.length).toBeLessThanOrEqual(5);
  });
});
```

Add to `lib/__tests__/enrichment-mapping.test.ts`:

```typescript
import { extractWhois } from '../enrichment-mapping';

describe('extractWhois — only allowlisted org-level field patterns are ever extracted', () => {
  it('extracts org from a matching field pattern and ignores everything else in the response', () => {
    const text = [
      'Domain Name: EXAMPLE.TEST',
      'Registrant Organization: Example Org',
      'Registrant Name: Jane Doe',      // personal — the entry's fieldPatterns below deliberately has no pattern for this key
      'Registrant Email: jane@example.test',
    ].join('\r\n');
    const entry = {
      matches: () => true,
      host: 'whois.example.test',
      fieldPatterns: { org: /^Registrant Organization:\s*(.+)$/m },
    };
    const result = extractWhois(text, entry);
    expect(result.org).toBe('Example Org');
    expect(JSON.stringify(result)).not.toContain('Jane Doe');
  });

  it('never throws on malformed/adversarial WHOIS text', () => {
    const entry = { matches: () => true, host: 'x', fieldPatterns: { org: /Organization:\s*(.+)/ } };
    const hostile = ['', 'x'.repeat(1_000_000), '\0\0\0binary garbage\0\0\0', 'Organization:'.repeat(10000)];
    for (const text of hostile) {
      expect(() => extractWhois(text, entry)).not.toThrow();
    }
  });
});
```

- [x] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-whois-client.test.ts lib/__tests__/enrichment-mapping.test.ts`
Expected: new cases FAIL — modules/exports don't exist yet.

- [x] **Step 3: Implement `lib/enrichment/whois-client.ts`**

```typescript
// lib/enrichment/whois-client.ts
import net from 'node:net';

export interface WhoisAllowlistEntry {
  matches: (target: string) => boolean;
  host: string;
  port?: number;
  fieldPatterns: Record<string, RegExp>;
}

const MAX_RESPONSE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;

// Capped at 5 entries deliberately — each one requires its own free-text
// parser maintained against adversarial/malformed input (spec Scope: "'zero
// new npm dependencies' describes the transport, not the effort"). Extend
// only via a reviewed, deliberate change, never opportunistically.
export const WHOIS_ALLOWLIST: WhoisAllowlistEntry[] = [
  {
    matches: (target) => target.endsWith('.de'),
    host: 'whois.denic.de',
    fieldPatterns: { org: /^Organisation:\s*(.+)$/m },
  },
];

export function queryWhois(
  entry: WhoisAllowlistEntry,
  target: string,
  opts: { timeoutMs?: number } = {},
): Promise<string | null> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: entry.host, port: entry.port ?? 43 });
    let received = 0;
    const chunks: Buffer[] = [];
    let settled = false;

    const finish = (result: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };

    const timer = setTimeout(() => finish(null), timeoutMs);

    socket.on('connect', () => socket.write(`${target}\r\n`));
    socket.on('data', (chunk) => {
      received += chunk.length;
      if (received > MAX_RESPONSE_BYTES) {
        finish(null); // aborted mid-read, treated as a failure — never buffered in full
        return;
      }
      chunks.push(chunk);
    });
    socket.on('end', () => finish(Buffer.concat(chunks).toString('utf8')));
    socket.on('error', () => finish(null));
  });
}
```

- [x] **Step 4: Add `extractWhois` to `lib/enrichment-mapping.ts`**

```typescript
// lib/enrichment-mapping.ts addition
import { WhoisAllowlistEntry } from './enrichment/whois-client';

export function extractWhois(text: string, entry: WhoisAllowlistEntry): { org?: string; registrant?: string } {
  try {
    const result: { org?: string; registrant?: string } = {};
    for (const [key, pattern] of Object.entries(entry.fieldPatterns)) {
      // Only the field NAMES present in entry.fieldPatterns are ever
      // extracted — an org-only allowlist entry (like WHOIS_ALLOWLIST's
      // denic.de entry above) simply never defines a pattern for a personal
      // field, so there is no code path here that could read one.
      if (key !== 'org' && key !== 'registrant') continue;
      const match = text.match(pattern);
      if (match?.[1]) {
        const value = match[1].trim().slice(0, 500); // guard against pathologically long matches
        if (key === 'org') result.org = value;
        if (key === 'registrant') result.registrant = value;
      }
    }
    return result;
  } catch {
    return {};
  }
}
```

- [x] **Step 5: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/enrichment-whois-client.test.ts lib/__tests__/enrichment-mapping.test.ts`
Expected: all tests PASS.

- [x] **Step 6: Commit**

```bash
git add lib/enrichment/whois-client.ts lib/enrichment-mapping.ts lib/__tests__/enrichment-whois-client.test.ts lib/__tests__/enrichment-mapping.test.ts
git commit -m "feat(enrichment): add narrow legacy WHOIS fallback client (extended tier, step 3 of 3)"
```

---

### Task 15: Wire the extended-tier chain end-to-end in `EnrichmentClient`; surface `registrant` and `Unavailable` in the UI

**Files:**
- Modify: `lib/enrichment.ts` (complete the `// TODO(Task 13)` insertion point from Task 12; add the domain-bootstrap → RDAP-with-referral → WHOIS-fallback chain; queue-log entries for the domain leg; `remoteHostname` passthrough)
- Modify: `components/ConnectionsView.tsx` (already renders `registrant` per Task 10 Step 4 — this task just needs the "Unavailable" state, if not already reachable)
- Extend: `lib/__tests__/enrichment-client.test.ts`

**Interfaces:**
- Consumes: everything from Tasks 12–14.
- Produces: the fully-wired extended tier — this is the last task in the plan.

- [x] **Step 1: Write the failing integration test**

```typescript
// addition to lib/__tests__/enrichment-client.test.ts
it('extended tier: resolves a hostname via reverse DNS, then looks up domain registrant, and emits both on one result', async () => {
  const ipRdapResponse = { objectClassName: 'ip network', name: 'EXAMPLE-NET', country: 'US' };
  const domainRdapResponse = {
    objectClassName: 'domain',
    entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['org', {}, 'text', 'Example Registrant Org']]] }],
  };
  let call = 0;
  const fetchImpl = (async () => {
    call += 1;
    const body = call === 1 ? ipRdapResponse : domainRdapResponse;
    return new Response(JSON.stringify(body), { status: 200 });
  }) as unknown as typeof fetch;

  // dns.promises.reverse is mocked at the module level for this test file —
  // implementer note: use vi.mock('node:dns', ...) at the top of the test
  // file (hoisted, per Vitest's mocking rules) rather than inline here, so
  // it applies before EnrichmentClient's import chain resolves reverse-dns.ts.

  const client = new EnrichmentClient({ dataDir: dir, fetchImpl });
  client.enable();
  const resultPromise = new Promise((resolve) => client.once('result', resolve));
  client.requestLookup('conn-1', '93.184.216.34');
  const result = (await resultPromise) as { enrichment: { org?: string; registrant?: string } };

  expect(result.enrichment.org).toBe('EXAMPLE-NET');
  expect(result.enrichment.registrant).toBe('Example Registrant Org');
}, 20_000);

it('extended tier: reverse-DNS failure leaves the core-tier result intact, no registrant field, no error', async () => {
  // vi.mock('node:dns') for this case returns/throws ENOTFOUND — the lookup
  // must still complete and emit the core-tier org/country result.
});
```

The second stub test needs the same `vi.mock('node:dns', ...)` treatment as the first — write both fully rather than leaving the second as an empty body; it's flagged as a stub here only to keep this plan's own code block from duplicating the mock-setup boilerplate twice.

- [x] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/enrichment-client.test.ts`
Expected: the new extended-tier case FAILs — `lookup()` doesn't chain into domain RDAP yet.

- [x] **Step 3: Complete the chain in `lib/enrichment.ts`**

Replace the `// TODO(Task 13): domain RDAP lookup goes here` marker from Task 12 Step 5 with:

```typescript
// After a successful core-tier IP RDAP result, inside lookup():
const hostname = await reverseDnsLookup(remoteAddr);
if (hostname) {
  const domainCached = this.cache.getForDomain(hostname);
  if (domainCached && this.cache.isFresh(domainCached) && domainCached.record) {
    record.registrant = domainCached.record.registrant;
  } else {
    if (!this.domainBootstrapPromise) {
      this.domainBootstrapPromise = loadDomainBootstrap(this.domainBootstrapCachePath, this.fetchImpl);
    }
    const domainServices = await this.domainBootstrapPromise;
    const domainBase = resolveRdapBaseForDomain(hostname, domainServices);
    if (domainBase) {
      const domainUrl = `${domainBase.replace(/\/$/, '')}/domain/${hostname}`;
      const domainResult = await this.queue.enqueue(() => this.rdap.fetchWithReferral(domainUrl));
      await this.queryLog.append({ target: hostname, endpoint: new URL(domainUrl).host, cacheStatus: 'miss' });
      if (domainResult.ok) {
        const domainExtracted = extractDomainRdap(domainResult.json);
        record.registrant = domainExtracted.registrant;
        await this.cache.setSuccess(hostname, { ...domainExtracted, source: 'rdap', fetchedAt: new Date().toISOString() }, CACHE_TTL_MS);
      } else {
        // Not RDAP-eligible and no matching WHOIS allowlist entry -> falls
        // through to "unavailable" for registrant specifically, per spec —
        // the core-tier org/ASN/country result above is still emitted.
        const whoisEntry = WHOIS_ALLOWLIST.find((e) => e.matches(hostname));
        if (whoisEntry) {
          const whoisText = await this.queue.enqueue(() => queryWhois(whoisEntry, hostname));
          if (whoisText) {
            const whoisExtracted = extractWhois(whoisText, whoisEntry);
            record.registrant = whoisExtracted.registrant ?? whoisExtracted.org;
          }
        }
      }
    }
  }
}
```

(Add the corresponding imports — `reverseDnsLookup`, `loadDomainBootstrap`, `resolveRdapBaseForDomain`, `extractDomainRdap`, `WHOIS_ALLOWLIST`, `queryWhois`, `extractWhois` — and a `domainBootstrapPromise`/`domainBootstrapCachePath` field pair mirroring the existing IP-bootstrap ones from Task 8.)

- [x] **Step 4: Confirm the "Unavailable" UI state is reachable**

`ConnectionsView`'s Ownership section (Task 10 Step 4) currently branches only on `!selectedConn.enrichment` vs. present. Add the fifth state: when a lookup has completed (i.e. the connection is no longer in the `lookingUpIds` set from Task 10) but produced no `org`/`asn`/`registrant` at all, render `"Unavailable."` instead of an empty `Org: — · ASN: —` line — the spec draws a distinction between "an ASN can legitimately be blank while org is present" (fine, shown as `—`) and "nothing came back at all" (shown as `Unavailable`, a different message). Add a short-circuit check for `!enrichment.org && !enrichment.asn && !enrichment.registrant` before the normal render path.

- [x] **Step 5: Run the full test suite and manual end-to-end check**

Run: `npx vitest run`
Expected: every test in this plan passes, including the extended-tier chain.

Run: `npm run build && npm run lint`
Expected: both succeed with no new errors/warnings.

Manually (with the capture agent and `npm run dev` both running, real network access): `enrich on` in the command bar, select a connection to a domain you expect to have RDAP-visible registrant data (e.g. one resolving to a `.com`/`.org` you control or know), expand Ownership, and confirm `Registrant: ...` appears after the on-demand lookup completes.

- [x] **Step 6: Commit**

```bash
git add lib/enrichment.ts components/ConnectionsView.tsx lib/__tests__/enrichment-client.test.ts
git commit -m "feat(enrichment): wire extended-tier reverse-DNS + domain RDAP/WHOIS chain end-to-end"
```

---

### Task 16: Update `docs/security.md`

**Files:**
- Modify: `docs/security.md`

**Interfaces:**
- Produces: an accurate security posture doc — no code change.

- [x] **Step 1: Replace the stale bullet**

In the "What's explicitly NOT done yet" section, replace:

> - **No ownership/reputation enrichment (WHOIS/RDAP)** on remote IPs or domains yet (epic #23) — you're seeing raw IPs and SNI hostnames, not who they belong to.

with a short description of what actually shipped — default-off, runtime-only opt-in; what's contacted (RIR/registrar RDAP servers, a small WHOIS-fallback allowlist, the relay's configured DNS resolver for reverse lookups); where the cache/query-log live (`.data/enrichment/`, `0600` permissions, 14-day cache TTL / 30-day query-log retention); and a pointer to `docs/superpowers/specs/2026-08-28-ownership-enrichment-design.md` for the full security model. Keep the framing consistent with the rest of the file's plain, unhedged style (see how the LAN-access bullet above it is written).

Also add a new bullet (or extend the existing "no authentication" framing) noting the relay-wide (not per-viewer) scope of the enrichment opt-in, per the spec's named "Explicitly out of scope" limitation — this matters more once epic #22 (LAN access) lands and multiple devices can see the same relay.

- [x] **Step 2: Commit**

```bash
git add docs/security.md
git commit -m "docs(security): update posture doc for ownership enrichment (epic #23)"
```

---

## Post-plan verification

- [x] `npx vitest run` — every test in this plan (Tasks 1–15) passes
- [x] `npx tsc --noEmit` — no new type errors
- [ ] `npm run lint` — no new lint errors
- [x] `npm run build` — Next.js production build succeeds
- [x] `grep -rn "dangerouslySetInnerHTML\|\.innerHTML\s*=" app/ components/ lib/` — still empty (Task 11's regression test already enforces this, but worth a manual final check)
- [ ] Manual end-to-end check (Task 9 Step 6 and Task 15 Step 5): `enrich on`, `enrich background on`, `enrich clear`, and on-demand per-connection lookup all work against a running agent + relay with real network access; the disclosure banner reappears every time enrichment is (re-)enabled, not just the first time
- [x] Confirm no file under `capture-agent/` changed — this whole plan is relay+browser only, per the spec's architecture
- [ ] Confirm `.data/enrichment/cache.json` and `.data/enrichment/query-log.ndjson` are created with `0600` permissions on a real run (`ls -la .data/enrichment/`)

**Next plan:** sub-project 3 (network path visualization — on-demand traceroute + per-hop geoIP, consuming this sub-project's cached ASN/org data as hop context) — not yet written; per `CONTRIBUTING.md`'s spec-then-plan process, write its design spec first once this plan's software is working end-to-end and epic #23 is closed.
