// lib/enrichment.ts
import { EventEmitter } from 'node:events';
import { join } from 'node:path';
import { isPrivateOrReserved, ipToInt } from './enrichment/scope-filter';
import { EnrichmentCache } from './enrichment/cache';
import { QueryLog } from './enrichment/query-log';
import { RequestQueue, RequestQueueOptions, shuffle } from './enrichment/request-queue';
import { loadIpBootstrap, resolveRdapBaseForIp, loadDomainBootstrap, resolveRdapBaseForDomain } from './enrichment/bootstrap';
import { RdapClient } from './enrichment/rdap-client';
import { reverseDnsLookup } from './enrichment/reverse-dns';
import { WHOIS_ALLOWLIST, queryWhois } from './enrichment/whois-client';
import { extractIpRdap, extractDomainRdap, extractWhois, buildEnrichmentEvent } from './enrichment-mapping';
import { EnrichmentRecord } from './enrichment/types';

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
  private queue: RequestQueue;
  private rdap: RdapClient;
  private fetchImpl: typeof fetch;
  // Keyed by remoteAddr (the single-flight key). Each in-flight lookup
  // tracks every connectionId that asked for it while it was already
  // underway, so that a second (or third...) request for the same address
  // — from a different connection row, or the same row clicked twice —
  // still gets notified once the shared lookup resolves, rather than being
  // silently dropped. Spec's Error handling & lifecycle: a connection
  // sitting on "Looking up…" behind an in-flight request for the same key
  // must still resolve, not hang forever just because it wasn't the first
  // asker.
  private inFlightWaiters = new Map<string, Set<string>>();
  private bootstrapPromise: ReturnType<typeof loadIpBootstrap> | null = null;
  private random: () => number;
  private bootstrapCachePath: string;
  private reverseDnsFn: typeof reverseDnsLookup;
  // Mirrors bootstrapPromise/bootstrapCachePath above, but for the
  // domain-name RDAP bootstrap (Task 13) — a genuinely separate registry
  // host set (Verisign/PIR/etc., not ARIN/RIPE/etc.), fetched/cached
  // independently and only once the extended tier actually needs it (i.e.
  // never for a client that only ever does core-tier IP lookups).
  private domainBootstrapPromise: ReturnType<typeof loadDomainBootstrap> | null = null;
  private domainBootstrapCachePath: string;

  constructor(opts: {
    dataDir: string;
    fetchImpl?: typeof fetch;
    random?: () => number;
    // Test-only override of the queue's inter-dispatch jitter window — production
    // callers never pass this and get RequestQueue's real 3-10s default spacing.
    queueOptions?: RequestQueueOptions;
    // Test-only override of the extended-tier reverse-DNS step (Task 12).
    // Production callers never pass this and get the real
    // dns.promises.reverse() wrapper; tests inject a fast, offline stub so
    // this otherwise-fully-mocked suite never attempts a live DNS query —
    // same reasoning as `fetchImpl` already gets for RDAP HTTP calls.
    reverseDnsFn?: typeof reverseDnsLookup;
  }) {
    super();
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.random = opts.random ?? Math.random;
    this.reverseDnsFn = opts.reverseDnsFn ?? reverseDnsLookup;
    this.cache = new EnrichmentCache(join(opts.dataDir, 'cache.json'));
    this.cache.load();
    this.queryLog = new QueryLog(join(opts.dataDir, 'query-log.ndjson'));
    this.rdap = new RdapClient(this.fetchImpl);
    // The same injected `random` drives both this.queue's inter-dispatch
    // jitter and the shuffle() call in notifyObservedConnections below, so a
    // single injected sequence makes the whole dispatch pipeline
    // deterministic for tests.
    this.queue = new RequestQueue({ random: this.random, ...opts.queueOptions });
    void this.queryLog.prune(QUERY_LOG_RETENTION_DAYS).catch(() => {});
    this.bootstrapCachePath = join(opts.dataDir, 'bootstrap-ipv4.json');
    this.domainBootstrapCachePath = join(opts.dataDir, 'bootstrap-dns.json');
  }

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

    const cached = this.cache.getForIp(remoteAddr);
    if (cached && this.cache.isFresh(cached)) {
      await this.queryLog.append({ target: remoteAddr, endpoint: 'cache', cacheStatus: 'hit' });
      if (cached.record) {
        this.emit('result', buildEnrichmentEvent(connectionId, remoteAddr, { ...cached.record, source: 'cache' }));
      }
      return;
    }

    const existingWaiters = this.inFlightWaiters.get(flightKey);
    if (existingWaiters) {
      // Single-flight: join the in-flight lookup's waiter set rather than
      // issuing a duplicate request. All waiters get the eventual 'result'.
      existingWaiters.add(connectionId);
      return;
    }
    const waiters = new Set([connectionId]);
    this.inFlightWaiters.set(flightKey, waiters);

    try {
      if (!this.bootstrapPromise) {
        // Un-memoize on rejection: a transient failure (timeout, network
        // blip, oversized/redirected response — anything fetchBootstrapJson
        // now rejects on) must not permanently wedge every future lookup
        // behind the same stale rejected promise for the rest of the
        // process's lifetime. Clearing the field lets the next lookup()
        // retry a fresh fetch instead of instantly re-throwing forever.
        this.bootstrapPromise = loadIpBootstrap(this.bootstrapCachePath, this.fetchImpl).catch((err) => {
          this.bootstrapPromise = null;
          throw err;
        });
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

      // Extended tier (spec §4): once core-tier RDAP has resolved an org,
      // and there's no domain-level data on this record yet (there never is
      // on a fresh lookup — a cache hit above already returned early),
      // resolve remoteAddr's PTR hostname as the prerequisite for a domain
      // RDAP/WHOIS registrant lookup. Sequential, not parallel-with-RDAP: it
      // only makes sense to spend a reverse-DNS query once we know RDAP
      // actually found an organization worth attributing a domain to.
      let resolvedHostname: string | undefined;
      if (record.org && !record.registrant) {
        const remoteHostname = await this.reverseDnsFn(remoteAddr);
        if (remoteHostname) {
          resolvedHostname = remoteHostname;
          await this.resolveRegistrant(remoteHostname, record);
        }
      }

      const key = cidrKeyFromRdap(result.json) ?? cidrKeyFor(remoteAddr);
      await this.cache.setSuccess(key, record, CACHE_TTL_MS);
      for (const cid of waiters) {
        this.emit('result', buildEnrichmentEvent(cid, remoteAddr, record, resolvedHostname));
      }
    } catch (err) {
      // lookup() is always invoked fire-and-forget (`void this.lookup(...)`)
      // from requestLookup()/notifyObservedConnections() — there is no
      // caller anywhere that awaits or attaches a rejection handler to it.
      // An uncaught error here (e.g. a transient disk error from
      // queryLog.append/cache.setSuccess) would otherwise become an
      // unhandled promise rejection and, under Node's default policy, crash
      // the entire process — taking down the unrelated live packet-capture
      // SSE stream over what should be a contained, best-effort enrichment
      // failure. Deliberately NOT `this.emit('error', err)`: EventEmitter
      // special-cases the 'error' event and throws synchronously when there
      // is no registered listener (there is none, anywhere in this app),
      // which would just reproduce the exact unhandled-rejection crash this
      // catch exists to prevent. Fail closed the same way the RDAP-failure
      // branch above does instead: log for observability, and let the
      // affected connection(s) simply never receive a 'result' event — the
      // UI's own timeout resolves them to "Unavailable".
      console.error('[enrichment] lookup failed for', remoteAddr, err);
    } finally {
      this.inFlightWaiters.delete(flightKey);
    }
  }

  // Extended tier (Tasks 13/14), invoked once a hostname has been resolved
  // for the connection's remote address: domain RDAP first (registry, with
  // an allowlist-gated registrar referral per Task 13), falling back to the
  // narrow legacy WHOIS allowlist (Task 14) only when the hostname's TLD has
  // no RDAP service at all. Mutates `record.registrant` in place when
  // something is found; leaves it unset (surfaced as "Unavailable" in the UI,
  // Step 4) on any failure — never throws, mirroring the core-tier RDAP leg's
  // stale-on-failure posture just below in `lookup()`.
  private async resolveRegistrant(hostname: string, record: EnrichmentRecord): Promise<void> {
    const domainCached = this.cache.getForDomain(hostname);
    if (domainCached && this.cache.isFresh(domainCached)) {
      if (domainCached.record) record.registrant = domainCached.record.registrant;
      return; // fresh negative cache entry: no registrant, and no re-query.
    }

    if (!this.domainBootstrapPromise) {
      // Same un-memoize-on-rejection reasoning as bootstrapPromise above: a
      // transient failure must not permanently wedge every future
      // registrant lookup behind one stale rejected promise.
      this.domainBootstrapPromise = loadDomainBootstrap(this.domainBootstrapCachePath, this.fetchImpl).catch((err) => {
        this.domainBootstrapPromise = null;
        throw err;
      });
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
        await this.cache.setNegative(hostname, NEGATIVE_TTL_MS);
      }
      return;
    }

    // Not RDAP-eligible — fall through to the narrow legacy WHOIS allowlist.
    // No matching entry (the common case: most TLDs have RDAP) resolves to
    // "unavailable" for registrant specifically; the core-tier org/ASN/
    // country result is unaffected either way.
    const whoisEntry = WHOIS_ALLOWLIST.find((e) => e.matches(hostname));
    if (!whoisEntry) {
      await this.cache.setNegative(hostname, NEGATIVE_TTL_MS);
      return;
    }
    const whoisText = await this.queue.enqueue(() => queryWhois(whoisEntry, hostname));
    await this.queryLog.append({ target: hostname, endpoint: whoisEntry.host, cacheStatus: 'miss' });
    if (whoisText) {
      const whoisExtracted = extractWhois(whoisText, whoisEntry);
      record.registrant = whoisExtracted.registrant ?? whoisExtracted.org;
      await this.cache.setSuccess(hostname, { registrant: record.registrant, source: 'whois', fetchedAt: new Date().toISOString() }, CACHE_TTL_MS);
    } else {
      await this.cache.setNegative(hostname, NEGATIVE_TTL_MS);
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
// Floor on how wide a single RDAP response is ever allowed to poison the
// cache for. Real-world RIR delegations are essentially never wider than a
// /8 (that's already an entire legacy Class-A block); a response claiming
// anything wider than that is a malformed or malicious registry, not a
// legitimate allocation, and must not be trusted to key the cache — since
// EnrichmentCache.getForIp matches any IP falling inside the cached CIDR
// (cidrContains treats bits===0 as "matches everything"), an unbounded
// prefix here would let one bad response silently poison ownership data for
// every future connection for up to CACHE_TTL_MS.
const MIN_CIDR_PREFIX_LEN = 8;

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
    if (typeof prefix === 'string' && typeof first?.length === 'number' && first.length >= MIN_CIDR_PREFIX_LEN) {
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

  for (let prefixLen = 32; prefixLen >= MIN_CIDR_PREFIX_LEN; prefixLen--) {
    const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
    const blockSize = prefixLen === 32 ? 1 : Math.pow(2, 32 - prefixLen);
    if ((start & mask) >>> 0 === start && start + blockSize - 1 === end) {
      return `${intToIp(start)}/${prefixLen}`;
    }
  }
  return null;
}
