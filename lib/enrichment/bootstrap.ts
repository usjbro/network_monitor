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

// Mirrors RdapClient's timeout + streamed-size-cap hardening (Task 2) for
// the two bootstrap fetches below, which call fetchImpl directly rather
// than going through RdapClient — they need their own guard against a
// hung/oversized response from data.iana.org, since without one a stalled
// fetch here would hang forever (no AbortController) and, because
// bootstrapPromise/domainBootstrapPromise are memoized and awaited by every
// lookup(), would wedge every future enrichment lookup behind it
// indefinitely. Deliberately not routed through RdapClient itself: that
// class's per-host backoff/circuit-breaker state is keyed and tuned for
// RIR/registrar RDAP hosts hit on every lookup, not this one-per-30-days
// bootstrap fetch, and reusing it would require broader signature changes
// to this module's existing (test-covered) fetchImpl-based API.
const BOOTSTRAP_TIMEOUT_MS = 10_000;
const BOOTSTRAP_MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // IANA's real ipv4.json/dns.json are well under 1MB

async function fetchBootstrapJson(url: string, fetchImpl: typeof fetch): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), BOOTSTRAP_TIMEOUT_MS);
  try {
    const res = await fetchImpl(url, { redirect: 'manual', signal: controller.signal });
    if ((res as Response & { type?: string }).type === 'opaqueredirect' || (res.status >= 300 && res.status < 400)) {
      throw new Error(`bootstrap fetch redirected: ${url}`);
    }
    if (!res.ok) throw new Error(`bootstrap fetch failed: ${res.status}`);
    const reader = res.body?.getReader();
    if (!reader) throw new Error('bootstrap response has no body');
    let received = 0;
    const chunks: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > BOOTSTRAP_MAX_RESPONSE_BYTES) {
        controller.abort();
        throw new Error('bootstrap response too large');
      }
      chunks.push(value);
    }
    const text = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
    return JSON.parse(text);
  } finally {
    clearTimeout(timer);
  }
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

// Only the IPv4 bootstrap file is fetched. `cidrContains` (Task 1's
// scope-filter, reused here for prefix routing) parses dotted-decimal IPv4
// only — it returns false for any IPv6-shaped input rather than matching an
// IPv6 CIDR — so a service list built from ipv6.json could never be matched
// by resolveRdapBaseForIp below. Fetching it would just be an unused
// outbound request against a third party; add it back if/when CIDR routing
// grows real IPv6 support.
export async function loadIpBootstrap(
  cachePath: string,
  fetchImpl: typeof fetch,
  ttlMs: number = 30 * 24 * 60 * 60 * 1000,
): Promise<BootstrapService[]> {
  const cached = readJsonIfExists<BootstrapCacheFile>(cachePath);
  if (cached && Date.now() - cached.fetchedAt < ttlMs) {
    return cached.services;
  }

  const json = await fetchBootstrapJson(IANA_IPV4_BOOTSTRAP_URL, fetchImpl);
  const services = parseIpBootstrap(json);
  await atomicWriteJson(cachePath, { fetchedAt: Date.now(), services } satisfies BootstrapCacheFile);
  return services;
}

// --- Domain-name RDAP bootstrap (extended tier, Task 13) ---

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
    try {
      host = new URL(url).host;
    } catch {
      continue;
    }
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

interface DomainBootstrapCacheFile {
  fetchedAt: number;
  services: DomainBootstrapService[];
}

const IANA_DNS_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

export async function loadDomainBootstrap(
  cachePath: string,
  fetchImpl: typeof fetch,
  ttlMs: number = 30 * 24 * 60 * 60 * 1000,
): Promise<DomainBootstrapService[]> {
  const cached = readJsonIfExists<DomainBootstrapCacheFile>(cachePath);
  if (cached && Date.now() - cached.fetchedAt < ttlMs) {
    return cached.services;
  }

  const json = await fetchBootstrapJson(IANA_DNS_BOOTSTRAP_URL, fetchImpl);
  const services = parseDomainBootstrap(json);
  await atomicWriteJson(cachePath, { fetchedAt: Date.now(), services } satisfies DomainBootstrapCacheFile);
  return services;
}
