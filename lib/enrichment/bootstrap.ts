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

  const res = await fetchImpl(IANA_IPV4_BOOTSTRAP_URL, { redirect: 'manual' });
  const services = parseIpBootstrap(await res.json());
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

  const res = await fetchImpl(IANA_DNS_BOOTSTRAP_URL, { redirect: 'manual' });
  const services = parseDomainBootstrap(await res.json());
  await atomicWriteJson(cachePath, { fetchedAt: Date.now(), services } satisfies DomainBootstrapCacheFile);
  return services;
}
