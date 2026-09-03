// lib/enrichment-mapping.ts
import { EnrichmentRecord } from './enrichment/types';
import { WhoisAllowlistEntry } from './enrichment/whois-client';
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

/**
 * Extracts org/registrant text out of a raw port-43 WHOIS response using
 * only the field patterns an allowlist entry (lib/enrichment/whois-client.ts)
 * itself defines. Like extractDomainRdap above, this is a safety property of
 * *which keys are ever read* — an entry that only defines an `org` pattern
 * has no code path here that could read a personal field, because
 * WHOIS_ALLOWLIST entries are deliberately never given patterns for
 * personal fields (name/email/phone/address) in the first place.
 */
export function extractWhois(text: string, entry: WhoisAllowlistEntry): { org?: string; registrant?: string } {
  try {
    const result: { org?: string; registrant?: string } = {};
    for (const [key, pattern] of Object.entries(entry.fieldPatterns)) {
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

export function buildEnrichmentEvent(
  connectionId: string,
  remoteAddr: string,
  record: EnrichmentRecord,
  // Extended tier only (Task 15): the reverse-DNS hostname resolved as the
  // prerequisite for the domain registrant lookup, surfaced onto the
  // connection's own top-level `remoteHostname` field (lib/types.ts) — the
  // same field the connections table already displays in place of the raw
  // remote address (components/ConnectionsView.tsx) but that, per
  // docs/wire-protocol.md, the capture agent itself never populates.
  // Omitted entirely (not even as `undefined`) when no hostname resolved,
  // so `'remoteHostname' in event` cleanly distinguishes "resolved" from
  // "never attempted/failed."
  remoteHostname?: string,
): { type: 'connection_enrichment'; connectionId: string; remoteAddr: string; remoteHostname?: string; enrichment: NetworkConnection['enrichment'] } {
  return {
    type: 'connection_enrichment',
    connectionId,
    remoteAddr,
    ...(remoteHostname ? { remoteHostname } : {}),
    enrichment: { ...record },
  };
}

export function applyEnrichmentEvent(
  connections: NetworkConnection[],
  event: { connectionId: string; enrichment: NetworkConnection['enrichment']; remoteHostname?: string },
): NetworkConnection[] {
  const idx = connections.findIndex((c) => c.id === event.connectionId);
  if (idx === -1) return connections;
  const next = [...connections];
  next[idx] = {
    ...next[idx],
    enrichment: event.enrichment,
    ...(event.remoteHostname ? { remoteHostname: event.remoteHostname } : {}),
  };
  return next;
}
