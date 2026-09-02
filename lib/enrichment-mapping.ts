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
