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
