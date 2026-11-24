import { Conversation, Endpoint, NetworkConnection } from './types';

export interface RollupEnrichmentEvent {
  remoteAddr: string;
  remoteHostname?: string;
  enrichment: NetworkConnection['enrichment'];
}

type HostEnrichment = Pick<Endpoint, 'remoteHostname' | 'enrichment'>;

// Every ownership field: a result that differs in any of them is a new result.
const ENRICHMENT_FIELDS = Object.keys({
  org: true,
  asn: true,
  asnOrg: true,
  country: true,
  registrant: true,
  source: true,
  fetchedAt: true,
} satisfies Record<keyof NonNullable<HostEnrichment['enrichment']>, true>) as (keyof NonNullable<HostEnrichment['enrichment']>)[];

function sameEntry(a: HostEnrichment, b: HostEnrichment): boolean {
  if (a.remoteHostname !== b.remoteHostname || !a.enrichment !== !b.enrichment) return false;
  return ENRICHMENT_FIELDS.every((field) => a.enrichment?.[field] === b.enrichment?.[field]);
}

export const MAX_IDLE_ENRICHMENT = 1_000;

// Ownership and PTR names by remote address, for one tab (KAN-131, design
// D7). A host leaves and re-enters the received rows as the rankings change,
// so this cannot be kept on the rows. Hosts in either current list are never
// evicted; the rest share an LRU of MAX_IDLE_ENRICHMENT.
export class EnrichmentMap {
  private currentHosts = new Set<string>();
  private current = new Map<string, HostEnrichment>();
  // Oldest first (Map iteration order).
  private idle = new Map<string, HostEnrichment>();

  // Replaces the ownership data. A result without a PTR name keeps the known
  // one. Returns whether anything known about the host changed; an unchanged
  // result still counts as use.
  record(event: RollupEnrichmentEvent): boolean {
    const host = event.remoteAddr;
    const known = this.get(host);
    const received: HostEnrichment = {
      remoteHostname: event.remoteHostname || known?.remoteHostname,
      enrichment: event.enrichment,
    };
    const unchanged = known !== undefined && sameEntry(known, received);
    const entry = unchanged ? known : received;
    if (this.currentHosts.has(host)) {
      this.current.set(host, entry);
    } else {
      this.idle.delete(host);
      this.idle.set(host, entry);
      this.trimIdle();
    }
    return !unchanged;
  }

  setCurrentHosts(endpointHosts: Iterable<string>, conversationHosts: Iterable<string>): void {
    const hosts = new Set(endpointHosts);
    for (const host of conversationHosts) hosts.add(host);
    const next = new Map<string, HostEnrichment>();
    for (const host of hosts) {
      const entry = this.get(host);
      if (entry) next.set(host, entry);
      this.idle.delete(host);
    }
    for (const [host, entry] of this.current) {
      if (!hosts.has(host)) this.idle.set(host, entry);
    }
    this.currentHosts = hosts;
    this.current = next;
    this.trimIdle();
  }

  get(host: string): HostEnrichment | undefined {
    return this.current.get(host) ?? this.idle.get(host);
  }

  get size(): number {
    return this.current.size + this.idle.size;
  }

  private trimIdle(): void {
    for (const host of this.idle.keys()) {
      if (this.idle.size <= MAX_IDLE_ENRICHMENT) break;
      this.idle.delete(host);
    }
  }
}

const remoteOf = (row: Endpoint | Conversation) => ('host' in row ? row.host : row.remoteAddr);

function enrichRow<T extends Endpoint | Conversation>(row: T, map: EnrichmentMap): T {
  const known = map.get(remoteOf(row));
  if (!known) return row;
  return {
    ...row,
    remoteHostname: row.remoteHostname ?? known.remoteHostname,
    enrichment: row.enrichment ?? known.enrichment,
  };
}

// Fills in ownership and PTR names; what a row already carries wins. Nothing
// else is retained: observedName is always the latest event's.
export function withEnrichment<T extends Endpoint | Conversation>(rows: T[], map: EnrichmentMap): T[] {
  return rows.map((row) => enrichRow(row, map));
}

// `shown` after a new result for `host`: its rows are enriched again from the
// received rows (an enriched row would keep its old result); the others are the
// same objects. `shown` and `received` hold the same rows in the same order.
export function replaceHostRows<T extends Endpoint | Conversation>(
  shown: T[],
  received: T[],
  host: string,
  map: EnrichmentMap,
): T[] {
  return shown.map((row, i) => (remoteOf(row) === host ? enrichRow(received[i], map) : row));
}
