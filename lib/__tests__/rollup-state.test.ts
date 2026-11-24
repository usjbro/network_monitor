import { describe, expect, it } from 'vitest';
import { EnrichmentMap, MAX_IDLE_ENRICHMENT, RollupEnrichmentEvent, withEnrichment } from '../rollup-state';
import { Conversation, Endpoint } from '../types';

const enrichment = {
  org: 'Example Org',
  source: 'rdap' as const,
  fetchedAt: '2026-09-28T00:00:00.000Z',
};

function endpoint(overrides: Partial<Endpoint> = {}): Endpoint {
  return {
    host: '93.184.216.34', rxBytesTotal: 100, txBytesTotal: 50,
    rxPacketsTotal: 2, txPacketsTotal: 1, rxSpeed: 10, txSpeed: 5,
    flowCount: 1, firstSeenMs: 0, lastSeenMs: 1000, processName: 'Safari', pid: 1234, historyComplete: true,
    ...overrides,
  };
}

function conversation(overrides: Partial<Conversation> = {}): Conversation {
  return {
    localAddr: '192.168.1.10', remoteAddr: '93.184.216.34',
    rxBytesTotal: 100, txBytesTotal: 50, rxPacketsTotal: 2, txPacketsTotal: 1,
    rxSpeed: 10, txSpeed: 5, flowCount: 1, firstSeenMs: 0, lastSeenMs: 1000,
    durationMs: 1000, processName: 'Safari', pid: 1234, historyComplete: true,
    ...overrides,
  };
}

function result(remoteAddr: string, remoteHostname?: string): RollupEnrichmentEvent {
  return { remoteAddr, enrichment, ...(remoteHostname ? { remoteHostname } : {}) };
}

const hosts = (n: number, prefix = 'h') => Array.from({ length: n }, (_, i) => `${prefix}${i}`);

describe('withEnrichment', () => {
  const HOST = '93.184.216.34';

  it('adds ownership and PTR name by remote address to endpoints and conversations', () => {
    const map = new EnrichmentMap();
    map.setCurrentHosts([HOST, '8.8.8.8'], [HOST, '8.8.8.8']);
    map.record(result(HOST, 'example.com'));
    const endpoints = withEnrichment([endpoint(), endpoint({ host: '8.8.8.8' })], map);
    const conversations = withEnrichment([conversation(), conversation({ remoteAddr: '8.8.8.8' })], map);

    expect(endpoints).toEqual([endpoint({ enrichment, remoteHostname: 'example.com' }), endpoint({ host: '8.8.8.8' })]);
    expect(conversations).toEqual([
      conversation({ enrichment, remoteHostname: 'example.com' }),
      conversation({ remoteAddr: '8.8.8.8' }),
    ]);
  });

  it('a_name_gone_from_the_snapshot_is_not_retained, but the PTR name and ownership are', () => {
    const map = new EnrichmentMap();
    map.setCurrentHosts([HOST], []);
    map.record(result(HOST, 'ptr.example.net'));
    const [before] = withEnrichment([endpoint({ observedName: 'example.com' })], map);
    expect(before.observedName).toBe('example.com');

    map.setCurrentHosts([HOST], []);
    const [after] = withEnrichment([endpoint({ rxBytesTotal: 200 })], map);
    expect(after.observedName).toBeUndefined();
    expect(after).toMatchObject({ rxBytesTotal: 200, remoteHostname: 'ptr.example.net', enrichment });
  });

  it('survives leaving both lists and re-entering, without resurrecting the observed name', () => {
    const map = new EnrichmentMap();
    map.setCurrentHosts([HOST], [HOST]);
    map.record(result(HOST, 'ptr.example.net'));
    withEnrichment([endpoint({ observedName: 'example.com' })], map);
    map.setCurrentHosts([], []);
    map.setCurrentHosts(['8.8.8.8'], []);
    map.setCurrentHosts([HOST], [HOST]);
    const expected = { remoteHostname: 'ptr.example.net', enrichment };
    expect(withEnrichment([endpoint()], map)).toEqual([endpoint(expected)]);
    expect(withEnrichment([conversation()], map)).toEqual([conversation(expected)]);
  });

  it('what the row itself carries wins', () => {
    const map = new EnrichmentMap();
    map.record(result(HOST, 'ptr.example.net'));
    const own = { org: 'Row', source: 'cache' as const, fetchedAt: '2026-09-29T00:00:00.000Z' };
    const [row] = withEnrichment([endpoint({ remoteHostname: 'row.example', enrichment: own })], map);
    expect(row).toMatchObject({ remoteHostname: 'row.example', enrichment: own });
  });

  it('keeps order and leaves the input rows unchanged', () => {
    const map = new EnrichmentMap();
    map.record(result('b'));
    const rows = [endpoint({ host: 'c' }), endpoint({ host: 'b' }), endpoint({ host: 'a' })];
    expect(withEnrichment(rows, map).map((r) => r.host)).toEqual(['c', 'b', 'a']);
    expect(rows[1].enrichment).toBeUndefined();
  });
});

describe('EnrichmentMap', () => {
  it('a later result replaces ownership, and keeps the PTR name when it has none', () => {
    const map = new EnrichmentMap();
    map.record(result('h', 'ptr.example.net'));
    const newer = { org: 'Newer', source: 'rdap' as const, fetchedAt: '2026-09-29T00:00:00.000Z' };
    map.record({ remoteAddr: 'h', enrichment: newer });
    expect(map.get('h')).toEqual({ remoteHostname: 'ptr.example.net', enrichment: newer });
  });

  it('keeps a result for a host in neither list, as idle', () => {
    const map = new EnrichmentMap();
    map.setCurrentHosts(['a'], ['b']);
    map.record(result('elsewhere', 'ptr.example.net'));
    expect(map.get('elsewhere')).toEqual({ remoteHostname: 'ptr.example.net', enrichment });
    for (const host of hosts(MAX_IDLE_ENRICHMENT)) map.record(result(host));
    expect(map.get('elsewhere')).toBeUndefined();
  });

  it('keeps 1,000 of 1,001 idle hosts, evicting the oldest', () => {
    expect(MAX_IDLE_ENRICHMENT).toBe(1_000);
    const map = new EnrichmentMap();
    const all = hosts(1_001);
    for (const host of all) map.record(result(host));
    expect(map.size).toBe(1_000);
    expect(map.get(all[0])).toBeUndefined();
    expect(all.slice(1).every((host) => map.get(host) !== undefined)).toBe(true);
  });

  it('keeps 1,000 of 1,001 hosts that leave the lists, evicting the first to leave', () => {
    const map = new EnrichmentMap();
    const all = hosts(1_001);
    map.setCurrentHosts(all, []);
    for (const host of all) map.record(result(host));
    expect(map.size).toBe(1_001);
    map.setCurrentHosts(all.slice(0, 1_000).filter((host) => host !== 'h500'), []); // h500 and h1000 leave
    expect(map.size).toBe(1_001);
    map.setCurrentHosts([], []);
    expect(map.size).toBe(1_000);
    expect(map.get('h500')).toBeUndefined();
    expect(map.get('h1000')).toBeDefined();
  });

  it('a new result for an idle host makes it the most recent', () => {
    const map = new EnrichmentMap();
    const all = hosts(1_000);
    for (const host of all) map.record(result(host));
    map.record(result(all[0]));
    map.record(result('one-more'));
    expect(map.get(all[0])).toBeDefined();
    expect(map.get(all[1])).toBeUndefined();
  });

  it('keeps all 8,000 current hosts while idle ones churn, and stays within 9,000', () => {
    const map = new EnrichmentMap();
    const endpointHosts = hosts(4_000, 'e');
    const conversationHosts = hosts(4_000, 'c');
    map.setCurrentHosts(endpointHosts, conversationHosts);
    const current = [...endpointHosts, ...conversationHosts];
    for (const host of current) map.record(result(host));
    for (const host of hosts(3_000, 'idle')) map.record(result(host));
    expect(map.size).toBe(9_000);
    expect(current.every((host) => map.get(host) !== undefined)).toBe(true);
    map.setCurrentHosts(endpointHosts, conversationHosts);
    expect(current.every((host) => map.get(host) !== undefined)).toBe(true);
    expect(map.size).toBeLessThanOrEqual(9_000);
    // All 8,000 leave at once: only the idle allowance is left.
    map.setCurrentHosts([], []);
    expect(map.size).toBe(1_000);
  });

  it('a host in either list alone is current, and one in both counts once', () => {
    const map = new EnrichmentMap();
    map.setCurrentHosts(['e', 'both'], ['c', 'both']);
    for (const host of ['e', 'c', 'both']) map.record(result(host));
    for (const host of hosts(2_000)) map.record(result(host));
    expect(map.size).toBe(1_003);
    expect(['e', 'c', 'both'].every((host) => map.get(host) !== undefined)).toBe(true);
  });

  it('an idle host that becomes current again leaves the idle allowance', () => {
    const map = new EnrichmentMap();
    const all = hosts(1_000);
    for (const host of all) map.record(result(host));
    map.setCurrentHosts([all[0], all[1]], []);
    expect(map.size).toBe(1_000);
    map.record(result('x'));
    map.record(result('y'));
    expect(map.size).toBe(1_002);
    expect([...all, 'x', 'y'].every((host) => map.get(host) !== undefined)).toBe(true);
  });

  it('holds nothing for hosts that were never looked up', () => {
    const map = new EnrichmentMap();
    map.setCurrentHosts(hosts(100), hosts(100, 'c'));
    expect(map.size).toBe(0);
  });
});
