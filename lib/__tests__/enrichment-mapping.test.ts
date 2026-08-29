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
