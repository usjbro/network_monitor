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
    ['::ffff:127.0.0.1', true],       // IPv4-mapped loopback
    ['::ffff:192.168.1.10', true],    // IPv4-mapped RFC1918
    ['::ffff:169.254.169.254', true], // IPv4-mapped link-local (cloud metadata)
    ['::ffff:8.8.8.8', false],        // IPv4-mapped public
    ['::93.184.216.34', false],       // bare-mapped (deprecated form) public
    // Malformed embedded IPv4 (octet > 255): the extraction regex's \d{1,3}
    // groups match this syntactically, but it's not a real IPv4 address —
    // must fail closed (treated as reserved/blocked), not fall through to
    // "not private" just because it doesn't match any real CIDR block.
    ['::ffff:999.1.1.1', true],
  ];
  it.each(cases)('isPrivateOrReserved(%s) === %s', (ip, expected) => {
    expect(isPrivateOrReserved(ip)).toBe(expected);
  });
});
