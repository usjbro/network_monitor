// lib/__tests__/geoip-mapping.test.ts
import { describe, expect, it } from 'vitest';
import { buildGeoHopEvent } from '../geoip-mapping';

describe('buildGeoHopEvent', () => {
  it('builds a camelCase geo_hop_update event with a resolved location', () => {
    const event = buildGeoHopEvent('12.122.1.1', 4, '93.184.216.34', { city: 'Ashburn', country: 'US', source: 'geoip' });
    expect(event).toEqual({
      type: 'geo_hop_update',
      targetIp: '93.184.216.34',
      hopNumber: 4,
      hopIp: '12.122.1.1',
      location: { city: 'Ashburn', country: 'US', source: 'geoip' },
    });
  });

  it('carries a null location through when the lookup failed', () => {
    const event = buildGeoHopEvent('12.122.1.1', 4, '93.184.216.34', null);
    expect(event.location).toBeNull();
  });
});
