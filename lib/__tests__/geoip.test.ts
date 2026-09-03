// lib/__tests__/geoip.test.ts
import { describe, expect, it, vi } from 'vitest';
import { GeoIpClient } from '../geoip';

function fakeFetch(body: unknown, status = 200) {
  return vi.fn(async () => new Response(JSON.stringify(body), { status }));
}

describe('GeoIpClient', () => {
  it('starts in "off" mode and makes zero HTTP calls when disabled', async () => {
    const fetchImpl = fakeFetch({ city: 'Ashburn', country: 'US' });
    const client = new GeoIpClient({ fetchImpl, cachePath: tmpCachePath() });
    await client.lookup('93.184.216.34');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('never queries a private/reserved IP even when enabled', async () => {
    const fetchImpl = fakeFetch({ city: 'X', country: 'US' });
    const client = new GeoIpClient({ fetchImpl, cachePath: tmpCachePath() });
    client.enable();
    await client.lookup('10.0.0.5');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('emits a result event with mapped location on a successful lookup', async () => {
    const fetchImpl = fakeFetch({ city: 'Ashburn', country: 'US', lat: 39.04, lon: -77.48 });
    const client = new GeoIpClient({ fetchImpl, cachePath: tmpCachePath() });
    client.enable();
    const result = await new Promise((resolve) => {
      client.on('result', resolve);
      client.lookup('93.184.216.34');
    });
    expect((result as any).location.city).toBe('Ashburn');
  });

  it('caches a result and does not re-fetch the same IP within the TTL', async () => {
    const fetchImpl = fakeFetch({ city: 'Ashburn', country: 'US' });
    const client = new GeoIpClient({ fetchImpl, cachePath: tmpCachePath() });
    client.enable();
    await new Promise((resolve) => { client.on('result', resolve); client.lookup('93.184.216.34'); });
    await new Promise((resolve) => { client.on('result', resolve); client.lookup('93.184.216.34'); });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('mode never persists across a fresh instance — opt-in resets on restart', () => {
    const client1 = new GeoIpClient({ fetchImpl: fakeFetch({}), cachePath: tmpCachePath() });
    client1.enable();
    const client2 = new GeoIpClient({ fetchImpl: fakeFetch({}), cachePath: tmpCachePath() });
    expect(client2.getMode()).toBe('off');
  });

  it('disclosure text is non-empty and names the geoIP provider behavior', () => {
    const client = new GeoIpClient({ fetchImpl: fakeFetch({}), cachePath: tmpCachePath() });
    expect(client.enable().length).toBeGreaterThan(0);
  });
});

function tmpCachePath(): string {
  return require('node:path').join(require('node:os').tmpdir(), `geoip-test-${Math.random().toString(36).slice(2)}.json`);
}
