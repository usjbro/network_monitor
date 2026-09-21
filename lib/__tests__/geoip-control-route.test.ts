// Coverage for /api/geoip/control — the action allowlist and dispatch to
// the shared GeoIpClient singleton, plus the cross-site guard (JAM-151)
// this route applies like /api/control.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { NextRequest } from 'next/server';
import { POST } from '@/app/api/geoip/control/route';
import type { GeoIpClient } from '@/lib/geoip';

function req(body: unknown, headers: Record<string, string> = { 'sec-fetch-site': 'same-origin' }): NextRequest {
  return {
    url: 'http://127.0.0.1:3000/api/geoip/control',
    headers: new Headers(headers),
    json: async () => body,
  } as unknown as NextRequest;
}

describe('POST /api/geoip/control', () => {
  let enable: ReturnType<typeof vi.fn>;
  let disable: ReturnType<typeof vi.fn>;
  let clear: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    // Unlike EnrichmentClient.enable() (returns {disclosureText}),
    // GeoIpClient.enable() returns a plain string — the route spreads it
    // under a `disclosure` key, not object-spread like the enrichment route.
    enable = vi.fn(() => 'geoip enabled, using a third-party IP geolocation lookup');
    disable = vi.fn();
    clear = vi.fn(async () => {});
    global.__geoIpClient = { enable, disable, clear } as unknown as GeoIpClient;
  });

  afterEach(() => {
    global.__geoIpClient = undefined;
  });

  it('dispatches enable and returns its disclosure string under `disclosure`', async () => {
    const res = await POST(req({ action: 'enable' }));
    const json = await res.json();

    expect(res.status).toBe(200);
    expect(enable).toHaveBeenCalled();
    expect(json).toEqual({ ok: true, disclosure: 'geoip enabled, using a third-party IP geolocation lookup' });
  });

  it('dispatches disable', async () => {
    const res = await POST(req({ action: 'disable' }));

    expect(res.status).toBe(200);
    expect(disable).toHaveBeenCalled();
  });

  it('dispatches clear', async () => {
    const res = await POST(req({ action: 'clear' }));

    expect(res.status).toBe(200);
    expect(clear).toHaveBeenCalled();
  });

  it('rejects an action not on the allowlist without touching the client', async () => {
    const res = await POST(req({ action: 'nonexistent' }));

    expect(res.status).toBe(400);
    expect(enable).not.toHaveBeenCalled();
    expect(disable).not.toHaveBeenCalled();
  });

  it('rejects a cross-site request with 403 before touching the client', async () => {
    const res = await POST(req({ action: 'enable' }, { 'sec-fetch-site': 'cross-site' }));

    expect(res.status).toBe(403);
    expect(enable).not.toHaveBeenCalled();
  });
});
