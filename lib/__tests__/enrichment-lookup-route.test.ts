// Coverage for /api/enrichment/lookup — request-body validation, dispatch
// to the shared EnrichmentClient singleton, and (JAM-178) the same
// rejectIfCrossSite guard as its sibling routes: while enrichment is on, a
// lookup sends real outbound RDAP/WHOIS queries, which a foreign page must
// not be able to trigger.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { NextRequest } from 'next/server';
import { POST } from '@/app/api/enrichment/lookup/route';
import type { EnrichmentClient } from '@/lib/enrichment';

function req(body: unknown, headers: Record<string, string> = { 'sec-fetch-site': 'same-origin' }): NextRequest {
  return {
    url: 'http://127.0.0.1:3000/api/enrichment/lookup',
    headers: new Headers(headers),
    json: async () => body,
  } as unknown as NextRequest;
}

describe('POST /api/enrichment/lookup', () => {
  let requestLookup: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    requestLookup = vi.fn();
    global.__enrichmentClient = { requestLookup } as unknown as EnrichmentClient;
  });

  afterEach(() => {
    global.__enrichmentClient = undefined;
  });

  it('forwards a valid connectionId/remoteAddr pair to the client', async () => {
    const res = await POST(req({ connectionId: 'conn-1', remoteAddr: '93.184.216.34' }));

    expect(res.status).toBe(200);
    expect(requestLookup).toHaveBeenCalledWith('conn-1', '93.184.216.34');
  });

  it.each([
    ['missing connectionId', { remoteAddr: '93.184.216.34' }],
    ['missing remoteAddr', { connectionId: 'conn-1' }],
    ['a non-string connectionId', { connectionId: 42, remoteAddr: '93.184.216.34' }],
    ['a non-string remoteAddr', { connectionId: 'conn-1', remoteAddr: 42 }],
  ])('rejects %s with 400 without touching the client', async (_label, body) => {
    const res = await POST(req(body));

    expect(res.status).toBe(400);
    expect(requestLookup).not.toHaveBeenCalled();
  });

  it.each([
    ['Sec-Fetch-Site: cross-site', { 'sec-fetch-site': 'cross-site' }],
    ['a foreign Origin', { origin: 'https://attacker.example' }],
  ])('refuses a cross-site lookup (%s) with 403 without touching the client', async (_label, headers) => {
    const res = await POST(req({ connectionId: 'conn-1', remoteAddr: '93.184.216.34' }, headers));

    expect(res.status).toBe(403);
    expect(requestLookup).not.toHaveBeenCalled();
  });

  it('still accepts a non-browser caller that sends neither header', async () => {
    const res = await POST(req({ connectionId: 'conn-1', remoteAddr: '93.184.216.34' }, {}));

    expect(res.status).toBe(200);
    expect(requestLookup).toHaveBeenCalledWith('conn-1', '93.184.216.34');
  });
});
