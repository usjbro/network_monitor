// Coverage for /api/enrichment/control — the action allowlist and its
// dispatch to the shared EnrichmentClient singleton, plus the cross-site
// guard (JAM-151) this route applies like /api/control.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { NextRequest } from 'next/server';
import { POST as postHandler } from '@/app/api/enrichment/control/route';
import type { EnrichmentClient } from '@/lib/enrichment';

function req(body: unknown, headers: Record<string, string> = { 'sec-fetch-site': 'same-origin' }): NextRequest {
  return {
    url: 'http://127.0.0.1:3000/api/enrichment/control',
    headers: new Headers(headers),
    json: async () => body,
  } as unknown as NextRequest;
}

// The route's switch has no `default`, so TS can't prove every action in
// VALID_ACTIONS returns — its inferred type is `NextResponse | undefined`.
// This wrapper turns that into a real (never-hit-in-practice) failure
// rather than requiring a non-null assertion at every call site below.
async function POST(request: NextRequest) {
  const res = await postHandler(request);
  if (!res) throw new Error('POST /api/enrichment/control returned no response');
  return res;
}

describe('POST /api/enrichment/control', () => {
  let enable: ReturnType<typeof vi.fn>;
  let enableBackground: ReturnType<typeof vi.fn>;
  let disable: ReturnType<typeof vi.fn>;
  let disableBackground: ReturnType<typeof vi.fn>;
  let clear: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    enable = vi.fn(() => ({ disclosureText: 'enrichment enabled' }));
    enableBackground = vi.fn(() => ({ disclosureText: 'background enrichment enabled' }));
    disable = vi.fn();
    disableBackground = vi.fn();
    clear = vi.fn(async () => {});
    global.__enrichmentClient = {
      enable,
      enableBackground,
      disable,
      disableBackground,
      clear,
    } as unknown as EnrichmentClient;
  });

  afterEach(() => {
    global.__enrichmentClient = undefined;
  });

  it('dispatches enable and spreads its disclosure text into the response', async () => {
    const res = await POST(req({ action: 'enable' }));
    const json = await res.json();

    expect(res.status).toBe(200);
    expect(enable).toHaveBeenCalled();
    expect(json).toEqual({ ok: true, disclosureText: 'enrichment enabled' });
  });

  it('dispatches enable_background and spreads its disclosure text into the response', async () => {
    const res = await POST(req({ action: 'enable_background' }));
    const json = await res.json();

    expect(res.status).toBe(200);
    expect(enableBackground).toHaveBeenCalled();
    expect(json).toEqual({ ok: true, disclosureText: 'background enrichment enabled' });
  });

  it('dispatches disable', async () => {
    const res = await POST(req({ action: 'disable' }));

    expect(res.status).toBe(200);
    expect(disable).toHaveBeenCalled();
  });

  it('dispatches disable_background', async () => {
    const res = await POST(req({ action: 'disable_background' }));

    expect(res.status).toBe(200);
    expect(disableBackground).toHaveBeenCalled();
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
