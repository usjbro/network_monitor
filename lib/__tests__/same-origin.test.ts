// Coverage for the cross-site guard (JAM-151) — both the policy itself and
// its application to every state-changing POST route.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { NextRequest } from 'next/server';
import { isCrossSiteRequest } from '@/lib/same-origin';
import { POST as controlPOST } from '@/app/api/control/route';
import { POST as traceroutePOST } from '@/app/api/traceroute/start/route';
import type { AgentClient } from '@/lib/agent-client';

/** A NextRequest stand-in: these routes read only `url`, `headers`, `json()`. */
function req(headers: Record<string, string>, body: unknown = {}, url = 'http://127.0.0.1:3000/api/control'): NextRequest {
  return {
    url,
    headers: new Headers(headers),
    json: async () => body,
  } as unknown as NextRequest;
}

describe('isCrossSiteRequest', () => {
  it('allows the app’s own page fetch (Sec-Fetch-Site: same-origin)', () => {
    expect(isCrossSiteRequest(req({ 'sec-fetch-site': 'same-origin' }))).toBe(false);
  });

  it('allows a user-initiated request (Sec-Fetch-Site: none)', () => {
    expect(isCrossSiteRequest(req({ 'sec-fetch-site': 'none' }))).toBe(false);
  });

  it('rejects a cross-site request — the actual attack', () => {
    expect(isCrossSiteRequest(req({ 'sec-fetch-site': 'cross-site' }))).toBe(true);
  });

  it('rejects same-site too, because site ignores port on loopback', () => {
    // http://localhost:9999 and http://localhost:3000 are *same-site*:
    // Sec-Fetch-Site is computed from the registrable domain and does not
    // consider the port. Another local service must not be trusted.
    expect(isCrossSiteRequest(req({ 'sec-fetch-site': 'same-site' }))).toBe(true);
  });

  it('falls back to comparing Origin when Sec-Fetch-Site is absent', () => {
    expect(isCrossSiteRequest(req({ origin: 'http://127.0.0.1:3000' }))).toBe(false);
    expect(isCrossSiteRequest(req({ origin: 'https://evil.example' }))).toBe(true);
    // Same host, different port is a different origin.
    expect(isCrossSiteRequest(req({ origin: 'http://127.0.0.1:9999' }))).toBe(true);
  });

  it('rejects an unparseable Origin rather than giving it the benefit of the doubt', () => {
    expect(isCrossSiteRequest(req({ origin: 'not a url' }))).toBe(true);
  });

  it('allows a request carrying neither header — a non-browser client', () => {
    // bin/osi-inspect.js POSTs register_decrypt_eligible with only a
    // Content-Type header. A browser always attaches Origin or
    // Sec-Fetch-Site to a cross-origin POST, so their joint absence is not
    // the attack this guards against, and rejecting would break that CLI.
    expect(isCrossSiteRequest(req({ 'content-type': 'application/json' }))).toBe(false);
  });

  it('prefers Sec-Fetch-Site over a spoofable-looking Origin', () => {
    // Page script cannot set either header, but if they ever disagree the
    // browser-set navigation signal is the one to trust.
    expect(isCrossSiteRequest(req({ 'sec-fetch-site': 'cross-site', origin: 'http://127.0.0.1:3000' }))).toBe(true);
  });
});

describe('routes reject cross-site requests before doing anything', () => {
  let sendControl: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    sendControl = vi.fn();
    global.__agentClient = { sendControl } as unknown as AgentClient;
  });
  afterEach(() => {
    global.__agentClient = undefined;
  });

  it('/api/control refuses a cross-site start_capture_file with 403', async () => {
    const res = await controlPOST(
      req({ 'sec-fetch-site': 'cross-site' }, { type: 'start_capture_file', path: '/tmp/evil.pcapng' })
    );

    expect(res.status).toBe(403);
    // The agent must never have been told anything.
    expect(sendControl).not.toHaveBeenCalled();
  });

  it('/api/control still accepts the same request same-origin', async () => {
    const res = await controlPOST(
      req({ 'sec-fetch-site': 'same-origin' }, { type: 'start_capture_file', path: '/tmp/ok.pcapng' })
    );

    expect(res.status).toBe(200);
    expect(sendControl).toHaveBeenCalledWith({ type: 'start_capture_file', path: '/tmp/ok.pcapng' });
  });

  it('/api/traceroute/start refuses a cross-site trace', async () => {
    const res = await traceroutePOST(
      req({ 'sec-fetch-site': 'cross-site' }, { remoteAddr: '93.184.216.34' }, 'http://127.0.0.1:3000/api/traceroute/start')
    );

    expect(res.status).toBe(403);
    expect(sendControl).not.toHaveBeenCalled();
  });

  it('/api/traceroute/start still accepts a same-origin trace', async () => {
    const res = await traceroutePOST(
      req({ 'sec-fetch-site': 'same-origin' }, { remoteAddr: '93.184.216.34' }, 'http://127.0.0.1:3000/api/traceroute/start')
    );

    expect(res.status).toBe(200);
    expect(sendControl).toHaveBeenCalledWith({ type: 'trace_route', targetIp: '93.184.216.34' });
  });
});
