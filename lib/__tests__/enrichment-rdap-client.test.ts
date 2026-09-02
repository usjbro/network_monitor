// lib/__tests__/enrichment-rdap-client.test.ts
import { describe, expect, it, vi } from 'vitest';
import { RdapClient, computeBackoffDelayMs } from '../enrichment/rdap-client';

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers });
}

describe('computeBackoffDelayMs', () => {
  it('follows the 30s-start, doubling, 30min-cap schedule', () => {
    expect(computeBackoffDelayMs(1)).toBe(30_000);
    expect(computeBackoffDelayMs(2)).toBe(60_000);
    expect(computeBackoffDelayMs(3)).toBe(120_000);
    expect(computeBackoffDelayMs(10)).toBe(30 * 60_000); // capped
  });
  it('honors Retry-After when it is larger than the computed default', () => {
    expect(computeBackoffDelayMs(1, 90)).toBe(90_000);
    expect(computeBackoffDelayMs(1, 5)).toBe(30_000); // default still wins if larger
  });
});

describe('RdapClient', () => {
  it('never follows a 3xx redirect — redirect:"manual" is honored, not just configured', async () => {
    const fetchImpl = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(init?.redirect).toBe('manual');
      return new Response(null, { status: 0, statusText: '', headers: {} }) as Response & { type: string };
    });
    // Simulate what Node's fetch actually returns for redirect:'manual': an
    // opaqueredirect response (status 0, type 'opaqueredirect'), not a thrown
    // error and not the 3xx status directly.
    Object.defineProperty(fetchImpl.mock.results, 'x', { value: undefined, configurable: true }); // no-op, keep TS quiet
    const client = new RdapClient(async (url, init) => {
      expect(init?.redirect).toBe('manual');
      const r = new Response(null, { status: 302 });
      Object.defineProperty(r, 'type', { value: 'opaqueredirect' });
      return r;
    });

    const result = await client.fetch('https://rdap.arin.net/registry/ip/93.184.216.34');
    expect(result).toEqual({ ok: false, reason: 'redirect', status: undefined });
  });

  it('aborts a response exceeding the 256KB cap and treats it as a failure', async () => {
    const bigChunk = new Uint8Array(300 * 1024); // 300KB > 256KB cap
    const fetchImpl = (async () => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bigChunk);
          controller.close();
        },
      });
      return new Response(stream, { status: 200 });
    }) as typeof fetch;

    const client = new RdapClient(fetchImpl);
    const result = await client.fetch('https://rdap.arin.net/registry/ip/93.184.216.34');
    expect(result).toEqual({ ok: false, reason: 'too_large' });
  });

  it('aborts at the 10-second timeout when the registry never responds', async () => {
    vi.useFakeTimers();
    const fetchImpl = ((_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      })) as typeof fetch;

    const client = new RdapClient(fetchImpl);
    const resultPromise = client.fetch('https://rdap.arin.net/registry/ip/93.184.216.34');
    await vi.advanceTimersByTimeAsync(10_000);
    const result = await resultPromise;
    expect(result).toEqual({ ok: false, reason: 'timeout' });
    vi.useRealTimers();
  });

  it('trips the circuit breaker after 3 consecutive 429s within 10 minutes and holds the 1hr cooldown', async () => {
    let now = 0;
    const fetchImpl = (async () => jsonResponse({}, 429)) as typeof fetch;
    const client = new RdapClient(fetchImpl, () => now);

    await client.fetch('https://rdap.arin.net/x'); // 429 #1
    now += 60_000;
    await client.fetch('https://rdap.arin.net/x'); // 429 #2 (backoff window may block the *dispatch* in the real queue, but this client's own state machine is what's under test here — advance past any self-imposed backoffUntil too)
    now += 200_000;
    const third = await client.fetch('https://rdap.arin.net/x'); // 429 #3, within the 10-minute window
    expect(third).toMatchObject({ reason: 'http_error', status: 429 });

    now += 1000; // still well within the 1hr cooldown
    const duringCooldown = await client.fetch('https://rdap.arin.net/x');
    expect(duringCooldown).toEqual({ ok: false, reason: 'circuit_open' });

    now += 60 * 60_000 + 1;
    const afterCooldown = await client.fetch('https://rdap.arin.net/x');
    expect(afterCooldown).not.toEqual({ ok: false, reason: 'circuit_open' });
  });

  it('returns parsed JSON on a normal 200 response', async () => {
    const fetchImpl = (async () => jsonResponse({ objectClassName: 'ip network' })) as typeof fetch;
    const client = new RdapClient(fetchImpl);
    const result = await client.fetch('https://rdap.arin.net/registry/ip/93.184.216.34');
    expect(result).toEqual({ ok: true, json: { objectClassName: 'ip network' } });
  });

  describe('fetchWithReferral (Task 13, response-controlled SSRF hardening)', () => {
    it('follows a referral link only if its host is on the allowlist', async () => {
      const registryResponse = { objectClassName: 'domain', links: [{ rel: 'related', href: 'https://rdap.verisign.com/com/v1/domain/example.com' }] };
      const registrarResponse = { objectClassName: 'domain', entities: [] };
      const calls: string[] = [];
      const fetchImpl = (async (url: string) => {
        calls.push(url);
        if (calls.length === 1) return jsonResponse(registryResponse);
        return jsonResponse(registrarResponse);
      }) as typeof fetch;

      const client = new RdapClient(fetchImpl);
      const result = await client.fetchWithReferral('https://rdap.example-registry.test/domain/example.com');
      expect(calls).toContain('https://rdap.verisign.com/com/v1/domain/example.com');
      expect(result).toMatchObject({ ok: true, referralFollowed: true, json: registrarResponse });
    });

    it('never dials a referral to a non-allowlisted host, including a loopback address', async () => {
      const registryResponse = { objectClassName: 'domain', links: [{ rel: 'related', href: 'http://127.0.0.1:9990/pause' }] };
      const calls: string[] = [];
      const fetchImpl = (async (url: string) => {
        calls.push(url);
        return jsonResponse(registryResponse);
      }) as typeof fetch;

      const client = new RdapClient(fetchImpl);
      const result = await client.fetchWithReferral('https://rdap.example-registry.test/domain/example.com');
      // only the first call — the loopback referral was never dialed
      expect(calls).toEqual(['https://rdap.example-registry.test/domain/example.com']);
      expect(result).toMatchObject({ referralFollowed: false });
    });

    it('returns the registry response unchanged (with referralFollowed:false) when there is no referral link at all', async () => {
      const registryResponse = { objectClassName: 'domain', entities: [] };
      const fetchImpl = (async () => jsonResponse(registryResponse)) as typeof fetch;
      const client = new RdapClient(fetchImpl);
      const result = await client.fetchWithReferral('https://rdap.example-registry.test/domain/example.com');
      expect(result).toMatchObject({ ok: true, referralFollowed: false, json: registryResponse });
    });

    it('propagates a failure from the initial registry fetch without attempting any referral', async () => {
      const fetchImpl = (async () => jsonResponse({}, 500)) as typeof fetch;
      const client = new RdapClient(fetchImpl);
      const result = await client.fetchWithReferral('https://rdap.example-registry.test/domain/example.com');
      expect(result).toEqual({ ok: false, reason: 'http_error', status: 500 });
    });
  });
});
