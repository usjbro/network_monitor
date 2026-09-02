// lib/__tests__/enrichment-reverse-dns.test.ts
import { describe, expect, it, vi } from 'vitest';
import { reverseDnsLookup } from '../enrichment/reverse-dns';

describe('reverseDnsLookup', () => {
  it('returns the resolved hostname on success', async () => {
    const resolveFn = vi.fn(async () => ['example.com']);
    const result = await reverseDnsLookup('93.184.216.34', { resolveFn: resolveFn as never });
    expect(result).toBe('example.com');
  });

  it('returns null (not a thrown error) when the resolver has no PTR record', async () => {
    const resolveFn = vi.fn(async () => { throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' }); });
    const result = await reverseDnsLookup('93.184.216.34', { resolveFn: resolveFn as never });
    expect(result).toBeNull();
  });

  it('times out and returns null rather than hanging, when given a short timeout', async () => {
    const resolveFn = vi.fn(() => new Promise<string[]>(() => {})); // never resolves
    const result = await reverseDnsLookup('93.184.216.34', { timeoutMs: 20, resolveFn: resolveFn as never });
    expect(result).toBeNull();
  });

  it('never calls the real dns.promises.reverse when resolveFn is injected — proves tests stay offline', async () => {
    const resolveFn = vi.fn(async () => ['example.net']);
    await reverseDnsLookup('203.0.113.9', { resolveFn: resolveFn as never });
    expect(resolveFn).toHaveBeenCalledWith('203.0.113.9');
    expect(resolveFn).toHaveBeenCalledTimes(1);
  });

  it('defaults timeoutMs to 10s when not specified (does not fire early)', async () => {
    vi.useFakeTimers();
    try {
      const resolveFn = vi.fn(() => new Promise<string[]>(() => {})); // never resolves
      const resultPromise = reverseDnsLookup('93.184.216.34', { resolveFn: resolveFn as never });
      await vi.advanceTimersByTimeAsync(9_000);
      // Not yet timed out at 9s.
      let settled = false;
      resultPromise.then(() => { settled = true; });
      await Promise.resolve();
      expect(settled).toBe(false);

      await vi.advanceTimersByTimeAsync(2_000); // cross the 10s mark
      const result = await resultPromise;
      expect(result).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});
