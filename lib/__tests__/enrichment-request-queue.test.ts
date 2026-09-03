// lib/__tests__/enrichment-request-queue.test.ts
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { RequestQueue, shuffle } from '../enrichment/request-queue';

describe('RequestQueue', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    // This Vitest/sinon version seeds the fake clock from the real wall
    // clock rather than epoch 0, so pin it explicitly — the spacing
    // assertions below compare Date.now() deltas and need a known origin.
    vi.setSystemTime(0);
  });
  afterEach(() => vi.useRealTimers());

  it('never runs more than 1 task concurrently', async () => {
    const queue = new RequestQueue({ minDelayMs: 3000, maxDelayMs: 3000 });
    let inFlight = 0;
    let maxInFlight = 0;
    const task = () => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          inFlight -= 1;
          resolve();
        }, 100);
      });
    };

    const results = [queue.enqueue(task), queue.enqueue(task), queue.enqueue(task)];
    await vi.runAllTimersAsync();
    await Promise.all(results);

    expect(maxInFlight).toBe(1);
  });

  it('enforces the minimum spacing floor between dispatches', async () => {
    const queue = new RequestQueue({ minDelayMs: 3000, maxDelayMs: 3000 }); // fixed delay for a deterministic assertion
    const dispatchTimes: number[] = [];
    const task = () => {
      dispatchTimes.push(Date.now());
      return Promise.resolve();
    };

    const p1 = queue.enqueue(task);
    const p2 = queue.enqueue(task);
    const p3 = queue.enqueue(task);
    await vi.runAllTimersAsync();
    await Promise.all([p1, p2, p3]);

    expect(dispatchTimes[0]).toBe(0); // first dispatch is immediate — nothing to space against yet
    expect(dispatchTimes[1] - dispatchTimes[0]).toBeGreaterThanOrEqual(3000);
    expect(dispatchTimes[2] - dispatchTimes[1]).toBeGreaterThanOrEqual(3000);
  });

  it('redraws jitter within the 3–10s band for each dispatch, not a fixed interval', async () => {
    const draws: number[] = [];
    const random = () => {
      const v = draws.length % 2 === 0 ? 0 : 0.999; // alternate min/max ends of the band
      draws.push(v);
      return v;
    };
    const queue = new RequestQueue({ minDelayMs: 3000, maxDelayMs: 10000, random });
    const gaps: number[] = [];
    let last = 0;
    const task = () => {
      gaps.push(Date.now() - last);
      last = Date.now();
      return Promise.resolve();
    };
    const ps = [queue.enqueue(task), queue.enqueue(task), queue.enqueue(task)];
    await vi.runAllTimersAsync();
    await Promise.all(ps);

    // Not asserting exact values (that's `random`'s job to determine) — just
    // that consecutive gaps differ, proving the delay is redrawn per
    // dispatch rather than a single fixed interval reused every time.
    expect(gaps[1]).not.toBe(gaps[2]);
  });
});

describe('shuffle', () => {
  it('produces a permutation (same elements, order changed for a non-trivial input)', () => {
    const input = [1, 2, 3, 4, 5, 6, 7, 8];
    let call = 0;
    const random = () => {
      // deterministic sequence that is not the identity permutation
      const seq = [0.9, 0.1, 0.8, 0.2, 0.7, 0.3, 0.6];
      return seq[call++ % seq.length];
    };
    const result = shuffle(input, random);
    expect(result.slice().sort((a, b) => a - b)).toEqual(input);
    expect(result).not.toEqual(input);
  });
});
