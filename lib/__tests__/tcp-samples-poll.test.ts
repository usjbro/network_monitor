// KAN-129 Task 4: the TCP graphs poller. Once per second with nextIndex,
// at most 4 immediate follow-ups for `more: true`, one request in flight,
// restart on stale, stop on close or when the flow is gone.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { TcpSamplesPoller, fetchTcpSamples, type FetchResult } from '../tcp-samples-poll';
import type { TcpGraphState, TcpSamplesQuery } from '../tcp-graphs';
import type { TcpSample, TcpSamplesPage } from '../types';

const ID = 'Tcp-192.168.1.10:51000-93.184.216.34:443';
const GEN = '00000000feedbeef:3';

function sample(i: number): TcpSample {
  return { tUs: 1_794_120_000_000_000 + i, seq: i, ack: 0, win: 100, len: 1, flags: 16, mark: 1, rttUs: 0, outbound: true };
}

function page(fromIndex: number, count: number, more: boolean, generation = GEN): TcpSamplesPage {
  return {
    found: true, stale: false, connectionId: ID, generation, handshakeSeen: true, windowScale: null,
    seqBase: { outbound: 0, inbound: 0 }, relativeTo: 'isn', firstIndex: 0, nextIndex: fromIndex + count, more, droppedOlder: 0,
    samples: Array.from({ length: count }, (_, i) => sample(fromIndex + i)),
  };
}

type Pending = { query: TcpSamplesQuery; signal: AbortSignal; resolve: (r: FetchResult) => void };

function harness() {
  const pending: Pending[] = [];
  const queries: TcpSamplesQuery[] = [];
  const fetch = vi.fn((query: TcpSamplesQuery, signal: AbortSignal) => {
    queries.push(query);
    return new Promise<FetchResult>((resolve) => pending.push({ query, signal, resolve }));
  });
  const states: TcpGraphState[] = [];
  const errors: (number | null)[] = [];
  const poller = new TcpSamplesPoller(ID, fetch, { onState: (s) => states.push(s), onError: (e) => errors.push(e) });
  /** Answers the oldest pending request and lets the poller react. */
  async function answer(r: FetchResult) {
    const next = pending.shift();
    if (!next) throw new Error('no request pending');
    next.resolve(r);
    await vi.advanceTimersByTimeAsync(0);
  }
  return { poller, fetch, pending, queries, states, errors, answer };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe('TcpSamplesPoller', () => {
  it('asks from 0, then once per second from nextIndex with the generation', async () => {
    const h = harness();
    h.poller.start();
    expect(h.queries).toEqual([{ connectionId: ID, fromIndex: 0 }]);
    await h.answer({ ok: true, page: page(0, 5, false) });
    expect(h.states.at(-1)?.samples).toHaveLength(5);
    await vi.advanceTimersByTimeAsync(999);
    expect(h.queries).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(h.queries[1]).toEqual({ connectionId: ID, generation: GEN, fromIndex: 5 });
  });

  it('follows more:true at once, at most 4 times per tick', async () => {
    const h = harness();
    h.poller.start();
    for (let i = 0; i < 5; i++) await h.answer({ ok: true, page: page(i * 10, 10, true) });
    // 1 + 4 follow-ups, then it waits for the next tick despite `more`.
    expect(h.queries.map((q) => q.fromIndex)).toEqual([0, 10, 20, 30, 40]);
    expect(h.pending).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.queries.map((q) => q.fromIndex)).toEqual([0, 10, 20, 30, 40, 50]);
  });

  it('keeps one request in flight however long it takes', async () => {
    const h = harness();
    h.poller.start();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(h.fetch).toHaveBeenCalledTimes(1);
  });

  it('restarts from 0 at once when the reply is stale', async () => {
    const h = harness();
    h.poller.start();
    await h.answer({ ok: true, page: page(0, 5, false) });
    await vi.advanceTimersByTimeAsync(1000);
    await h.answer({ ok: true, page: { found: true, stale: true, connectionId: ID, generation: '00000000feedbeef:4' } });
    expect(h.queries.at(-1)).toEqual({ connectionId: ID, fromIndex: 0 });
    expect(h.states.at(-1)?.samples).toEqual([]);
  });

  it('reports a retryable error, keeps the samples, and clears it on success', async () => {
    const h = harness();
    h.poller.start();
    await h.answer({ ok: true, page: page(0, 5, false) });
    await vi.advanceTimersByTimeAsync(1000);
    await h.answer({ ok: false, status: 429 });
    expect(h.errors.at(-1)).toBe(429);
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.queries.at(-1)).toEqual({ connectionId: ID, generation: GEN, fromIndex: 5 });
    await h.answer({ ok: true, page: page(5, 1, false) });
    expect(h.errors.at(-1)).toBeNull();
    expect(h.states.at(-1)?.samples).toHaveLength(6);
  });

  it('stops polling once the flow is no longer found', async () => {
    const h = harness();
    h.poller.start();
    await h.answer({ ok: true, page: page(0, 5, false) });
    await vi.advanceTimersByTimeAsync(1000);
    await h.answer({ ok: true, page: { found: false, connectionId: ID } });
    expect(h.states.at(-1)?.found).toBe(false);
    await vi.advanceTimersByTimeAsync(5000);
    expect(h.fetch).toHaveBeenCalledTimes(2);
  });

  it('stops on close: aborts the request in flight and ignores its answer', async () => {
    const h = harness();
    h.poller.start();
    const inFlight = h.pending[0];
    h.poller.stop();
    expect(inFlight.signal.aborted).toBe(true);
    const seen = h.states.length;
    await h.answer({ ok: true, page: page(0, 5, false) });
    await vi.advanceTimersByTimeAsync(5000);
    expect(h.states.length).toBe(seen);
    expect(h.fetch).toHaveBeenCalledTimes(1);
  });

  it('resumes from where it was after stop and start', async () => {
    const h = harness();
    h.poller.start();
    await h.answer({ ok: true, page: page(0, 5, false) });
    h.poller.stop();
    h.poller.start();
    expect(h.queries.at(-1)).toEqual({ connectionId: ID, generation: GEN, fromIndex: 5 });
  });
});

describe('fetchTcpSamples', () => {
  const reply = {
    type: 'tcp_samples', connectionId: ID, found: true, stale: false, generation: GEN, handshakeSeen: true, windowScale: null,
    seqBase: { outbound: 0, inbound: 0 }, relativeTo: 'isn', firstIndex: 0, nextIndex: 1, more: false, droppedOlder: 0,
    samples: { tUs: [5], seq: [0], ack: [0], win: [1], len: [0], flags: [2], mark: [1], rttUs: [0] },
  };

  it('POSTs the query as JSON and maps the reply', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(reply), { status: 200 }));
    const signal = new AbortController().signal;
    const result = await fetchTcpSamples({ connectionId: ID, fromIndex: 0 }, signal, fetchImpl);
    expect(fetchImpl).toHaveBeenCalledWith('/api/tcp-samples', expect.objectContaining({
      method: 'POST', body: JSON.stringify({ connectionId: ID, fromIndex: 0 }), signal,
      headers: { 'Content-Type': 'application/json' },
    }));
    expect(result).toMatchObject({ ok: true, page: { found: true, nextIndex: 1 } });
  });

  it('returns the HTTP status of a refusal', async () => {
    const fetchImpl = vi.fn(async () => new Response('{"error":"busy"}', { status: 429 }));
    expect(await fetchTcpSamples({ connectionId: ID, fromIndex: 0 }, new AbortController().signal, fetchImpl)).toEqual({ ok: false, status: 429 });
  });

  it('treats a malformed reply as a bad gateway and a network failure as status 0', async () => {
    const bad = vi.fn(async () => new Response(JSON.stringify({ ...reply, samples: { tUs: [1] } }), { status: 200 }));
    expect(await fetchTcpSamples({ connectionId: ID, fromIndex: 0 }, new AbortController().signal, bad)).toEqual({ ok: false, status: 502 });
    const down = vi.fn(async () => { throw new TypeError('fetch failed'); });
    expect(await fetchTcpSamples({ connectionId: ID, fromIndex: 0 }, new AbortController().signal, down)).toEqual({ ok: false, status: 0 });
  });
});
