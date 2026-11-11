// JAM-18 IO graph wire contract on the TypeScript side: the mappers, the
// control route's set_io_series allowlist entry and validation, and the
// relay's cached io_series_status for tabs opened on an already-connected
// relay. The agent's real output is pinned separately in
// agent-wire-contract.test.ts; these cases cover what a single capture
// cannot (rejections, every notObserved reason, malformed input, limits).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import type { NextRequest } from 'next/server';
import { POST } from '@/app/api/control/route';
import type { AgentClient } from '@/lib/agent-client';
import { mapCaptureStatsEvent, mapIoBucketsEvent, mapIoSeriesStatusEvent } from '@/lib/agent-mapping';
import { buildStreamResponse, StreamAgentClient, StreamEnrichmentClient, StreamGeoIpClient } from '@/lib/stream-response';

const statusExample = {
  type: 'io_series_status', revision: 8, requestId: 'c41f09aa', epoch: '4be1a07c', replayWaiting: false,
  series: [
    { id: 'all', filter: '', ok: true },
    { id: 'big', filter: 'frame.len > 1000 and ==', ok: false, error: { message: 'Unexpected token', token: '==', position: 21 } },
  ],
};

const bucketsExample = {
  type: 'io_buckets', revision: 8, epoch: '4be1a07c', bucketMs: 100,
  coveredFromMs: 1794120000000, coveredToMs: 1794120001000,
  notObserved: [
    { fromMs: 1794120000300, toMs: 1794120000600, reason: 'interface_switch' },
    { fromMs: 1794120000900, toMs: 1794120000900, reason: 'replay_error' },
    { fromMs: 1794120000100, toMs: 1794120000200, reason: 'backlog' },
    { fromMs: 1794120000100, toMs: 1794120000200, reason: 'from_a_newer_agent' },
  ],
  loss: { kernelDropped: 0, ifDropped: 0, unparseable: 3, evaluationSkipped: 0 },
  series: [
    { id: 'all', late: 0, lateBuckets: [], buckets: [[1794120000000, 412, 301122], [1794120000100, 388, 280004]] },
    { id: 'dns', late: 2, lateBuckets: [[1794119999900, 1, 90]], buckets: [[1794120000100, 2, 180]] },
  ],
};

describe('io_series_status mapping', () => {
  it('maps the spec example, keeping the failing series with its filter and error', () => {
    const mapped = mapIoSeriesStatusEvent(statusExample);
    expect(mapped).toEqual({
      revision: 8, epoch: '4be1a07c', replayWaiting: false, requestId: 'c41f09aa', rejected: undefined,
      series: [
        { id: 'all', filter: '', ok: true },
        { id: 'big', filter: 'frame.len > 1000 and ==', ok: false, error: { message: 'Unexpected token', token: '==', position: 21 } },
      ],
    });
  });

  it('maps a conflict rejection and a bootstrap status without requestId', () => {
    expect(mapIoSeriesStatusEvent({ ...statusExample, rejected: 'conflict' }).rejected).toBe('conflict');
    const boot = mapIoSeriesStatusEvent({ type: 'io_series_status', revision: 0, epoch: '4be1a07c', replayWaiting: true, series: [] });
    expect(boot.requestId).toBeUndefined();
    expect(boot.replayWaiting).toBe(true);
  });

  it('throws on malformed input rather than inventing a set', () => {
    expect(() => mapIoSeriesStatusEvent({ ...statusExample, series: undefined })).toThrow();
    expect(() => mapIoSeriesStatusEvent({ ...statusExample, revision: '8' })).toThrow();
    expect(() => mapIoSeriesStatusEvent({ ...statusExample, series: [{ id: 'x', ok: true }] })).toThrow();
  });
});

describe('io_buckets mapping', () => {
  it('maps buckets, late attribution and loss', () => {
    const mapped = mapIoBucketsEvent(bucketsExample);
    expect(mapped.series[1]).toEqual({ id: 'dns', late: 2, lateBuckets: [[1794119999900, 1, 90]], buckets: [[1794120000100, 2, 180]] });
    expect(mapped.loss.unparseable).toBe(3);
    expect(mapped.coveredToMs - mapped.coveredFromMs).toBe(1000);
  });

  it('maps every known notObserved reason and an unknown one to "unknown" without throwing', () => {
    expect(mapIoBucketsEvent(bucketsExample).notObserved.map((n) => n.reason)).toEqual([
      'interface_switch', 'replay_error', 'backlog', 'unknown',
    ]);
  });

  it('throws on a malformed bucket tuple', () => {
    const bad = structuredClone(bucketsExample);
    (bad.series[0].buckets as unknown[]).push([1, 2]);
    expect(() => mapIoBucketsEvent(bad)).toThrow(/malformed io_buckets/);
    const nan = structuredClone(bucketsExample);
    (nan.series[0].buckets as unknown[]).push([1, 'x', 3]);
    expect(() => mapIoBucketsEvent(nan)).toThrow();
  });
});

describe('capture_stats replayWaiting', () => {
  const stats = { received: 0, dropped: 0, ifDropped: 0, relayLaggedEvents: 0, unparseableFrames: 0, totalConnectionsObserved: 0, capacityEvictions: 0, idleEvictions: 0 };
  it('is true only when the agent says so; absent means not waiting', () => {
    expect(mapCaptureStatsEvent({ type: 'capture_stats', stats: { ...stats, replayWaiting: true } }).replayWaiting).toBe(true);
    expect(mapCaptureStatsEvent({ type: 'capture_stats', stats }).replayWaiting).toBeUndefined();
  });
});

function req(body: unknown, site = 'same-origin'): NextRequest {
  return {
    url: 'http://127.0.0.1:3000/api/control',
    headers: new Headers({ 'sec-fetch-site': site }),
    json: async () => body,
  } as unknown as NextRequest;
}

const valid = {
  type: 'set_io_series', baseEpoch: '4be1a07c', baseRevision: 7, requestId: 'c41f09aa',
  series: [{ id: 'all', filter: '' }, { id: 'dns', filter: 'dns' }],
};

describe('POST /api/control — set_io_series', () => {
  let sendControl: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    sendControl = vi.fn();
    global.__agentClient = { sendControl } as unknown as AgentClient;
  });
  afterEach(() => {
    global.__agentClient = undefined;
  });

  it('forwards a valid request, rebuilt from its validated fields only', async () => {
    const res = await POST(req({ ...valid, extra: 'dropped', series: [{ id: 'all', filter: '', note: 'x' }] }));
    expect(res.status).toBe(200);
    expect(sendControl).toHaveBeenCalledWith({
      type: 'set_io_series', baseEpoch: '4be1a07c', baseRevision: 7, requestId: 'c41f09aa', series: [{ id: 'all', filter: '' }],
    });
  });

  it('rejects a cross-site request before validating', async () => {
    const res = await POST(req(valid, 'cross-site'));
    expect(res.status).toBe(403);
    expect(sendControl).not.toHaveBeenCalled();
  });

  it('accepts each bound at its limit', async () => {
    const eight = Array.from({ length: 8 }, (_, i) => ({ id: `s${i}`, filter: '' }));
    for (const body of [
      { ...valid, series: eight },
      { ...valid, series: [{ id: 'a'.repeat(32), filter: 'x'.repeat(2048) }] },
      { ...valid, series: [] },
      { ...valid, baseRevision: 0 },
      { ...valid, baseRevision: 0xffffffff },
      { ...valid, requestId: 'a'.repeat(32), baseEpoch: 'ABCDEF01' },
    ]) {
      expect((await POST(req(body))).status).toBe(200);
    }
  });

  it('rejects each bound at limit + 1 and every malformed field', async () => {
    const nine = Array.from({ length: 9 }, (_, i) => ({ id: `s${i}`, filter: '' }));
    for (const body of [
      { ...valid, series: nine },
      { ...valid, series: [{ id: 'a'.repeat(33), filter: '' }] },
      { ...valid, series: [{ id: 'a', filter: 'x'.repeat(2049) }] },
      { ...valid, series: [{ id: 'a', filter: '' }, { id: 'a', filter: 'dns' }] },
      { ...valid, series: [{ id: 'Bad', filter: '' }] },
      { ...valid, series: [{ id: '', filter: '' }] },
      { ...valid, series: [{ id: 'a' }] },
      { ...valid, series: [null] },
      { ...valid, series: 'all' },
      { ...valid, baseRevision: -1 },
      { ...valid, baseRevision: 0x100000000 },
      { ...valid, baseRevision: 1.5 },
      { ...valid, requestId: 'short' },
      { ...valid, requestId: 'not-hex!' },
      { ...valid, baseEpoch: undefined },
    ]) {
      expect((await POST(req(body))).status).toBe(400);
    }
    expect(sendControl).not.toHaveBeenCalled();
  });

  it('answers 503 when the agent is not connected', async () => {
    global.__agentClient = undefined;
    expect((await POST(req(valid))).status).toBe(503);
  });
});

class FakeAgentClient extends EventEmitter implements StreamAgentClient {
  connected = true;
  cached: unknown = undefined;
  isConnected(): boolean {
    return this.connected;
  }
  latestIoSeriesStatus(): unknown {
    return this.cached;
  }
}
class FakeEnrichmentClient extends EventEmitter implements StreamEnrichmentClient {
  getMode(): 'off' | 'on-demand' | 'background' {
    return 'off';
  }
  notifyObservedConnections(): void {}
}
class FakeGeoIpClient extends EventEmitter implements StreamGeoIpClient {
  getMode(): 'off' | 'on' {
    return 'off';
  }
  lookup = vi.fn();
}

async function readEvents(reader: ReadableStreamDefaultReader<Uint8Array>, count: number): Promise<Array<Record<string, unknown>>> {
  const events: Array<Record<string, unknown>> = [];
  let buffered = '';
  while (events.length < count) {
    const { value } = await reader.read();
    buffered += new TextDecoder().decode(value);
    const parts = buffered.split('\n\n');
    buffered = parts.pop()!;
    for (const part of parts) events.push(JSON.parse(part.replace(/^data: /, '')));
  }
  return events;
}

function subscribe(agent: FakeAgentClient): ReadableStreamDefaultReader<Uint8Array> {
  return buildStreamResponse({ agent, enrichment: new FakeEnrichmentClient(), geoip: new FakeGeoIpClient() }).body!.getReader();
}

describe('relay replays the cached io_series_status to a new subscriber', () => {
  it('sends connection_status, then the cached status, before any live event', async () => {
    const agent = new FakeAgentClient();
    agent.cached = statusExample;
    const reader = subscribe(agent);
    const [first, second] = await readEvents(reader, 2);
    expect(first).toEqual({ type: 'connection_status', connected: true });
    expect(second).toEqual(statusExample);
    await reader.cancel();
  });

  it('sends nothing extra when there is no cached status or the agent is disconnected', async () => {
    for (const [connected, cached] of [[true, undefined], [false, statusExample]] as const) {
      const agent = new FakeAgentClient();
      agent.connected = connected;
      agent.cached = cached;
      const reader = subscribe(agent);
      expect((await readEvents(reader, 1))[0]).toEqual({ type: 'connection_status', connected });
      agent.emit('event', { type: 'capture_stats', stats: {} });
      expect((await readEvents(reader, 1))[0].type).toBe('capture_stats');
      await reader.cancel();
    }
  });

  it('adds no listeners beyond the per-subscriber ones (no leak on cancel)', async () => {
    const agent = new FakeAgentClient();
    agent.cached = statusExample;
    const reader = subscribe(agent);
    await readEvents(reader, 2);
    await reader.cancel();
    expect(agent.listenerCount('event')).toBe(0);
    expect(agent.listenerCount('status')).toBe(0);
  });
});

// JAM-18 Task 5 (spec D10): numeric-field aggregates.
describe('aggregates on the wire', () => {
  let sendControl: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    sendControl = vi.fn();
    global.__agentClient = { sendControl } as unknown as AgentClient;
  });
  afterEach(() => {
    global.__agentClient = undefined;
  });

  it('the route forwards a series aggregate, rebuilt from its validated fields', async () => {
    const body = { ...valid, series: [{ id: 'win', filter: 'tcp', aggregate: { fn: 'avg', field: 'tcp.window_size', extra: 1 } }] };
    expect((await POST(req(body))).status).toBe(200);
    expect(sendControl).toHaveBeenCalledWith({
      ...valid, series: [{ id: 'win', filter: 'tcp', aggregate: { fn: 'avg', field: 'tcp.window_size' } }],
    });
  });

  it('the route accepts every fn and a 64-character field, and refuses anything else', async () => {
    for (const fn of ['sum', 'min', 'max', 'avg']) {
      expect((await POST(req({ ...valid, series: [{ id: 'a', filter: '', aggregate: { fn, field: 'f'.repeat(64) } }] }))).status).toBe(200);
    }
    sendControl.mockClear();
    for (const aggregate of [
      { fn: 'median', field: 'ip.ttl' },
      { fn: 'sum', field: '' },
      { fn: 'sum', field: 'f'.repeat(65) },
      { fn: 'sum', field: 'ip ttl' },
      { fn: 'sum' },
      'sum(ip.ttl)',
      null,
    ]) {
      expect((await POST(req({ ...valid, series: [{ id: 'a', filter: '', aggregate }] }))).status).toBe(400);
    }
    expect(sendControl).not.toHaveBeenCalled();
  });

  it('io_series_status keeps a series aggregate', () => {
    const mapped = mapIoSeriesStatusEvent({ ...statusExample, series: [{ id: 'win', filter: 'tcp', ok: true, aggregate: { fn: 'avg', field: 'tcp.window_size' } }] });
    expect(mapped.series[0].aggregate).toEqual({ fn: 'avg', field: 'tcp.window_size' });
    expect(mapIoSeriesStatusEvent(statusExample).series[0].aggregate).toBeUndefined();
  });

  it('io_buckets accepts 7-tuples for aggregate series and 3-tuples for the rest', () => {
    const mapped = mapIoBucketsEvent({
      ...bucketsExample,
      series: [
        { id: 'win', late: 0, lateBuckets: [[1794119999900, 1, 90]], buckets: [
          [1794120000000, 3, 180, 2, 612, 100, 512],
          [1794120000100, 1, 60, 0, 0, null, null], // matched, but no frame had the field
          [1794120000200, 2, 120, 2, '36893488147419103230', 18446744073709552000, 18446744073709552000],
        ] },
        { id: 'all', late: 0, lateBuckets: [], buckets: [[1794120000000, 4, 192]] },
      ],
    });
    const win = mapped.series[0].buckets;
    expect(win[0]).toEqual([1794120000000, 3, 180, 2, 612, 100, 512]);
    expect(win[1]).toEqual([1794120000100, 1, 60, 0, 0, null, null]);
    expect(win[2][4]).toBe(36893488147419103230); // a decimal-string sum above 2^53 - 1, as the nearest double
    expect(mapped.series[1].buckets).toEqual([[1794120000000, 4, 192]]);
  });

  it('io_buckets throws on a malformed aggregate tuple', () => {
    for (const bad of [
      [1, 1, 1, 1],
      [1, 1, 1, 1, 1, 1],
      [1, 1, 1, 1, 'not a number', 1, 1],
      [1, 1, 1, 1, 1, 'x', 1],
      [1, 1, 1, 1, 1, 1, 1, 1],
    ]) {
      expect(() => mapIoBucketsEvent({ ...bucketsExample, series: [{ id: 'a', late: 0, lateBuckets: [], buckets: [bad] }] })).toThrow();
    }
    // Late buckets never carry an aggregate.
    expect(() => mapIoBucketsEvent({ ...bucketsExample, series: [{ id: 'a', late: 0, lateBuckets: [[1, 1, 1, 1, 1, 1, 1]], buckets: [] }] })).toThrow();
  });
});
