import { describe, expect, it } from 'vitest';
import { mapFindingEvent, mapServiceTimeUpdateEvent } from '@/lib/agent-mapping';
import { answeredBy, formatServiceTime, responseLinkOf } from '@/lib/service-time';
import type { PacketFrame, WireField } from '@/lib/types';

function packet(id: string, fields: WireField[] = []): PacketFrame {
  return {
    id, timestamp: '1', relativeTimeMs: 0, layer: 7, protocol: 'UDP', src: 'a:1', dst: 'b:53',
    length: 80, summary: id, hexDump: '', headerHexDump: '', fields,
  };
}

const derived = (path: string, type: WireField['type'], value: WireField['value']): WireField =>
  ({ path, label: path, group: path.split('.')[0], type, value, region: 'payload', offset: 0, len: 0 });

describe('mapServiceTimeUpdateEvent', () => {
  it('maps every summary, keeping absent timing values absent rather than zero', () => {
    const mapped = mapServiceTimeUpdateEvent({
      type: 'service_time_update',
      summaries: [
        { protocol: 'DNS', answered: 3, unanswered: 1, untracked: 0, minUs: 400, maxUs: 9000, sampleCount: 3, medianUs: 800, p95Us: 9000 },
        { protocol: 'HTTP', answered: 0, unanswered: 0, untracked: 2, sampleCount: 0 },
      ],
    });
    expect(mapped).toEqual([
      { protocol: 'DNS', answered: 3, unanswered: 1, untracked: 0, minUs: 400, maxUs: 9000, sampleCount: 3, medianUs: 800, p95Us: 9000 },
      { protocol: 'HTTP', answered: 0, unanswered: 0, untracked: 2, sampleCount: 0, minUs: undefined, maxUs: undefined, medianUs: undefined, p95Us: undefined },
    ]);
  });

  it('rejects an event without its summaries or a summary missing a count', () => {
    expect(() => mapServiceTimeUpdateEvent({ type: 'service_time_update' })).toThrow(/summaries/);
    expect(() => mapServiceTimeUpdateEvent({ type: 'service_time_update', summaries: [{ protocol: 'DNS' }] })).toThrow(/answered/);
  });
});

describe('unanswered-request findings', () => {
  it('map like any other finding code', () => {
    const finding = mapFindingEvent({
      type: 'finding',
      finding: {
        id: 'finding-1-1', timestamp: '1', severity: 'warning', code: 'unanswered-request',
        summary: 'no DNS response to "a.com" A within 5 s', frameId: 'pkt-1-1', flowId: 'Udp-a:1-b:53',
      },
    });
    expect(finding.code).toBe('unanswered-request');
    expect(finding.frameId).toBe('pkt-1-1');
  });
});

describe('formatServiceTime', () => {
  it('picks a unit that keeps sub-millisecond answers visible', () => {
    expect(formatServiceTime(850)).toBe('850 µs');
    expect(formatServiceTime(12_345)).toBe('12.3 ms');
    expect(formatServiceTime(1_250_000)).toBe('1.25 s');
    expect(formatServiceTime(0)).toBe('0 µs');
  });
});

describe('request/response links', () => {
  const request = packet('pkt-req');
  const response = packet('pkt-resp', [derived('dns.time_us', 'uint', 1500), derived('dns.response_to', 'str', 'pkt-req')]);
  const httpResponse = packet('pkt-http', [derived('http.time_us', 'uint', 20_000)]);

  it('reads a response link from its derived fields', () => {
    expect(responseLinkOf(response)).toEqual({ protocol: 'DNS', serviceTimeUs: 1500, requestId: 'pkt-req' });
    expect(responseLinkOf(httpResponse)).toEqual({ protocol: 'HTTP', serviceTimeUs: 20_000, requestId: undefined });
    expect(responseLinkOf(request)).toBeNull();
  });

  it('finds the response that answered a request among buffered packets', () => {
    expect(answeredBy('pkt-req', [httpResponse, response])).toBe(response);
    expect(answeredBy('pkt-other', [httpResponse, response])).toBeUndefined();
  });
});
