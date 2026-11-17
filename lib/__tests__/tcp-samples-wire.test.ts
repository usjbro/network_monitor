// KAN-129 Task 3: the `tcp_samples` reply mapper (docs/wire-protocol.md
// "tcp_samples"). Delta-decoded timestamps, per-direction sequence bases,
// tolerant of unknown fields and enum values, strict about malformed
// columns and numbers that are not exact.
import { describe, expect, it } from 'vitest';
import { mapCaptureStatsEvent, mapTcpSamplesReply } from '../agent-mapping';
import { TCP_SAMPLE_FLAG, TCP_SAMPLE_MARK } from '../types';

const ID = 'Tcp-192.168.1.10:51000-93.184.216.34:443';
const T0 = 1_794_120_000_000_000;

function reply(overrides: Record<string, unknown> = {}, samples: Record<string, unknown> = {}) {
  return {
    type: 'tcp_samples',
    connectionId: ID,
    found: true,
    stale: false,
    generation: '4be1a07c9d22f310:17',
    handshakeSeen: true,
    windowScale: { local: 7, remote: 8 },
    seqBase: { outbound: 1294467712, inbound: 3011845120 },
    relativeTo: 'isn',
    firstIndex: 18230,
    nextIndex: 18233,
    more: true,
    droppedOlder: 18230,
    samples: {
      tUs: [T0, 1200, -350],
      seq: [0, 1, 1449],
      ack: [0, 1, 1],
      win: [65535, 131328, 131328],
      len: [0, 1448, 1448],
      flags: [2, 24, 24],
      mark: [1, 0, 3],
      rttUs: [0, 0, 0],
      ...samples,
    },
    ...overrides,
  };
}

describe('mapTcpSamplesReply', () => {
  it('maps a page, decoding signed timestamp deltas in both directions', () => {
    const page = mapTcpSamplesReply(reply());
    expect(page).toMatchObject({
      found: true,
      stale: false,
      connectionId: ID,
      generation: '4be1a07c9d22f310:17',
      handshakeSeen: true,
      windowScale: { local: 7, remote: 8 },
      relativeTo: 'isn',
      firstIndex: 18230,
      nextIndex: 18233,
      more: true,
      droppedOlder: 18230,
    });
    if (!page.found || page.stale) throw new Error('expected a page');
    expect(page.samples.map((s) => s.tUs)).toEqual([T0, T0 + 1200, T0 + 850]);
    expect(page.samples[2]).toEqual({ tUs: T0 + 850, seq: 1449, ack: 1, win: 131328, len: 1448, flags: 24, mark: 3, rttUs: 0, outbound: true });
    expect(page.samples.map((s) => s.outbound)).toEqual([true, false, true]);
  });

  it('keeps the sequence base per direction', () => {
    const page = mapTcpSamplesReply(reply({ seqBase: { outbound: 4294967295, inbound: 0 } }));
    if (!page.found || page.stale) throw new Error('expected a page');
    expect(page.seqBase).toEqual({ outbound: 4294967295, inbound: 0 });
  });

  it('ignores unknown fields and shows unknown enum values as unknown', () => {
    const page = mapTcpSamplesReply(reply({ relativeTo: 'somethingNew', futureField: { x: 1 } }));
    if (!page.found || page.stale) throw new Error('expected a page');
    expect(page.relativeTo).toBe('unknown');
    expect(page).not.toHaveProperty('futureField');
    // Mark bits this client does not know stay visible in `mark`.
    const marked = mapTcpSamplesReply(reply({}, { mark: [1 | 64, 0, 3] }));
    if (!marked.found || marked.stale) throw new Error('expected a page');
    expect(marked.samples[0].mark).toBe(65);
  });

  it('maps a raw-window, midstream page and an empty page', () => {
    const page = mapTcpSamplesReply(
      reply({ windowScale: null, relativeTo: 'firstSeen', more: false }, { tUs: [], seq: [], ack: [], win: [], len: [], flags: [], mark: [], rttUs: [] }),
    );
    expect(page).toMatchObject({ found: true, stale: false, windowScale: null, relativeTo: 'firstSeen', more: false, samples: [] });
  });

  it('maps the absent cases', () => {
    expect(mapTcpSamplesReply({ type: 'tcp_samples', connectionId: ID, found: false, stale: false })).toEqual({ found: false, connectionId: ID });
    expect(mapTcpSamplesReply({ type: 'tcp_samples', connectionId: ID, found: true, stale: true, generation: 'aaaaaaaaaaaaaaaa:2' })).toEqual({
      found: true,
      stale: true,
      connectionId: ID,
      generation: 'aaaaaaaaaaaaaaaa:2',
    });
  });

  it.each([
    ['columns of different lengths', reply({}, { seq: [0, 1] })],
    ['a missing column', reply({}, { rttUs: undefined })],
    ['a column that is not an array', reply({}, { win: 'x' })],
    ['a non-number', reply({}, { len: [0, '1448', 1448] })],
    ['a fraction', reply({}, { win: [65535, 1.5, 131328] })],
    ['a negative sequence number', reply({}, { seq: [0, -1, 1449] })],
    ['a sequence number past 32 bits', reply({}, { seq: [0, 2 ** 32, 1449] })],
    ['an unsafe delta', reply({}, { tUs: [T0, 2 ** 53, 0] })],
    ['a reconstructed timestamp that is not a safe integer', reply({}, { tUs: [2 ** 53 - 1, 1, 0] })],
    ['a reconstructed timestamp below zero', reply({}, { tUs: [5, -6, 0] })],
    ['an unsafe index', reply({ nextIndex: 2 ** 53 })],
    ['a negative index', reply({ firstIndex: -1 })],
    ['a window shift above 14', reply({ windowScale: { local: 15, remote: 8 } })],
    ['nextIndex below firstIndex', reply({ firstIndex: 10, nextIndex: 9 }, { tUs: [], seq: [], ack: [], win: [], len: [], flags: [], mark: [], rttUs: [] })],
    ['a nextIndex that does not cover the samples returned', reply({ firstIndex: 18231, nextIndex: 18233 })],
    ['a missing samples object', reply({ samples: undefined })],
    ['a missing seqBase', reply({ seqBase: undefined })],
    ['a non-boolean found', reply({ found: 'yes' })],
    ['a missing connectionId', reply({ connectionId: undefined })],
    ['a non-object', null],
  ])('throws on %s', (_name, json) => {
    expect(() => mapTcpSamplesReply(json)).toThrow(/malformed tcp_samples/);
  });

  it('exposes the flag and mark bits the agent defines', () => {
    expect(TCP_SAMPLE_FLAG).toEqual({ FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16 });
    expect(TCP_SAMPLE_MARK).toEqual({ OUTBOUND: 1, RETRANSMIT: 2, WIN_SCALED: 4, ZERO_WINDOW: 8, RTT: 16 });
  });
});

describe('mapCaptureStatsEvent TCP sample cost', () => {
  const base = {
    received: 1, dropped: 0, ifDropped: 0, relayLaggedEvents: 0, unparseableFrames: 0,
    totalConnectionsObserved: 1, capacityEvictions: 0, idleEvictions: 0,
  };

  it('maps the three cost fields', () => {
    const stats = mapCaptureStatsEvent({ stats: { ...base, tcpSampleRings: 3, tcpSampleRingBytes: 405000, tcpSampleRingsRecycled: 11 } });
    expect(stats).toMatchObject({ tcpSampleRings: 3, tcpSampleRingBytes: 405000, tcpSampleRingsRecycled: 11 });
  });

  it('leaves them unknown for an older agent rather than claiming zero', () => {
    const stats = mapCaptureStatsEvent({ stats: base });
    expect(stats.tcpSampleRings).toBeUndefined();
    expect(stats.tcpSampleRingBytes).toBeUndefined();
    expect(stats.tcpSampleRingsRecycled).toBeUndefined();
  });
});
