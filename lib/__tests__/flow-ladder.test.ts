// KAN-130 Task 3: the ladder model (spec D3 rows and collapse, D4 match key).
import { describe, expect, it } from 'vitest';
import { MAX_ROWS, RUN_DRAW_MAX, arrowText, buildLadder, linkSamples, packetKey, sampleKey, type LadderRow } from '../flow-ladder';
import type { IndexedSample, TcpGraphState } from '../tcp-graphs';
import { TCP_SAMPLE_FLAG as F, TCP_SAMPLE_MARK as M, type NetworkConnection, type PacketFrame, type TcpSample, type TcpSampleLabel, type WireField } from '../types';

const ID = 'Tcp-192.168.1.10:51000-93.184.216.34:443';
const T0 = 1_794_120_000_000_000;
const BASE = { outbound: 1000, inbound: 5000 };

function s(index: number, tUs: number, outbound: boolean, over: Partial<TcpSample> = {}): IndexedSample {
  const mark = (outbound ? M.OUTBOUND : 0) | (over.mark ?? 0);
  return { index, tUs, seq: 0, ack: 0, win: 1000, len: 0, flags: F.ACK, rttUs: 0, ...over, mark, outbound };
}

function state(samples: IndexedSample[], over: Partial<TcpGraphState> = {}): TcpGraphState {
  return {
    connectionId: ID, generation: 'g:1', samples, nextIndex: (samples.at(-1)?.index ?? -1) + 1,
    meta: { handshakeSeen: true, windowScale: null, seqBase: BASE, relativeTo: 'isn' },
    found: true, head: [], labels: new Map(), ...over,
  };
}

function labels(...entries: TcpSampleLabel[]): Map<number, TcpSampleLabel> {
  return new Map(entries.map((l) => [l.index, l]));
}

/** SYN, SYN-ACK, ACK, then `n` outbound data / inbound ACK pairs, then FIN,ACK both ways and a last ACK. */
function flow(n: number): IndexedSample[] {
  const out = [
    s(0, T0, true, { flags: F.SYN }),
    s(1, T0 + 1000, false, { flags: F.SYN | F.ACK, ack: 1 }),
    s(2, T0 + 2000, true, { seq: 1, ack: 1 }),
  ];
  let t = T0 + 2000;
  for (let i = 0; i < n; i++) {
    out.push(s(out.length, (t += 100), true, { flags: F.PSH | F.ACK, seq: 1 + i * 100, ack: 1, len: 100 }));
    out.push(s(out.length, (t += 100), false, { seq: 1, ack: 1 + (i + 1) * 100 }));
  }
  out.push(s(out.length, (t += 1000), true, { flags: F.FIN | F.ACK, seq: 1 + n * 100, ack: 1 }));
  out.push(s(out.length, (t += 1000), false, { flags: F.FIN | F.ACK, seq: 1, ack: 2 + n * 100 }));
  out.push(s(out.length, (t += 1000), true, { seq: 2 + n * 100, ack: 2 }));
  return out;
}

const kinds = (rows: LadderRow[]) => rows.map((r) => r.kind);
const arrows = (rows: LadderRow[]) => rows.flatMap((r) => (r.kind === 'arrow' ? [r] : []));

describe('arrowText', () => {
  it('names flags, length, label and marks', () => {
    expect(arrowText(s(0, T0, true, { flags: F.SYN }))).toBe('SYN');
    expect(arrowText(s(0, T0, false, { flags: F.SYN | F.ACK }))).toBe('SYN,ACK');
    expect(arrowText(s(0, T0, true, { flags: F.FIN | F.ACK }))).toBe('FIN,ACK');
    expect(arrowText(s(0, T0, true, { flags: F.RST }))).toBe('RST');
    expect(arrowText(s(0, T0, true, { flags: F.PSH | F.ACK, len: 517 }), { kind: 'tls_client_hello', text: 'ClientHello (SNI: example.com)' }))
      .toBe('PSH,ACK len=517 · ClientHello (SNI: example.com)');
    expect(arrowText(s(0, T0, true, { len: 100, mark: M.RETRANSMIT }))).toBe('ACK len=100 · retransmission');
    expect(arrowText(s(0, T0, false, { win: 0, mark: M.ZERO_WINDOW }))).toBe('ACK · zero window');
    expect(arrowText(s(0, T0, true, { flags: 0 }))).toBe('(no flags)');
  });

  it('shows an unknown label kind as unknown, not its text', () => {
    expect(arrowText(s(0, T0, true, { len: 1 }), { kind: 'from_the_future', text: 'whatever' })).toBe('ACK len=1 · unknown label');
  });
});

describe('buildLadder', () => {
  it('draws a handshake, a short exchange and a close arrow by arrow', () => {
    const rows = buildLadder(state(flow(2)));
    expect(kinds(rows).every((k) => k === 'arrow')).toBe(true);
    expect(arrows(rows).map((r) => r.text)).toEqual([
      'SYN', 'SYN,ACK', 'ACK',
      'PSH,ACK len=100', 'ACK', 'PSH,ACK len=100', 'ACK',
      'FIN,ACK', 'FIN,ACK', 'ACK',
    ]);
    expect(arrows(rows).map((r) => r.sample.outbound)).toEqual([true, false, true, true, false, true, false, true, false, true]);
  });

  it(`draws a run of ${RUN_DRAW_MAX} bulk segments and collapses one of ${RUN_DRAW_MAX + 1}`, () => {
    // flow(n): the first data segment is interesting (first payload outbound),
    // so the bulk run after it is 2n − 1 segments long.
    const drawn = buildLadder(state(flow(2)));
    expect(kinds(drawn).includes('run')).toBe(false);
    // n = 3: run of 5 (ACK, data, ACK, data, ACK).
    const collapsed = buildLadder(state(flow(3)));
    const run = collapsed.find((r) => r.kind === 'run');
    expect(run).toMatchObject({ kind: 'run', firstIndex: 4, lastIndex: 8, segments: 5,
      out: { data: 2, bytes: 200, acks: 0 }, in: { data: 0, bytes: 0, acks: 3 } });
    expect(run && run.kind === 'run' && run.spanUs).toBe(400);
    expect(kinds(collapsed)).toEqual(['arrow', 'arrow', 'arrow', 'arrow', 'run', 'arrow', 'arrow', 'arrow']);
  });

  it('keeps interesting segments as arrows and lets them split runs', () => {
    const samples = flow(10);
    samples[10] = { ...samples[10], mark: samples[10].mark | M.RETRANSMIT };
    const rows = buildLadder(state(samples));
    const retransmitRow = arrows(rows).find((r) => r.index === 10);
    expect(retransmitRow?.interesting).toBe(true);
    expect(retransmitRow?.text).toContain('retransmission');
    const runs = rows.filter((r) => r.kind === 'run');
    expect(runs.map((r) => r.kind === 'run' && [r.firstIndex, r.lastIndex])).toEqual([[4, 9], [11, 22]]);
  });

  it('keeps zero-window, RST and labelled segments as arrows', () => {
    const samples = flow(10);
    samples[8] = { ...samples[8], win: 0, mark: samples[8].mark | M.ZERO_WINDOW };
    samples[14] = { ...samples[14], flags: F.RST };
    const rows = buildLadder(state(samples, { labels: labels({ index: 12, kind: 'http_request', text: 'HTTP GET /' }) }));
    const indices = arrows(rows).filter((r) => r.interesting).map((r) => r.index);
    expect(indices).toEqual(expect.arrayContaining([8, 12, 14]));
    expect(arrows(rows).find((r) => r.index === 12)?.label).toEqual({ kind: 'http_request', text: 'HTTP GET /' });
  });

  it('marks the first payload in each direction as interesting', () => {
    const rows = buildLadder(state(flow(3)));
    expect(arrows(rows).find((r) => r.index === 3)?.interesting).toBe(true);
    // The inbound side sends no payload in flow(); give it one.
    const samples = flow(3);
    samples[6] = { ...samples[6], len: 50 };
    const withInbound = buildLadder(state(samples));
    expect(arrows(withInbound).find((r) => r.index === 6)?.interesting).toBe(true);
  });

  it('inserts a gap row where indices are missing, and a gap splits a run', () => {
    const samples = flow(20).filter((x) => x.index < 8 || x.index >= 30);
    const rows = buildLadder(state(samples));
    const gap = rows.find((r) => r.kind === 'gap');
    expect(gap).toEqual({ kind: 'gap', afterIndex: 7, missing: 22 });
    expect(rows.filter((r) => r.kind === 'gap')).toHaveLength(1);
  });

  it('puts exactly one gap row between a pinned head and the rolling samples', () => {
    const all = flow(2_100);
    const head = all.slice(0, 16);
    const rolling = all.slice(all.length - 4096);
    const rows = buildLadder(state(rolling, { head }));
    const gaps = rows.filter((r) => r.kind === 'gap');
    expect(gaps).toEqual([{ kind: 'gap', afterIndex: 15, missing: rolling[0].index - 16 }]);
    expect(arrows(rows).slice(0, 3).map((r) => r.text)).toEqual(['SYN', 'SYN,ACK', 'ACK']);
  });

  it(`keeps ${MAX_ROWS} rows and elides the middle beyond that`, () => {
    // Each retransmitted segment is interesting, so every sample is a row.
    const many = (n: number) => Array.from({ length: n }, (_, i) => s(i, T0 + i, true, { len: 10, mark: M.RETRANSMIT }));
    expect(buildLadder(state(many(MAX_ROWS)))).toHaveLength(MAX_ROWS);
    const rows = buildLadder(state(many(MAX_ROWS + 1)));
    expect(rows).toHaveLength(201);
    expect(rows[100]).toEqual({ kind: 'elided', rows: 1, segments: 1 });
    expect(rows[99]).toMatchObject({ kind: 'arrow', index: 99 });
    expect(rows[101]).toMatchObject({ kind: 'arrow', index: 101 });
    const big = buildLadder(state(many(500)));
    expect(big[100]).toEqual({ kind: 'elided', rows: 300, segments: 300 });
  });

  it('counts collapsed segments in an elided row', () => {
    // 150 retransmission rows, one inbound first-payload row, a 50-segment run,
    // 150 more retransmission rows: 302 rows, 102 of them elided.
    const samples: IndexedSample[] = [];
    let i = 0;
    for (; i < 150; i++) samples.push(s(i, T0 + i, true, { len: 1, mark: M.RETRANSMIT }));
    samples.push(s(i, T0 + i, false, { len: 5 })); // first inbound payload: interesting
    for (i++; i < 201; i++) samples.push(s(i, T0 + i, true, {}));
    for (; i < 351; i++) samples.push(s(i, T0 + i, true, { len: 1, mark: M.RETRANSMIT }));
    const rows = buildLadder(state(samples));
    expect(rows[100]).toEqual({ kind: 'elided', rows: 102, segments: 151 });
  });

  it('is deterministic, and appending samples only changes the tail', () => {
    const a = flow(30);
    expect(buildLadder(state(a))).toEqual(buildLadder(state(a)));
    const before = buildLadder(state(a.slice(0, 40)));
    const after = buildLadder(state(a));
    expect(after.slice(0, 4)).toEqual(before.slice(0, 4));
  });

  it('builds nothing for an empty state', () => {
    expect(buildLadder(state([]))).toEqual([]);
  });

  it('builds a full ring with its head well within a frame', () => {
    const all = flow(2_100);
    const big = state(all.slice(all.length - 4096), {
      head: all.slice(0, 16),
      labels: labels(...Array.from({ length: 32 }, (_, k) => ({ index: k < 16 ? k : all.length - 100 + k, kind: 'http_request', text: 'x'.repeat(64) }))),
    });
    buildLadder(big);
    const times = Array.from({ length: 5 }, () => {
      const t = performance.now();
      buildLadder(big);
      return performance.now() - t;
    }).sort((x, y) => x - y);
    // The 16.7 ms budget itself is measured in a production build (Task 4);
    // this guards against a regression with a CI margin.
    expect(times[2]).toBeLessThan(33);
  });
});

function field(path: string, value: boolean | number): WireField {
  return { path, label: path, type: typeof value === 'boolean' ? 'bool' : 'uint', value, region: 'header', offset: 0, len: 1 };
}

function frame(id: string, src: string, dst: string, ms: number, seq: number, ack: number, flags: { syn?: boolean; ack?: boolean; fin?: boolean; rst?: boolean }): PacketFrame {
  return {
    id, timestamp: String(ms), relativeTimeMs: 0, layer: 4, protocol: 'TCP', src, dst, length: 60, summary: '',
    hexDump: '', headerHexDump: '',
    fields: [
      field('tcp.seq', seq), field('tcp.ack_number', ack),
      field('tcp.flags.syn', !!flags.syn), field('tcp.flags.ack', !!flags.ack),
      field('tcp.flags.fin', !!flags.fin), field('tcp.flags.rst', !!flags.rst),
    ],
  };
}

function conn(localAddr: string, localPort: number, remoteAddr: string, remotePort: number): NetworkConnection {
  return { id: ID, localAddr, localPort, remoteAddr, remotePort } as NetworkConnection;
}

describe('packet-view match key', () => {
  const c4 = conn('192.168.1.10', 51000, '93.184.216.34', 443);

  it('matches a sample to its frame by direction, raw seq/ack, flags and millisecond', () => {
    const sample = s(2, T0 + 2_345, true, { seq: 1, ack: 1 });
    const f = frame('pkt-1', '192.168.1.10:51000', '93.184.216.34:443', Math.floor((T0 + 2_345) / 1000), 1001, 5001, { ack: true });
    expect(packetKey(f, c4)).toBe(sampleKey(sample, BASE));
  });

  it('distinguishes direction, flags, numbers and time', () => {
    const sample = s(2, T0 + 2_345, true, { seq: 1, ack: 1 });
    const ms = Math.floor((T0 + 2_345) / 1000);
    const key = sampleKey(sample, BASE);
    expect(packetKey(frame('a', '93.184.216.34:443', '192.168.1.10:51000', ms, 1001, 5001, { ack: true }), c4)).not.toBe(key);
    expect(packetKey(frame('b', '192.168.1.10:51000', '93.184.216.34:443', ms, 1001, 5001, { ack: true, fin: true }), c4)).not.toBe(key);
    expect(packetKey(frame('c', '192.168.1.10:51000', '93.184.216.34:443', ms, 1002, 5001, { ack: true }), c4)).not.toBe(key);
    expect(packetKey(frame('d', '192.168.1.10:51000', '93.184.216.34:443', ms + 1, 1001, 5001, { ack: true }), c4)).not.toBe(key);
  });

  it('ignores the ACK number when ACK is not set', () => {
    const syn = s(0, T0, true, { flags: F.SYN, seq: 0, ack: 0 });
    const f = frame('syn', '192.168.1.10:51000', '93.184.216.34:443', Math.floor(T0 / 1000), 1000, 123456, { syn: true });
    expect(packetKey(f, c4)).toBe(sampleKey(syn, BASE));
  });

  it('wraps the raw sequence number past 2^32', () => {
    const base = { outbound: 0xffff_fff0, inbound: 7 };
    const sample = s(5, T0, true, { seq: 0x20, ack: 3 });
    const f = frame('w', '192.168.1.10:51000', '93.184.216.34:443', Math.floor(T0 / 1000), 0x10, 10, { ack: true });
    expect(packetKey(f, c4)).toBe(sampleKey(sample, base));
  });

  it('matches IPv6 endpoints in canonical form', () => {
    const c6 = conn('2001:db8::1', 51000, '2001:db8::2', 443);
    const sample = s(1, T0, false, { seq: 0, ack: 1 });
    const ms = Math.floor(T0 / 1000);
    const key = sampleKey(sample, BASE);
    expect(packetKey(frame('v6', '2001:db8::2:443', '2001:db8::1:51000', ms, 5000, 1001, { ack: true }), c6)).toBe(key);
    expect(packetKey(frame('v6b', '[2001:DB8::2]:443', '[2001:db8::1]:51000', ms, 5000, 1001, { ack: true }), c6)).toBe(key);
  });

  it('gives no key for a frame of another flow or without TCP fields', () => {
    expect(packetKey(frame('x', '10.0.0.1:1', '10.0.0.2:2', 0, 0, 0, { ack: true }), c4)).toBeNull();
    const noTcp = { ...frame('y', '192.168.1.10:51000', '93.184.216.34:443', 0, 0, 0, {}), fields: [] };
    expect(packetKey(noTcp, c4)).toBeNull();
  });

  it('links unique matches only; an ambiguous key links nothing', () => {
    const ms = (us: number) => Math.floor(us / 1000);
    const a = s(3, T0 + 10_000, true, { seq: 1, ack: 1, len: 10 });
    const b = s(4, T0 + 20_000, true, { seq: 11, ack: 1, len: 10 });
    // c is an identical retransmission of b within the same millisecond.
    const c = s(5, T0 + 20_400, true, { seq: 11, ack: 1, len: 10, mark: M.RETRANSMIT });
    const st = state([a, b, c]);
    const frames = [
      frame('pa', '192.168.1.10:51000', '93.184.216.34:443', ms(a.tUs), 1001, 5001, { ack: true }),
      frame('pb', '192.168.1.10:51000', '93.184.216.34:443', ms(b.tUs), 1011, 5001, { ack: true }),
    ];
    expect([...linkSamples(st, frames, c4)]).toEqual([[3, 'pa']]);
    // Two frames with the same key: neither links.
    const twice = [frames[0], { ...frames[0], id: 'pa2' }];
    expect(linkSamples(state([a]), twice, c4).size).toBe(0);
  });

  it('links nothing without sequence bases', () => {
    const a = s(3, T0, true, { seq: 1, ack: 1 });
    const frames = [frame('pa', '192.168.1.10:51000', '93.184.216.34:443', Math.floor(T0 / 1000), 1001, 5001, { ack: true })];
    expect(linkSamples(state([a], { meta: null }), frames, c4).size).toBe(0);
  });
});
