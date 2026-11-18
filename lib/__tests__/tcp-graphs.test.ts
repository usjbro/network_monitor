// KAN-129 Task 4: lib/tcp-graphs.ts, the pure state and series behind the
// TCP graphs view (spec D6, plan Task 4).
import { describe, expect, it } from 'vitest';
import {
  MAX_SAMPLES,
  accumulate,
  emptyState,
  heldValues,
  requestFor,
  series,
  throughput,
  throughputIntervalUs,
  type TcpGraphState,
} from '../tcp-graphs';
import { TCP_SAMPLE_FLAG as F, TCP_SAMPLE_MARK as M, type TcpSample, type TcpSamplesPage } from '../types';

const ID = 'Tcp-192.168.1.10:51000-93.184.216.34:443';
const GEN = '00000000feedbeef:3';
const T0 = 1_794_120_000_000_000;

type Found = Extract<TcpSamplesPage, { stale: false }>;

function s(tUs: number, outbound: boolean, over: Partial<TcpSample> = {}): TcpSample {
  const mark = (outbound ? M.OUTBOUND : 0) | (over.mark ?? 0);
  return { tUs, seq: 0, ack: 0, win: 1000, len: 0, flags: F.ACK, rttUs: 0, ...over, mark, outbound };
}

function page(firstIndex: number, nextIndex: number, samples: TcpSample[], over: Partial<Found> = {}): Found {
  return {
    found: true, stale: false, connectionId: ID, generation: GEN, handshakeSeen: true,
    windowScale: { local: 7, remote: 8 }, seqBase: { outbound: 1000, inbound: 5000 }, relativeTo: 'isn',
    firstIndex, nextIndex, more: false, droppedOlder: 0, samples, ...over,
  };
}

/** A small bulk transfer: 3 handshake samples, then n data/ACK pairs. */
function bulk(n: number, opts: { retransmitAt?: number; zeroAt?: number } = {}): TcpSample[] {
  const out: TcpSample[] = [
    s(T0, true, { flags: F.SYN, seq: 0 }),
    s(T0 + 1000, false, { flags: F.SYN | F.ACK, seq: 0, ack: 1 }),
    s(T0 + 2000, true, { seq: 1, ack: 1 }),
  ];
  let t = T0 + 2000;
  for (let i = 0; i < n; i++) {
    t += 1000;
    out.push(s(t, true, { seq: 1 + i * 100, ack: 1, len: 100, mark: opts.retransmitAt === i ? M.RETRANSMIT : 0 }));
    t += 500;
    const zero = opts.zeroAt === i;
    out.push(s(t, false, { seq: 1, ack: 1 + (i + 1) * 100, win: zero ? 0 : 2560, mark: (zero ? M.ZERO_WINDOW : M.WIN_SCALED) | M.RTT, rttUs: 500 }));
  }
  return out;
}

function fed(...pages: TcpSamplesPage[]): TcpGraphState {
  return pages.reduce(accumulate, emptyState(ID));
}

describe('accumulate', () => {
  it('merges pages by index and asks for the next one', () => {
    const all = bulk(4);
    const one = page(0, 5, all.slice(0, 5), { more: true });
    const two = page(0, all.length, all.slice(5));
    const state = fed(one, two);
    expect(state.samples.map((x) => x.index)).toEqual(all.map((_, i) => i));
    expect(requestFor(state)).toEqual({ connectionId: ID, generation: GEN, fromIndex: all.length });
    expect(requestFor(emptyState(ID))).toEqual({ connectionId: ID, fromIndex: 0 });
  });

  it('drops the overlap when a page repeats indices it already has', () => {
    const all = bulk(2);
    const state = fed(page(0, 4, all.slice(0, 4)), page(0, all.length, all.slice(2)));
    expect(state.samples.map((x) => x.index)).toEqual(all.map((_, i) => i));
  });

  it('resets on stale and on a new generation', () => {
    const all = bulk(2);
    const before = fed(page(0, all.length, all));
    const stale = accumulate(before, { found: true, stale: true, connectionId: ID, generation: '00000000feedbeef:9' });
    expect(stale.samples).toEqual([]);
    expect(requestFor(stale)).toEqual({ connectionId: ID, fromIndex: 0 });
    const regen = accumulate(before, page(0, 2, all.slice(0, 2), { generation: '00000000feedbeef:4' }));
    expect(regen.samples.map((x) => x.index)).toEqual([0, 1]);
    expect(regen.generation).toBe('00000000feedbeef:4');
  });

  it('keeps its samples when the flow is no longer found', () => {
    const all = bulk(2);
    const gone = accumulate(fed(page(0, all.length, all)), { found: false, connectionId: ID });
    expect(gone.found).toBe(false);
    expect(gone.samples).toHaveLength(all.length);
  });

  it('holds at most one ring of samples, newest kept', () => {
    const many = Array.from({ length: MAX_SAMPLES + 10 }, (_, i) => s(T0 + i, true, { seq: i, len: 1 }));
    const state = fed(page(0, MAX_SAMPLES, many.slice(0, MAX_SAMPLES)), page(0, many.length, many.slice(MAX_SAMPLES)));
    expect(MAX_SAMPLES).toBe(4096);
    expect(state.samples).toHaveLength(MAX_SAMPLES);
    expect(state.samples[0].index).toBe(10);
  });
});

describe('series', () => {
  it('draws the outbound staircase from segment ends, retransmissions flagged', () => {
    const state = fed(page(0, 11, bulk(4, { retransmitAt: 2 })));
    const out = series(state, 'outbound');
    expect(out.data.map((p) => p.seqEnd)).toEqual([101, 201, 301, 401]);
    expect(out.data.map((p) => p.retransmit)).toEqual([false, false, true, false]);
    expect(out.data[0].tUs).toBe(T0 + 3000);
  });

  it('takes the ACK and receive-window lines from the opposite direction', () => {
    const out = series(fed(page(0, 11, bulk(4))), 'outbound');
    // The SYN-ACK and the four data ACKs, in one unbroken line.
    expect(out.ack).toHaveLength(1);
    expect(out.ack[0].map((p) => p.value)).toEqual([1, 101, 201, 301, 401]);
    expect(out.window[0].map((p) => p.value)).toEqual([1 + 1000, 101 + 2560, 201 + 2560, 301 + 2560, 401 + 2560]);
    // Inbound data has no segments here, and the outbound side's ACKs form its ACK line.
    const inbound = series(fed(page(0, 11, bulk(4))), 'inbound');
    expect(inbound.data).toEqual([]);
    expect(inbound.ack[0].map((p) => p.value)).toEqual([1, 1, 1, 1, 1]);
  });

  it('labels windows scaled or unscaled per spec D4', () => {
    const all = bulk(1);
    expect(series(fed(page(0, all.length, all)), 'outbound').windowLabel).toBe('scaled');
    expect(series(fed(page(0, all.length, all, { windowScale: null })), 'outbound').windowLabel).toBe('unscaled (scaling not negotiated)');
    expect(series(fed(page(0, all.length, all, { windowScale: null, handshakeSeen: false })), 'outbound').windowLabel).toBe('unscaled (handshake not seen)');
  });

  it('labels RTT by the capture point, per direction', () => {
    const state = fed(page(0, 11, bulk(4)));
    const out = series(state, 'outbound');
    expect(out.rtt.map((p) => p.rttUs)).toEqual([500, 500, 500, 500]);
    expect(out.rttLabel).toBe("round trip from this host's capture point");
    const inbound = series(state, 'inbound');
    expect(inbound.rtt).toEqual([]);
    expect(inbound.rttLabel).toBe("this host's ACK delay (not network latency)");
  });

  it('shades zero-window spans until the window reopens', () => {
    const out = series(fed(page(0, 11, bulk(4, { zeroAt: 1 }))), 'outbound');
    expect(out.zeroWindow.inbound).toEqual([{ fromUs: T0 + 5000, toUs: T0 + 6500, open: false }]);
    expect(out.zeroWindow.outbound).toEqual([]);
    const tail = series(fed(page(0, 11, bulk(4, { zeroAt: 3 }))), 'outbound');
    expect(tail.zeroWindow.inbound).toEqual([{ fromUs: T0 + 8000, toUs: T0 + 8000, open: true }]);
  });

  it('shades a window still zero up to the newest sample held, whoever sent it', () => {
    // The sender keeps probing after the receiver's zero window.
    const all = [...bulk(4, { zeroAt: 3 }), s(T0 + 9000, true, { seq: 401, ack: 1, len: 1 }), s(T0 + 9500, true, { seq: 401, ack: 1, len: 1 })];
    const out = series(fed(page(0, all.length, all)), 'outbound');
    expect(out.zeroWindow.inbound).toEqual([{ fromUs: T0 + 8000, toUs: T0 + 9500, open: true }]);
  });

  it('ends a zero-window span at a gap rather than shading across it', () => {
    // Index 6 is the zero window; 8, the reopening, was overwritten unread.
    const all = bulk(4, { zeroAt: 1 });
    const out = series(fed(page(0, 8, all.slice(0, 8)), page(9, all.length, all.slice(9), { droppedOlder: 1 })), 'outbound');
    expect(out.zeroWindow.inbound).toEqual([{ fromUs: T0 + 5000, toUs: all[7].tUs, open: false }]);
  });

  it('marks RST and FIN in either direction', () => {
    const all = [...bulk(1), s(T0 + 9000, true, { flags: F.FIN | F.ACK, seq: 101 }), s(T0 + 9500, false, { flags: F.RST, seq: 1 })];
    const out = series(fed(page(0, all.length, all)), 'outbound');
    expect(out.controlMarks).toEqual([
      { tUs: T0 + 9000, seq: 101, kind: 'FIN', outbound: true },
      { tUs: T0 + 9500, seq: 1, kind: 'RST', outbound: false },
    ]);
  });

  it('shows overwritten history as a gap and a horizon, never interpolation', () => {
    const all = bulk(6);
    // The reader got indices 0..4, then fell behind; the ring overwrote 5..8.
    const state = fed(page(0, 5, all.slice(0, 5)), page(9, all.length, all.slice(9), { droppedOlder: 4 }));
    const out = series(state, 'outbound');
    expect(out.ack.length).toBe(2);
    expect(out.horizon).toEqual({ sinceUs: T0, dropped: 0, gaps: 1 });
    // Joined late: the first page starts past index 0.
    const late = series(fed(page(7, all.length, all.slice(7), { droppedOlder: 7 })), 'outbound');
    expect(late.horizon).toEqual({ sinceUs: all[7].tUs, dropped: 7, gaps: 0 });
  });

  it('notes a midstream join', () => {
    const all = bulk(1);
    expect(series(fed(page(0, all.length, all)), 'outbound').note).toBeNull();
    expect(series(fed(page(0, all.length, all, { relativeTo: 'firstSeen', handshakeSeen: false, windowScale: null })), 'outbound').note).toBe(
      'handshake not captured: sequence relative to first seen segment; window unscaled',
    );
  });

  it('has nothing to draw before the first page', () => {
    const out = series(emptyState(ID), 'outbound');
    expect(out).toMatchObject({ data: [], ack: [], window: [], rtt: [], horizon: null, note: null });
  });
});

describe('heldValues', () => {
  it('includes a step held across the window, not only points inside it', () => {
    const line = [{ tUs: 0, value: 10 }, { tUs: 100, value: 20 }, { tUs: 200, value: 30 }];
    // Zoomed between samples: 20 holds from 100 to 200 across [120, 180].
    expect(heldValues([line], 120, 180)).toEqual([20]);
    expect(heldValues([line], 50, 150)).toEqual([10, 20]);
    // A line's last point does not extend past itself.
    expect(heldValues([line], 250, 300)).toEqual([]);
  });
});

describe('throughput', () => {
  it('sums payload bytes per bin and direction', () => {
    const state = fed(page(0, 11, bulk(4)));
    const bins = throughput(state, T0, T0 + 8000, 2000);
    expect(bins).toEqual([
      { startUs: T0, outbound: 0, inbound: 0 },
      { startUs: T0 + 2000, outbound: 100, inbound: 0 },
      { startUs: T0 + 4000, outbound: 100, inbound: 0 },
      { startUs: T0 + 6000, outbound: 200, inbound: 0 },
    ]);
  });

  it('counts whole bins, so a bin cut by the window edge reads the same as when it is all in view', () => {
    const state = fed(page(0, 11, bulk(4)));
    // Data at T0+3000 sits before the window start, inside its first bin.
    expect(throughput(state, T0 + 3500, T0 + 8000, 2000)[0]).toEqual({ startUs: T0 + 2000, outbound: 100, inbound: 0 });
    // And at the right edge: data at T0+4500, after a window ending T0+4200.
    expect(throughput(state, T0, T0 + 4200, 2000).at(-1)).toEqual({ startUs: T0 + 4000, outbound: 100, inbound: 0 });
  });

  it('leaves out bins the held samples only partly cover, instead of drawing a dip', () => {
    const all = bulk(4);
    // Newest held is T0+8000: [T0+8000, T0+10000) has barely begun.
    expect(throughput(fed(page(0, all.length, all)), T0, T0 + 10_000, 2000).map((b) => b.startUs)).toEqual([T0, T0 + 2000, T0 + 4000, T0 + 6000]);
    // Joined late (oldest held T0+3000): [T0+2000, T0+4000) is only part-seen.
    const late = throughput(fed(page(3, all.length, all.slice(3), { droppedOlder: 3 })), T0 + 2000, T0 + 10_000, 2000);
    expect(late.map((b) => b.startUs)).toEqual([T0 + 4000, T0 + 6000]);
  });

  it('keeps the first bin when the flow was captured from its SYN: nothing came before it', () => {
    const all = bulk(4).map((x) => ({ ...x, tUs: x.tUs + 500 }));
    const bins = throughput(fed(page(0, all.length, all)), T0, T0 + 10_000, 2000);
    expect(bins[0]).toEqual({ startUs: T0, outbound: 0, inbound: 0 });
    expect(bins.map((b) => b.startUs)).toEqual([T0, T0 + 2000, T0 + 4000, T0 + 6000]);
  });

  it('keeps the last bin once the flow has ended: nothing more will arrive', () => {
    const all = [...bulk(4), s(T0 + 9000, true, { flags: F.FIN | F.ACK, seq: 401, ack: 1, len: 50 }), s(T0 + 9500, false, { flags: F.FIN | F.ACK, seq: 1, ack: 452 })];
    const ended = fed(page(0, all.length, all));
    expect(throughput(ended, T0, T0 + 10_000, 2000).at(-1)).toEqual({ startUs: T0 + 8000, outbound: 50, inbound: 0 });
    // A reset ends it too, and so does the agent dropping the flow.
    const reset = [...bulk(4), s(T0 + 9000, false, { flags: F.RST, seq: 1 })];
    expect(throughput(fed(page(0, reset.length, reset)), T0, T0 + 10_000, 2000).at(-1)?.startUs).toBe(T0 + 8000);
    const gone = accumulate(fed(page(0, 11, bulk(4))), { found: false, connectionId: ID });
    expect(throughput(gone, T0, T0 + 10_000, 2000).at(-1)?.startUs).toBe(T0 + 8000);
  });

  it('draws a flow shorter than one bin once it has ended', () => {
    const short = [s(T0 + 100, true, { flags: F.SYN }), s(T0 + 400, true, { seq: 1, len: 10 }), s(T0 + 700, false, { flags: F.RST })];
    expect(throughput(fed(page(0, short.length, short)), T0, T0 + 1000, 1000)).toEqual([{ startUs: T0, outbound: 10, inbound: 0 }]);
  });

  it('picks the interval from the visible window', () => {
    expect(throughputIntervalUs(1_000_000)).toBe(5000);
    expect(throughputIntervalUs(60_000_000)).toBe(500_000);
    expect(throughputIntervalUs(10)).toBe(1000);
    // At most 200 bins for any window.
    for (const span of [1e3, 1e5, 1e7, 3.6e9, 8.64e10]) expect(span / throughputIntervalUs(span)).toBeLessThanOrEqual(200);
  });
});
