// KAN-129 TCP stream graphs (spec D6, plan Task 4): pure state and series.
// `accumulate` merges `tcp_samples` pages by sample index; `series` and
// `throughput` turn the held samples into what TcpGraphsView draws. Header
// metadata only; times are frame timestamps in µs.
import { TCP_SAMPLE_FLAG, TCP_SAMPLE_MARK, type TcpSample, type TcpSamplesPage } from './types';

/** One agent ring; the client never holds more for a flow (spec D6 point budget). */
export const MAX_SAMPLES = 4096;

export interface IndexedSample extends TcpSample {
  index: number;
}

type FoundPage = Extract<TcpSamplesPage, { stale: false }>;
export type TcpPageMeta = Pick<FoundPage, 'handshakeSeen' | 'windowScale' | 'seqBase' | 'relativeTo'>;

export interface TcpGraphState {
  connectionId: string;
  generation: string | null;
  /** Ascending, unique indices. A jump between neighbours is a gap. */
  samples: IndexedSample[];
  nextIndex: number;
  meta: TcpPageMeta | null;
  /** null until the first reply; false once the agent no longer has the flow. */
  found: boolean | null;
}

export function emptyState(connectionId: string): TcpGraphState {
  return { connectionId, generation: null, samples: [], nextIndex: 0, meta: null, found: null };
}

export function accumulate(state: TcpGraphState, page: TcpSamplesPage): TcpGraphState {
  if (!page.found) return { ...state, found: false };
  if (page.stale) return { ...emptyState(state.connectionId), found: true };
  const fresh = state.generation !== page.generation;
  const start = page.nextIndex - page.samples.length;
  const kept = fresh ? [] : state.samples.filter((x) => x.index < start);
  const merged = kept.concat(page.samples.map((x, i) => ({ ...x, index: start + i })));
  return {
    connectionId: state.connectionId,
    generation: page.generation,
    samples: merged.length > MAX_SAMPLES ? merged.slice(merged.length - MAX_SAMPLES) : merged,
    nextIndex: page.nextIndex,
    meta: { handshakeSeen: page.handshakeSeen, windowScale: page.windowScale, seqBase: page.seqBase, relativeTo: page.relativeTo },
    found: true,
  };
}

export interface TcpSamplesQuery {
  connectionId: string;
  generation?: string;
  fromIndex: number;
}

/** The body for the next `POST /api/tcp-samples`. */
export function requestFor(state: TcpGraphState): TcpSamplesQuery {
  return state.generation === null
    ? { connectionId: state.connectionId, fromIndex: 0 }
    : { connectionId: state.connectionId, generation: state.generation, fromIndex: state.nextIndex };
}

export type Direction = 'outbound' | 'inbound';
export interface LinePoint {
  tUs: number;
  value: number;
}
export interface DataPoint {
  tUs: number;
  seqEnd: number;
  retransmit: boolean;
}
export interface ControlMark {
  tUs: number;
  seq: number;
  kind: 'FIN' | 'RST';
  outbound: boolean;
}
export interface ZeroWindowSpan {
  fromUs: number;
  toUs: number;
  /** Still zero at the newest sample held. */
  open: boolean;
}
export interface Horizon {
  sinceUs: number;
  /** Samples before the oldest held (overwritten or never fetched). */
  dropped: number;
  /** Breaks inside what is held. */
  gaps: number;
}
export interface TcpSeries {
  /** Time/sequence (Stevens): one point per data segment of `direction`, at its sequence end. */
  data: DataPoint[];
  /** The opposite direction's cumulative ACK, as lines broken at gaps. */
  ack: LinePoint[][];
  /** ACK + advertised window of the opposite direction. */
  window: LinePoint[][];
  /** RTT samples for `direction`'s data (they sit on the opposite direction's ACKs). */
  rtt: { tUs: number; rttUs: number }[];
  rttLabel: string;
  controlMarks: ControlMark[];
  /** Advertised window over time, per advertiser. */
  advertised: Record<Direction, LinePoint[][]>;
  zeroWindow: Record<Direction, ZeroWindowSpan[]>;
  windowLabel: string;
  /** The midstream-join caveat, or null. */
  note: string | null;
  horizon: Horizon | null;
}

const RTT_LABEL: Record<Direction, string> = {
  outbound: "round trip from this host's capture point",
  inbound: "this host's ACK delay (not network latency)",
};

function has(x: number, bit: number): boolean {
  return (x & bit) !== 0;
}

/** Lines of `pick(sample)` over `samples`, broken where an index is missing. */
function lines(samples: IndexedSample[], include: (x: IndexedSample) => boolean, value: (x: IndexedSample) => number): LinePoint[][] {
  const out: LinePoint[][] = [];
  let current: LinePoint[] | null = null;
  let prev: IndexedSample | null = null;
  for (const x of samples) {
    if (prev && x.index !== prev.index + 1) current = null;
    prev = x;
    if (!include(x)) continue;
    if (!current) out.push((current = []));
    current.push({ tUs: x.tUs, value: value(x) });
  }
  return out;
}

/**
 * The values of step `lines` drawn over [fromUs, toUs]: each point holds
 * until the next, so one before the window still counts while it is held.
 */
export function heldValues(lines: LinePoint[][], fromUs: number, toUs: number): number[] {
  const out: number[] = [];
  for (const l of lines) {
    for (let i = 0; i < l.length; i++) {
      const until = i + 1 < l.length ? l[i + 1].tUs : l[i].tUs;
      if (l[i].tUs <= toUs && until >= fromUs) out.push(l[i].value);
    }
  }
  return out;
}

/**
 * Spans where `outbound`'s advertised window is zero. A zero window holds
 * until that side advertises again, so a span still open runs to the newest
 * sample held; a gap ends it at the last sample before the gap.
 */
function zeroSpans(samples: IndexedSample[], outbound: boolean): ZeroWindowSpan[] {
  const out: ZeroWindowSpan[] = [];
  let from: number | null = null;
  let prev: IndexedSample | null = null;
  for (const x of samples) {
    if (prev && x.index !== prev.index + 1 && from !== null) {
      out.push({ fromUs: from, toUs: prev.tUs, open: false });
      from = null;
    }
    prev = x;
    if (x.outbound !== outbound || has(x.flags, TCP_SAMPLE_FLAG.RST)) continue;
    const zero = x.win === 0 || has(x.mark, TCP_SAMPLE_MARK.ZERO_WINDOW);
    if (zero && from === null) from = x.tUs;
    else if (!zero && from !== null) {
      out.push({ fromUs: from, toUs: x.tUs, open: false });
      from = null;
    }
  }
  if (from !== null && prev) out.push({ fromUs: from, toUs: prev.tUs, open: true });
  return out;
}

function windowLabel(meta: TcpPageMeta | null): string {
  if (meta?.windowScale) return 'scaled';
  return meta?.handshakeSeen ? 'unscaled (scaling not negotiated)' : 'unscaled (handshake not seen)';
}

export function series(state: TcpGraphState, direction: Direction): TcpSeries {
  const { samples, meta } = state;
  const sender = direction === 'outbound';
  const acking = (x: IndexedSample) => x.outbound !== sender && has(x.flags, TCP_SAMPLE_FLAG.ACK);
  let gaps = 0;
  for (let i = 1; i < samples.length; i++) if (samples[i].index !== samples[i - 1].index + 1) gaps++;
  return {
    data: samples
      .filter((x) => x.outbound === sender && x.len > 0)
      .map((x) => ({ tUs: x.tUs, seqEnd: x.seq + x.len, retransmit: has(x.mark, TCP_SAMPLE_MARK.RETRANSMIT) })),
    ack: lines(samples, acking, (x) => x.ack),
    window: lines(samples, acking, (x) => x.ack + x.win),
    rtt: samples.filter((x) => x.outbound !== sender && has(x.mark, TCP_SAMPLE_MARK.RTT)).map((x) => ({ tUs: x.tUs, rttUs: x.rttUs })),
    rttLabel: RTT_LABEL[direction],
    controlMarks: samples
      .filter((x) => has(x.flags, TCP_SAMPLE_FLAG.FIN | TCP_SAMPLE_FLAG.RST))
      .map((x) => ({ tUs: x.tUs, seq: x.seq, kind: has(x.flags, TCP_SAMPLE_FLAG.RST) ? ('RST' as const) : ('FIN' as const), outbound: x.outbound })),
    advertised: {
      outbound: lines(samples, (x) => x.outbound, (x) => x.win),
      inbound: lines(samples, (x) => !x.outbound, (x) => x.win),
    },
    zeroWindow: { outbound: zeroSpans(samples, true), inbound: zeroSpans(samples, false) },
    windowLabel: windowLabel(meta),
    note: meta && meta.relativeTo !== 'isn' ? 'handshake not captured: sequence relative to first seen segment; window unscaled' : null,
    horizon: samples.length ? { sinceUs: samples[0].tUs, dropped: samples[0].index, gaps } : null,
  };
}

// 1 ms … 1 h, in µs.
const BIN_STEPS_US = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10_000, 30_000, 60_000, 120_000, 300_000, 600_000, 1_800_000, 3_600_000].map(
  (ms) => ms * 1000,
);
const MAX_BINS = 200;

/** The finest bin width that keeps the visible window at or under 200 bins. */
export function throughputIntervalUs(spanUs: number): number {
  return BIN_STEPS_US.find((step) => spanUs / step <= MAX_BINS) ?? BIN_STEPS_US[BIN_STEPS_US.length - 1];
}

export interface ThroughputBin {
  startUs: number;
  outbound: number;
  inbound: number;
}

/** Earliest and latest `tUs` held (capture order need not be time order), or null. */
export function timeRange(state: TcpGraphState): [number, number] | null {
  if (!state.samples.length) return null;
  let lo = Infinity;
  let hi = -Infinity;
  for (const x of state.samples) {
    if (x.tUs < lo) lo = x.tUs;
    if (x.tUs > hi) hi = x.tUs;
  }
  return [lo, hi];
}

/** Whether the agent will send no more samples: a reset, FIN both ways, or the flow gone. */
function ended(state: TcpGraphState): boolean {
  if (state.found === false) return true;
  let finOut = false;
  let finIn = false;
  for (const x of state.samples) {
    if (has(x.flags, TCP_SAMPLE_FLAG.RST)) return true;
    if (has(x.flags, TCP_SAMPLE_FLAG.FIN)) {
      if (x.outbound) finOut = true;
      else finIn = true;
    }
  }
  return finOut && finIn;
}

/**
 * Payload bytes per `binUs`, both directions, for the bins (aligned to
 * multiples of `binUs`) that overlap [fromUs, toUs). Each bin counts every
 * sample in it, so one cut by the window edge reads as when it is in view.
 * A bin the held samples only partly cover is left out, not drawn as a
 * dip: the first when samples before the oldest held were missed (joined
 * late, or dropped), the last while the flow may still send. A flow
 * captured from its SYN has nothing before it, and one that has ended
 * nothing after it, so those edge bins are whole.
 */
export function throughput(state: TcpGraphState, fromUs: number, toUs: number, binUs: number): ThroughputBin[] {
  const range = timeRange(state);
  if (!range) return [];
  const head = state.samples[0];
  const fromStart = head.index === 0 && has(head.flags, TCP_SAMPLE_FLAG.SYN);
  const oldestBin = (fromStart ? Math.floor(range[0] / binUs) : Math.ceil(range[0] / binUs)) * binUs;
  const first = Math.max(Math.floor(fromUs / binUs) * binUs, oldestBin);
  const held = ended(state) ? Math.floor((range[1] - first) / binUs) + 1 : Math.floor((range[1] - first) / binUs);
  const count = Math.max(0, Math.min(held, Math.ceil((toUs - first) / binUs)));
  const bins: ThroughputBin[] = Array.from({ length: count }, (_, i) => ({ startUs: first + i * binUs, outbound: 0, inbound: 0 }));
  for (const x of state.samples) {
    if (x.len === 0) continue;
    const bin = bins[Math.floor((x.tUs - first) / binUs)];
    if (!bin) continue;
    if (x.outbound) bin.outbound += x.len;
    else bin.inbound += x.len;
  }
  return bins;
}
