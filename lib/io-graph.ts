// IO graph browser history (JAM-18 Task 3; spec
// docs/superpowers/specs/2026-11-10-io-graph-design.md D4/D5/D6/D8).
//
// Pure: no React, no DOM. The agent sends complete 100 ms bucket counts
// (io_buckets); this keeps them in fixed-capacity rings at three
// resolutions and answers "what does the chart show for this window",
// keeping three states distinct for every bucket:
//   - a counted value (a true zero is a value),
//   - unknown (outside every covered range, or aged out of the ring),
//   - not observed (inside a notObserved range from the agent).
// Late frames, loss and coverage are tracked separately and never merged
// into on-time counts.

import type { IoBuckets, IoNotObservedReason, IoSeriesStatus } from './types';

export const BUCKET_MS = 100;
export type IoInterval = 100 | 1000 | 10000 | 60000;
export const IO_INTERVALS: readonly IoInterval[] = [100, 1000, 10000, 60000];
export const MAX_POINTS = 2000;

// Ring capacities (spec D4): 15 min at 100 ms, 1 h at 1 s, 24 h at 1 min.
// The 10 s interval is summed from the 1 s ring.
export const RING_CAPACITY = { 100: 9000, 1000: 3600, 60000: 1440 } as const;
type RingResolution = keyof typeof RING_CAPACITY;
const RESOLUTIONS: readonly RingResolution[] = [100, 1000, 60000];

// Bounds on the side lists, so a long session cannot grow them.
const MAX_SPANS = 512;

class Ring {
  readonly keys: Float64Array;
  readonly packets: Float64Array;
  readonly bytes: Float64Array;
  readonly latePackets: Float64Array;
  readonly lateBytes: Float64Array;
  newestKey = -Infinity;

  constructor(readonly resolution: RingResolution, readonly series: number) {
    const capacity = RING_CAPACITY[resolution];
    this.keys = new Float64Array(capacity).fill(-1);
    this.packets = new Float64Array(capacity * series);
    this.bytes = new Float64Array(capacity * series);
    this.latePackets = new Float64Array(capacity * series);
    this.lateBytes = new Float64Array(capacity * series);
  }

  private slot(key: number): number {
    const capacity = this.keys.length;
    const slot = key % capacity;
    if (this.keys[slot] !== key) {
      // Reusing the slot evicts whatever older bucket held it.
      this.keys[slot] = key;
      const base = slot * this.series;
      for (let i = 0; i < this.series; i++) {
        this.packets[base + i] = 0;
        this.bytes[base + i] = 0;
        this.latePackets[base + i] = 0;
        this.lateBytes[base + i] = 0;
      }
    }
    if (key > this.newestKey) this.newestKey = key;
    return slot;
  }

  add(startMs: number, series: number, packets: number, bytes: number, late: boolean): void {
    const key = Math.floor(startMs / this.resolution);
    // A key older than the ring's horizon is dropped, never written over a
    // newer bucket.
    if (key <= this.newestKey - this.keys.length) return;
    const i = this.slot(key) * this.series + series;
    if (late) {
      this.latePackets[i] += packets;
      this.lateBytes[i] += bytes;
    } else {
      this.packets[i] += packets;
      this.bytes[i] += bytes;
    }
  }

  /** The bucket at `key`, or null when it has aged out or was never written. */
  get(key: number, series: number): { packets: number; bytes: number; latePackets: number; lateBytes: number } | null {
    const slot = key % this.keys.length;
    if (this.keys[slot] !== key) return null;
    const i = slot * this.series + series;
    return { packets: this.packets[i], bytes: this.bytes[i], latePackets: this.latePackets[i], lateBytes: this.lateBytes[i] };
  }

  /** Oldest key still retained (by capacity), given the newest written. */
  oldestRetainedKey(): number {
    return this.newestKey - this.keys.length + 1;
  }

  wrapped(): boolean {
    return Number.isFinite(this.newestKey) && this.keys.every((k) => k >= 0);
  }
}

export interface Span {
  fromMs: number;
  toMs: number;
}

export interface NotObservedSpan extends Span {
  reason: IoNotObservedReason;
}

export interface LossSpan extends Span {
  frames: number;
}

export interface IoHistory {
  epoch: string | null;
  revision: number | null;
  ids: string[];
  /** Ring per resolution, built for the current revision's series. */
  rings: Map<RingResolution, Ring>;
  covered: Span[];
  notObserved: NotObservedSpan[];
  loss: LossSpan[];
  /** Late frames not attributed to a bucket, per series, with their span. */
  unattributedLate: Array<Span & { series: number; frames: number }>;
  /** When this history segment started (first covered ms), for the horizon text. */
  startedMs: number | null;
  /** Bumped on every change, so a view can re-render cheaply. */
  version: number;
}

export function createHistory(): IoHistory {
  return {
    epoch: null,
    revision: null,
    ids: [],
    rings: new Map(),
    covered: [],
    notObserved: [],
    loss: [],
    unattributedLate: [],
    startedMs: null,
    version: 0,
  };
}

function resetSegment(h: IoHistory, epoch: string, revision: number, ids: string[]): void {
  h.epoch = epoch;
  h.revision = revision;
  h.ids = [...ids];
  h.rings = new Map(RESOLUTIONS.map((r) => [r, new Ring(r, Math.max(ids.length, 1))]));
  h.covered = [];
  h.notObserved = [];
  h.loss = [];
  h.unattributedLate = [];
  h.startedMs = null;
}

function pushBounded<T>(list: T[], item: T): void {
  list.push(item);
  if (list.length > MAX_SPANS) list.splice(0, list.length - MAX_SPANS);
}

/**
 * A new epoch (agent restart) or revision (series set changed) starts a
 * new history segment: bucket counts are only comparable within one
 * (epoch, revision). Applying the same status twice is a no-op.
 */
export function ingestStatus(h: IoHistory, status: IoSeriesStatus): void {
  if (status.rejected) return; // the set did not change
  if (h.epoch === status.epoch && h.revision === status.revision) return;
  resetSegment(h, status.epoch, status.revision, status.series.map((s) => s.id));
  h.version++;
}

export function ingestBuckets(h: IoHistory, msg: IoBuckets): void {
  // A new (epoch, revision), or a series the current segment does not know
  // (its status has not arrived yet), starts a segment keyed by the
  // message's own series. Checked once, before anything is added.
  if (h.epoch !== msg.epoch || h.revision !== msg.revision || msg.series.some((s) => !h.ids.includes(s.id))) {
    resetSegment(h, msg.epoch, msg.revision, msg.series.map((s) => s.id));
  }
  msg.series.forEach((s) => {
    const i = h.ids.indexOf(s.id);
    for (const ring of h.rings.values()) {
      for (const [start, packets, bytes] of s.buckets) ring.add(start, i, packets, bytes, false);
      for (const [start, packets, bytes] of s.lateBuckets) ring.add(start, i, packets, bytes, true);
    }
    if (s.late > 0) {
      pushBounded(h.unattributedLate, { fromMs: msg.coveredFromMs, toMs: msg.coveredToMs, series: i, frames: s.late });
    }
  });
  if (msg.coveredToMs > msg.coveredFromMs) {
    const last = h.covered[h.covered.length - 1];
    if (last && last.toMs === msg.coveredFromMs) last.toMs = msg.coveredToMs;
    else pushBounded(h.covered, { fromMs: msg.coveredFromMs, toMs: msg.coveredToMs });
    if (h.startedMs === null) h.startedMs = msg.coveredFromMs;
  }
  for (const n of msg.notObserved) pushBounded(h.notObserved, { fromMs: n.fromMs, toMs: n.toMs, reason: n.reason });
  const frames = msg.loss.kernelDropped + msg.loss.ifDropped + msg.loss.unparseable + msg.loss.evaluationSkipped;
  // Loss is reported per message, so it shades the whole message span; it
  // is never spread across buckets as though its timing were known.
  if (frames > 0) pushBounded(h.loss, { fromMs: msg.coveredFromMs, toMs: Math.max(msg.coveredToMs, msg.coveredFromMs + BUCKET_MS), frames });
  h.version++;
}

export type PointState = 'value' | 'unknown' | 'notObserved';

export interface IoPoint {
  startMs: number;
  state: PointState;
  packets: number;
  bytes: number;
  /** Late frames attributed to this interval, kept apart from `packets`. */
  latePackets: number;
  /** Loss reported in a message whose span overlaps this interval. */
  lossy: boolean;
}

function overlaps(a: Span, fromMs: number, toMs: number): boolean {
  return a.fromMs < toMs && fromMs < a.toMs;
}

function fullyCovered(h: IoHistory, fromMs: number, toMs: number): boolean {
  // Covered spans are disjoint and in order; walk the union across [from, to).
  let cursor = fromMs;
  for (const s of h.covered) {
    if (s.toMs <= cursor) continue;
    if (s.fromMs > cursor) return false;
    cursor = s.toMs;
    if (cursor >= toMs) return true;
  }
  return false;
}

function ringFor(interval: IoInterval): RingResolution {
  return interval === 10000 ? 1000 : interval;
}

/**
 * Points for one series over [fromMs, toMs) at `interval`. Coarser
 * intervals are exact sums of the 100 ms counts the agent sent.
 */
export function query(h: IoHistory, seriesId: string, interval: IoInterval, fromMs: number, toMs: number): IoPoint[] {
  const series = h.ids.indexOf(seriesId);
  const ring = h.rings.get(ringFor(interval));
  const points: IoPoint[] = [];
  if (series < 0 || !ring) return points;
  const step = ring.resolution;
  const first = Math.floor(fromMs / interval) * interval;
  // Only spans that touch the window matter; filter once, not per point.
  const notObservedHere = h.notObserved.filter((n) => n.toMs > n.fromMs && overlaps(n, first, toMs));
  const lossHere = h.loss.filter((l) => overlaps(l, first, toMs));
  for (let start = first; start < toMs && points.length < MAX_POINTS; start += interval) {
    const end = start + interval;
    let packets = 0;
    let bytes = 0;
    let latePackets = 0;
    let retained = true;
    for (let t = start; t < end; t += step) {
      const key = Math.floor(t / step);
      if (key < ring.oldestRetainedKey()) retained = false;
      const b = ring.get(key, series);
      if (b) {
        packets += b.packets;
        bytes += b.bytes;
        latePackets += b.latePackets;
      }
    }
    const notObserved = notObservedHere.some((n) => overlaps(n, start, end));
    const state: PointState = notObserved ? 'notObserved' : retained && fullyCovered(h, start, end) ? 'value' : 'unknown';
    points.push({
      startMs: start,
      state,
      packets: state === 'value' ? packets : 0,
      bytes: state === 'value' ? bytes : 0,
      latePackets,
      lossy: lossHere.some((l) => overlaps(l, start, end)),
    });
  }
  return points;
}

export type Measure = 'packets' | 'bits';

/** A point's value as a per-second rate in the measure's unit. */
export function rate(point: IoPoint, measure: Measure, interval: IoInterval): number {
  const seconds = interval / 1000;
  return measure === 'packets' ? point.packets / seconds : (point.bytes * 8) / seconds;
}

/** Intervals that keep the window within MAX_POINTS points per series. */
export function allowedIntervals(fromMs: number, toMs: number): { interval: IoInterval; allowed: boolean; reason?: string }[] {
  const span = Math.max(0, toMs - fromMs);
  return IO_INTERVALS.map((interval) => {
    const points = Math.ceil(span / interval);
    return points <= MAX_POINTS
      ? { interval, allowed: true }
      : { interval, allowed: false, reason: `${points} points per series; the limit is ${MAX_POINTS}. Zoom in or pick a coarser interval.` };
  });
}

/** The finest allowed interval for a window. */
export function finestAllowed(fromMs: number, toMs: number): IoInterval {
  return allowedIntervals(fromMs, toMs).find((i) => i.allowed)?.interval ?? 60000;
}

const TICK_STEPS = [
  100, 200, 500, 1000, 2000, 5000, 10000, 15000, 30000, 60000, 120000, 300000, 600000, 900000, 1800000, 3600000,
  7200000, 10800000, 21600000, 43200000, 86400000,
];

export interface Tick {
  ms: number;
  label: string;
}

/**
 * About `target` labelled ticks across [fromMs, toMs). Labels are wall-clock
 * time in `timeZone` (the viewer's own by default), with milliseconds only
 * when the step is sub-second.
 */
export function ticks(fromMs: number, toMs: number, target = 6, timeZone?: string): Tick[] {
  const span = toMs - fromMs;
  if (!(span > 0)) return [];
  const step = TICK_STEPS.find((s) => span / s <= target) ?? TICK_STEPS[TICK_STEPS.length - 1];
  const format = new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
    timeZone,
    ...(step < 1000 ? { fractionalSecondDigits: 3 as const } : {}),
  });
  const out: Tick[] = [];
  for (let t = Math.ceil(fromMs / step) * step; t < toMs; t += step) out.push({ ms: t, label: format.format(new Date(t)) });
  return out;
}

/** "History since 14:02:11" plus any retention limit already reached. */
export function horizonText(h: IoHistory, interval: IoInterval, timeZone?: string): string {
  if (h.startedMs === null) return 'No IO graph data yet';
  const fmt = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZone });
  const ring = h.rings.get(ringFor(interval));
  const limit = interval === 100 ? '15 min at 100 ms' : interval === 60000 ? '24 h at 1 min' : '1 h at 1 s';
  const parts = [`History since ${fmt.format(new Date(h.startedMs))} (this tab; lost on reload)`];
  if (ring?.wrapped()) parts.push(`retention limit reached: ${limit}`);
  return parts.join(' · ');
}

/** Newest covered time, for live-follow mode. */
export function latestCoveredMs(h: IoHistory): number | null {
  return h.covered.length ? h.covered[h.covered.length - 1].toMs : null;
}

/** A random hex request id for set_io_series (8–32 hex digits). */
export function newRequestId(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
