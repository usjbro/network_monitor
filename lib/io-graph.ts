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
//
// Coverage, not-observed time and loss are kept per ring slot, next to the
// counts, so they live exactly as long as the counts they describe: no side
// list can be truncated while the rings still hold the data.

import type { IoAggregateFn, IoBuckets, IoNotObservedReason, IoSeriesStatus } from './types';

export const BUCKET_MS = 100;
export type IoInterval = 100 | 1000 | 10000 | 60000;
export const IO_INTERVALS: readonly IoInterval[] = [100, 1000, 10000, 60000];
export const MAX_POINTS = 2000;

// Ring capacities (spec D4): 15 min at 100 ms, 1 h at 1 s, 24 h at 1 min.
// The 10 s interval is summed from the 1 s ring.
export const RING_CAPACITY = { 100: 9000, 1000: 3600, 60000: 1440 } as const;
type RingResolution = keyof typeof RING_CAPACITY;
const RESOLUTIONS: readonly RingResolution[] = [100, 1000, 60000];
/** The longest history any ring holds (24 h); no window is wider. */
export const MAX_HISTORY_MS = RING_CAPACITY[60000] * 60000;

// Bounds on the two side lists that are not per slot. Both are rare
// (zero-length markers; late frames whose bucket aged out of every ring),
// and the late list's frames are also kept in a running total that is
// never truncated.
const MAX_MARKERS = 64;
const MAX_UNPLACED_SPANS = 512;

const REASONS: readonly IoNotObservedReason[] = ['interface_switch', 'replay_error', 'backlog', 'unknown'];

class Ring {
  readonly keys: Float64Array;
  readonly packets: Float64Array;
  readonly bytes: Float64Array;
  readonly latePackets: Float64Array;
  readonly lateBytes: Float64Array;
  /** Per slot: ms of the slot inside a covered range. */
  readonly coveredMs: Float64Array;
  /** Per slot: ms of the slot inside a notObserved range, and its reason. */
  readonly notObservedMs: Float64Array;
  readonly notObservedReason: Uint8Array;
  /** Per slot: 1 if a message reporting loss covered any of the slot. */
  readonly lossy: Uint8Array;
  /**
   * Per (slot, series): numeric-field aggregates (Task 5), allocated on the
   * first aggregate bucket so plain series cost nothing. min/max are NaN
   * where no frame had the field.
   */
  agg: { count: Float64Array; sum: Float64Array; min: Float64Array; max: Float64Array } | null = null;
  newestKey = -Infinity;
  firstKey = Infinity;

  constructor(readonly resolution: RingResolution, readonly series: number) {
    const capacity = RING_CAPACITY[resolution];
    this.keys = new Float64Array(capacity).fill(-1);
    this.packets = new Float64Array(capacity * series);
    this.bytes = new Float64Array(capacity * series);
    this.latePackets = new Float64Array(capacity * series);
    this.lateBytes = new Float64Array(capacity * series);
    this.coveredMs = new Float64Array(capacity);
    this.notObservedMs = new Float64Array(capacity);
    this.notObservedReason = new Uint8Array(capacity);
    this.lossy = new Uint8Array(capacity);
  }

  get capacity(): number {
    return this.keys.length;
  }

  /**
   * The slot for `key`, claiming (and clearing) it if it held an older key.
   * -1 when the key is older than the ring's horizon: it is never written
   * over a newer bucket.
   */
  private claim(key: number): number {
    if (key <= this.newestKey - this.capacity) return -1;
    const slot = key % this.capacity;
    if (this.keys[slot] !== key) {
      this.keys[slot] = key;
      const base = slot * this.series;
      this.packets.fill(0, base, base + this.series);
      this.bytes.fill(0, base, base + this.series);
      this.latePackets.fill(0, base, base + this.series);
      this.lateBytes.fill(0, base, base + this.series);
      this.coveredMs[slot] = 0;
      this.notObservedMs[slot] = 0;
      this.notObservedReason[slot] = 0;
      this.lossy[slot] = 0;
      if (this.agg) {
        this.agg.count.fill(0, base, base + this.series);
        this.agg.sum.fill(0, base, base + this.series);
        this.agg.min.fill(Number.NaN, base, base + this.series);
        this.agg.max.fill(Number.NaN, base, base + this.series);
      }
    }
    if (key > this.newestKey) this.newestKey = key;
    if (key < this.firstKey) this.firstKey = key;
    return slot;
  }

  /** Adds a count; false when its bucket is older than this ring holds. */
  add(startMs: number, series: number, packets: number, bytes: number, late: boolean): boolean {
    const slot = this.claim(Math.floor(startMs / this.resolution));
    if (slot < 0) return false;
    const i = slot * this.series + series;
    if (late) {
      this.latePackets[i] += packets;
      this.lateBytes[i] += bytes;
    } else {
      this.packets[i] += packets;
      this.bytes[i] += bytes;
    }
    return true;
  }

  /**
   * Adds an on-time bucket's aggregate (count, sum, min, max). Late frames
   * never carry one. False when the bucket is older than this ring holds.
   */
  addAggregate(startMs: number, series: number, count: number, sum: number, min: number | null, max: number | null): boolean {
    const slot = this.claim(Math.floor(startMs / this.resolution));
    if (slot < 0) return false;
    if (!this.agg) {
      const n = this.keys.length * this.series;
      this.agg = { count: new Float64Array(n), sum: new Float64Array(n), min: new Float64Array(n).fill(Number.NaN), max: new Float64Array(n).fill(Number.NaN) };
    }
    const i = slot * this.series + series;
    this.agg.count[i] += count;
    this.agg.sum[i] += sum;
    // NaN (no value yet) loses every comparison, so test it explicitly.
    if (min !== null && !(this.agg.min[i] <= min)) this.agg.min[i] = min;
    if (max !== null && !(this.agg.max[i] >= max)) this.agg.max[i] = max;
    return true;
  }

  /** Calls `fn(slot, overlapMs)` for every retained slot overlapping [fromMs, toMs). */
  private eachSlot(fromMs: number, toMs: number, fn: (slot: number, overlapMs: number) => void): void {
    if (!(toMs > fromMs)) return;
    const res = this.resolution;
    const lastKey = Math.floor((toMs - 1) / res);
    // Older keys than one capacity behind the span's end could never be retained.
    const firstKey = Math.max(Math.floor(fromMs / res), lastKey - this.capacity + 1);
    for (let key = firstKey; key <= lastKey; key++) {
      const slot = this.claim(key);
      if (slot < 0) continue;
      const overlap = Math.min(toMs, (key + 1) * res) - Math.max(fromMs, key * res);
      fn(slot, overlap);
    }
  }

  markCovered(fromMs: number, toMs: number): void {
    const res = this.resolution;
    this.eachSlot(fromMs, toMs, (slot, ms) => {
      this.coveredMs[slot] = Math.min(res, this.coveredMs[slot] + ms);
    });
  }

  markNotObserved(fromMs: number, toMs: number, reason: IoNotObservedReason): void {
    const res = this.resolution;
    const code = REASONS.indexOf(reason) + 1;
    this.eachSlot(fromMs, toMs, (slot, ms) => {
      this.notObservedMs[slot] = Math.min(res, this.notObservedMs[slot] + ms);
      this.notObservedReason[slot] = code;
    });
  }

  markLoss(fromMs: number, toMs: number): void {
    this.eachSlot(fromMs, toMs, (slot) => {
      this.lossy[slot] = 1;
    });
  }

  /** The slot holding `key`, or -1 when it has aged out or was never written. */
  slotOf(key: number): number {
    const slot = key % this.capacity;
    return this.keys[slot] === key ? slot : -1;
  }

  /** True once the segment has written more keys than the ring holds. */
  wrapped(): boolean {
    return Number.isFinite(this.newestKey) && this.newestKey - this.firstKey + 1 > this.capacity;
  }
}

export interface Span {
  fromMs: number;
  toMs: number;
}

export interface Marker {
  ms: number;
  reason: IoNotObservedReason;
}

export interface UnplacedLate extends Span {
  series: number;
  frames: number;
}

export interface IoHistory {
  epoch: string | null;
  revision: number | null;
  ids: string[];
  /** Ring per resolution, built for the current revision's series. */
  rings: Map<RingResolution, Ring>;
  /** End of the newest covered range (covered ranges abut, per the wire protocol). */
  highWaterMs: number | null;
  /** Zero-length notObserved markers (e.g. replay_error at end of file). */
  markers: Marker[];
  /**
   * Late frames that could not be placed in a retained bucket: the scalar
   * `late` overflow, and late buckets older than every ring. Recorded
   * against their message's span (spec D5).
   */
  unplacedLate: UnplacedLate[];
  /** Running totals of unplaced late frames per series; never truncated. */
  unplacedLateTotal: number[];
  /** When this history segment started (first covered ms), for the horizon text. */
  startedMs: number | null;
  /** First covered ms seen in this agent epoch (kept across revision changes). */
  epochStartedMs: number | null;
  /** Bumped on every change, so a view can re-render cheaply. */
  version: number;
}

export function createHistory(): IoHistory {
  return {
    epoch: null,
    revision: null,
    ids: [],
    rings: new Map(),
    highWaterMs: null,
    markers: [],
    unplacedLate: [],
    unplacedLateTotal: [],
    startedMs: null,
    epochStartedMs: null,
    version: 0,
  };
}

function resetSegment(h: IoHistory, epoch: string, revision: number, ids: string[]): void {
  if (h.epoch !== epoch) h.epochStartedMs = null;
  h.epoch = epoch;
  h.revision = revision;
  h.ids = [...ids];
  h.rings = new Map(RESOLUTIONS.map((r) => [r, new Ring(r, Math.max(ids.length, 1))]));
  h.highWaterMs = null;
  h.markers = [];
  h.unplacedLate = [];
  h.unplacedLateTotal = ids.map(() => 0);
  h.startedMs = null;
}

function pushBounded<T>(list: T[], item: T, max: number): void {
  list.push(item);
  if (list.length > max) list.splice(0, list.length - max);
}

/** Within one epoch, revisions only move forward. */
function isOlder(h: IoHistory, epoch: string, revision: number): boolean {
  return h.epoch === epoch && h.revision !== null && revision < h.revision;
}

/**
 * A new epoch (agent restart) or revision (series set changed) starts a
 * new history segment: bucket counts are only comparable within one
 * (epoch, revision). Applying the same status twice, or an older one, is
 * a no-op.
 */
export function ingestStatus(h: IoHistory, status: IoSeriesStatus): void {
  if (status.rejected) return; // the set did not change
  if (h.epoch === status.epoch && h.revision === status.revision) return;
  if (isOlder(h, status.epoch, status.revision)) return;
  resetSegment(h, status.epoch, status.revision, status.series.map((s) => s.id));
  h.version++;
}

function addUnplaced(h: IoHistory, span: Span, series: number, frames: number): void {
  h.unplacedLateTotal[series] = (h.unplacedLateTotal[series] ?? 0) + frames;
  const last = h.unplacedLate[h.unplacedLate.length - 1];
  if (last && last.series === series && last.fromMs === span.fromMs && last.toMs === span.toMs) last.frames += frames;
  else pushBounded(h.unplacedLate, { ...span, series, frames }, MAX_UNPLACED_SPANS);
}

export function ingestBuckets(h: IoHistory, msg: IoBuckets): void {
  // The agent closes a replaced set's open buckets under the old revision
  // after announcing the new one (docs/wire-protocol.md "Revision
  // changes"). That tail belongs to a set the chart no longer shows.
  if (isOlder(h, msg.epoch, msg.revision)) return;
  // A new (epoch, revision), or a series the current segment does not know
  // (its status has not arrived yet), starts a segment keyed by the
  // message's own series. Checked once, before anything is added.
  if (h.epoch !== msg.epoch || h.revision !== msg.revision || msg.series.some((s) => !h.ids.includes(s.id))) {
    resetSegment(h, msg.epoch, msg.revision, msg.series.map((s) => s.id));
  }
  const rings = [...h.rings.values()];
  // Covered ranges abut; anything before the high-water mark was already
  // counted, so a duplicated or overlapping message cannot count it twice.
  const already = h.highWaterMs ?? -Infinity;
  const span: Span = { fromMs: msg.coveredFromMs, toMs: msg.coveredToMs };
  msg.series.forEach((s) => {
    const i = h.ids.indexOf(s.id);
    for (const bucket of s.buckets) {
      const [start, packets, bytes] = bucket;
      if (start < already) continue;
      for (const ring of rings) ring.add(start, i, packets, bytes, false);
      if (bucket.length === 7) {
        for (const ring of rings) ring.addAggregate(start, i, bucket[3], bucket[4], bucket[5], bucket[6]);
      }
    }
    for (const [start, packets, bytes] of s.lateBuckets) {
      let placed = false;
      for (const ring of rings) placed = ring.add(start, i, packets, bytes, true) || placed;
      // Aged out of every ring: the count stays on the message span.
      if (!placed) addUnplaced(h, span, i, packets);
    }
    if (s.late > 0) addUnplaced(h, span, i, s.late);
  });
  const coveredFrom = Math.max(msg.coveredFromMs, already);
  if (msg.coveredToMs > coveredFrom) {
    for (const ring of rings) ring.markCovered(coveredFrom, msg.coveredToMs);
    h.highWaterMs = msg.coveredToMs;
    if (h.startedMs === null) h.startedMs = coveredFrom;
    if (h.epochStartedMs === null) h.epochStartedMs = coveredFrom;
  }
  for (const n of msg.notObserved) {
    if (n.toMs > n.fromMs) for (const ring of rings) ring.markNotObserved(n.fromMs, n.toMs, n.reason);
    else pushBounded(h.markers, { ms: n.fromMs, reason: n.reason }, MAX_MARKERS);
  }
  const frames = msg.loss.kernelDropped + msg.loss.ifDropped + msg.loss.unparseable + msg.loss.evaluationSkipped;
  // Loss is reported per message, so it shades the whole message span; it
  // is never spread across buckets as though its timing were known.
  if (frames > 0) {
    const to = Math.max(msg.coveredToMs, msg.coveredFromMs + BUCKET_MS);
    for (const ring of rings) ring.markLoss(msg.coveredFromMs, to);
  }
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
  /** Late frames whose own bucket is not known, from a message span touching this interval. */
  unplacedLate: number;
  /** Loss reported in a message whose span overlaps this interval. */
  lossy: boolean;
  /** How much of the interval was not observed, and why (the latest reason). */
  notObservedMs: number;
  notObservedReason?: IoNotObservedReason;
  /**
   * Numeric-field aggregate (Task 5) over the interval's on-time frames that
   * had the field: exact roll-ups of the agent's per-bucket values. 0 and
   * null for a plain series, or when no frame had the field.
   */
  aggCount: number;
  aggSum: number;
  aggMin: number | null;
  aggMax: number | null;
}

function touches(span: Span, fromMs: number, toMs: number): boolean {
  // A zero-length span touches the interval that contains its instant.
  if (span.toMs <= span.fromMs) return fromMs <= span.fromMs && span.fromMs < toMs;
  return span.fromMs < toMs && fromMs < span.toMs;
}

function ringFor(interval: IoInterval): RingResolution {
  return interval === 10000 ? 1000 : interval;
}

/** Interval-aligned point count for [fromMs, toMs). */
export function pointCount(fromMs: number, toMs: number, interval: IoInterval): number {
  if (!(toMs > fromMs)) return 0;
  return Math.floor((toMs - 1) / interval) - Math.floor(fromMs / interval) + 1;
}

interface IntervalSum {
  state: PointState;
  packets: number;
  bytes: number;
  latePackets: number;
  unplacedLate: number;
  lossy: boolean;
  notObservedMs: number;
  notObservedReason?: IoNotObservedReason;
  aggCount: number;
  aggSum: number;
  aggMin: number;
  aggMax: number;
}

/** Raw on-time and late sums for one interval, with its coverage state. */
function sumInterval(ring: Ring, series: number, start: number, interval: IoInterval, unplaced: UnplacedLate[]): IntervalSum {
  const step = ring.resolution;
  const { keys, packets: P, bytes: B, latePackets: L, coveredMs, notObservedMs: N, notObservedReason: R, lossy: X } = ring;
  const capacity = ring.capacity;
  let packets = 0;
  let bytes = 0;
  let latePackets = 0;
  let covered = 0;
  let notObservedMs = 0;
  let reasonCode = 0;
  let lossy = false;
  let aggCount = 0;
  let aggSum = 0;
  let aggMin = Infinity;
  let aggMax = -Infinity;
  const agg = ring.agg;
  const firstKey = start / step;
  for (let k = 0, n = interval / step; k < n; k++) {
    const key = firstKey + k;
    const slot = key % capacity;
    if (keys[slot] !== key) continue; // aged out or never written: not covered
    const i = slot * ring.series + series;
    packets += P[i];
    bytes += B[i];
    latePackets += L[i];
    covered += coveredMs[slot];
    notObservedMs += N[slot];
    if (R[slot]) reasonCode = R[slot];
    if (X[slot]) lossy = true;
    if (agg && agg.count[i] > 0) {
      aggCount += agg.count[i];
      aggSum += agg.sum[i];
      if (agg.min[i] < aggMin) aggMin = agg.min[i];
      if (agg.max[i] > aggMax) aggMax = agg.max[i];
    }
  }
  // Not observed is the more specific signal, so it wins over unknown.
  const state: PointState = notObservedMs > 0 ? 'notObserved' : covered >= interval ? 'value' : 'unknown';
  let unplacedLate = 0;
  if (unplaced.length) for (const u of unplaced) if (touches(u, start, start + interval)) unplacedLate += u.frames;
  return {
    state, packets, bytes, latePackets, unplacedLate, lossy, notObservedMs,
    notObservedReason: reasonCode ? REASONS[reasonCode - 1] : undefined,
    aggCount, aggSum, aggMin, aggMax,
  };
}

/**
 * Points for one series over [fromMs, toMs) at `interval`. Coarser
 * intervals are exact sums of the 100 ms counts the agent sent. At most
 * MAX_POINTS points; if the window would need more, the newest are kept.
 */
export function query(h: IoHistory, seriesId: string, interval: IoInterval, fromMs: number, toMs: number): IoPoint[] {
  const series = h.ids.indexOf(seriesId);
  const ring = h.rings.get(ringFor(interval));
  const points: IoPoint[] = [];
  if (series < 0 || !ring || !(toMs > fromMs)) return points;
  const step = ring.resolution;
  const last = Math.floor((toMs - 1) / interval) * interval;
  const first = Math.max(Math.floor(fromMs / interval) * interval, last - (MAX_POINTS - 1) * interval);
  const unplacedHere = h.unplacedLate.filter((u) => u.series === series && touches(u, first, last + interval));
  for (let start = first; start <= last; start += interval) {
    const sum = sumInterval(ring, series, start, interval, unplacedHere);
    const value = sum.state === 'value';
    const agg = value && sum.aggCount > 0;
    points.push({
      startMs: start,
      state: sum.state,
      packets: value ? sum.packets : 0,
      bytes: value ? sum.bytes : 0,
      latePackets: sum.latePackets,
      unplacedLate: sum.unplacedLate,
      lossy: sum.lossy,
      notObservedMs: sum.notObservedMs,
      notObservedReason: sum.notObservedReason,
      aggCount: agg ? sum.aggCount : 0,
      aggSum: agg ? sum.aggSum : 0,
      aggMin: agg ? sum.aggMin : null,
      aggMax: agg ? sum.aggMax : null,
    });
  }
  return points;
}

/**
 * A point's aggregate (Task 5) as the chart plots it: SUM is the interval's
 * total, MIN/MAX its extremes, AVG sum / count over the whole interval
 * (never an average of averages). Null where there is nothing to show: no
 * frame had the field, or the interval is not a counted value.
 */
export function aggregateValue(point: IoPoint, fn: IoAggregateFn, interval: IoInterval): number | null {
  void interval; // values are per interval, not per second
  if (point.state !== 'value' || point.aggCount === 0) return null;
  switch (fn) {
    case 'sum': return point.aggSum;
    case 'min': return point.aggMin;
    case 'max': return point.aggMax;
    case 'avg': return point.aggSum / point.aggCount;
  }
}

export type Measure = 'packets' | 'bits';

/** A point's value as a per-second rate in the measure's unit. */
export function rate(point: IoPoint, measure: Measure, interval: IoInterval): number {
  const seconds = interval / 1000;
  return measure === 'packets' ? point.packets / seconds : (point.bytes * 8) / seconds;
}

/** Intervals that keep the window within MAX_POINTS points per series. */
export function allowedIntervals(fromMs: number, toMs: number): { interval: IoInterval; allowed: boolean; reason?: string }[] {
  return IO_INTERVALS.map((interval) => {
    const points = pointCount(fromMs, toMs, interval);
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

const partsFormats = new Map<string, Intl.DateTimeFormat>();

/** The zone's offset from UTC at `ms` (local wall time minus UTC), in ms. */
export function zoneOffsetMs(ms: number, timeZone?: string): number {
  const key = timeZone ?? '';
  let fmt = partsFormats.get(key);
  if (!fmt) {
    fmt = new Intl.DateTimeFormat('en-US', {
      timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
    partsFormats.set(key, fmt);
  }
  const p: Record<string, number> = {};
  for (const part of fmt.formatToParts(new Date(ms))) if (part.type !== 'literal') p[part.type] = Number(part.value);
  const wall = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
  return wall - (ms - (((ms % 1000) + 1000) % 1000));
}

function localDay(ms: number, timeZone?: string): number {
  return Math.floor((ms + zoneOffsetMs(ms, timeZone)) / 86_400_000);
}

/**
 * About `target` labelled ticks across [fromMs, toMs). Labels are wall-clock
 * time in `timeZone` (the viewer's own by default), with milliseconds only
 * when the step is sub-second. Steps of a minute or more are aligned to
 * local wall-clock multiples (so hourly ticks land on the hour in a +5:30
 * zone, and across DST), and carry the date when the window spans days.
 */
export function ticks(fromMs: number, toMs: number, target = 6, timeZone?: string): Tick[] {
  const span = toMs - fromMs;
  if (!(span > 0)) return [];
  const step = TICK_STEPS.find((s) => span / s <= target) ?? TICK_STEPS[TICK_STEPS.length - 1];
  const withDate = step >= 3_600_000 && localDay(fromMs, timeZone) !== localDay(toMs - 1, timeZone);
  const format = new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZone,
    ...(withDate ? { day: 'numeric', month: 'short' } : { second: '2-digit' }),
    ...(step < 1000 ? { fractionalSecondDigits: 3 as const } : {}),
  });
  const out: Tick[] = [];
  const push = (t: number) => {
    if (t >= fromMs && t < toMs && (out.length === 0 || t > out[out.length - 1].ms)) out.push({ ms: t, label: format.format(new Date(t)) });
  };
  if (step < 60_000) {
    for (let t = Math.ceil(fromMs / step) * step; t < toMs; t += step) push(t);
    return out;
  }
  // Walk local wall-clock multiples of the step and map each back to UTC.
  let offset = zoneOffsetMs(fromMs, timeZone);
  for (let wall = Math.ceil((fromMs + offset) / step) * step, guard = 0; guard < 1000; wall += step, guard++) {
    let t = wall - offset;
    const actual = zoneOffsetMs(t, timeZone);
    if (actual !== offset) {
      t = wall - actual;
      offset = actual;
    }
    if (t >= toMs) break;
    push(t);
  }
  return out;
}

/** "History since 14:02:11" plus any retention limit already reached. */
export function horizonText(h: IoHistory, interval: IoInterval, timeZone?: string): string {
  if (h.startedMs === null) return 'No IO graph data yet';
  const ring = h.rings.get(ringFor(interval));
  const limit = interval === 100 ? '15 min at 100 ms' : interval === 60000 ? '24 h at 1 min' : '1 h at 1 s';
  const parts = [`History since ${clock(h.startedMs, timeZone)} (this tab; lost on reload)`];
  if (ring?.wrapped()) parts.push(`retention limit reached: ${limit}`);
  return parts.join(' · ');
}

/** HH:MM:SS in `timeZone`. */
export function clock(ms: number, timeZone?: string): string {
  return new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZone }).format(new Date(ms));
}

/** Newest covered time, for live-follow mode. */
export function latestCoveredMs(h: IoHistory): number | null {
  return h.highWaterMs;
}

/** A random hex request id for set_io_series (8–32 hex digits). */
export function newRequestId(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// --- Click-through (spec D7) ---------------------------------------------

/** The agent's counts for one interval of one series, for click-through. */
export interface DrillInfo {
  seriesId: string;
  interval: IoInterval;
  fromMs: number;
  toMs: number;
  /** On-time frames the agent counted (even in a partly not-observed interval). */
  onTime: number;
  /** Late frames reported against this interval's own buckets. */
  late: number;
  /** Late frames whose bucket is not known, from a message span touching this interval. */
  unplacedLate: number;
  lossy: boolean;
  state: PointState;
  notObservedMs: number;
  notObservedReason?: IoNotObservedReason;
}

/** The interval of `interval` containing `atMs`, with the agent's counts for it. */
export function drillDown(h: IoHistory, seriesId: string, interval: IoInterval, atMs: number): DrillInfo | null {
  const series = h.ids.indexOf(seriesId);
  const ring = h.rings.get(ringFor(interval));
  if (series < 0 || !ring) return null;
  const fromMs = Math.floor(atMs / interval) * interval;
  const toMs = fromMs + interval;
  const sum = sumInterval(ring, series, fromMs, interval, h.unplacedLate.filter((u) => u.series === series && touches(u, fromMs, toMs)));
  return {
    seriesId, interval, fromMs, toMs,
    onTime: sum.packets, late: sum.latePackets, unplacedLate: sum.unplacedLate, lossy: sum.lossy,
    state: sum.state, notObservedMs: sum.notObservedMs, notObservedReason: sum.notObservedReason,
  };
}

const DRILL_INTERVAL_LABEL: Record<IoInterval, string> = { 100: '100 ms', 1000: '1 s', 10000: '10 s', 60000: '1 min' };
const DRILL_REASON_LABEL: Record<IoNotObservedReason, string> = {
  interface_switch: 'interface switch', replay_error: 'replay error', backlog: 'backlog', unknown: 'unknown reason',
};

function clockMs(ms: number, timeZone?: string): string {
  return new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3, hourCycle: 'h23', timeZone,
  }).format(new Date(ms));
}

function durationText(ms: number): string {
  return ms < 1000 ? `${Math.round(ms)} ms` : ms < 60_000 ? `${+(ms / 1000).toFixed(1)} s` : `${+(ms / 60_000).toFixed(1)} min`;
}

/**
 * What the Packets view can show for a drilled interval, stated exactly
 * (spec D7). `k` is the number of buffered packets in [fromMs, toMs) that
 * match the series filter; it is never clamped. N is the agent's on-time
 * count plus late frames attributed to the interval. Never suggests replay:
 * replayed frames pass the same packet-event rate limit.
 */
export function describeDrill(info: DrillInfo, k: number, opts: { filter: string; bufferLimit?: number; timeZone?: string }): { headline: string; detail: string[] } {
  const range = `${clockMs(info.fromMs, opts.timeZone)}–${clockMs(info.toMs, opts.timeZone)}`;
  const what = opts.filter.trim() ? `${range} matching \`${opts.filter.trim()}\`` : `${range} (every frame)`;
  const detail: string[] = [];
  const counted = info.state !== 'unknown';
  const n = info.onTime + info.late;
  let headline: string;
  if (!counted) {
    headline = `${k} packets in ${what} are available here.`;
    detail.push("This tab holds no agent count for this interval (it was not covered, or has aged out of this tab's history), so there is no total to compare against.");
  } else if (k > n || info.unplacedLate > 0) {
    headline = `${k} packets in ${what} are available here; the agent's count for this interval is incomplete (late frames).`;
    if (info.unplacedLate > 0) detail.push(`${info.unplacedLate} late frames were reported without their interval and may belong here.`);
  } else if (n === 0) {
    headline = `The agent counted no packets in ${what}.`;
  } else if (k === n) {
    headline = `All ${n} packets in ${what} are available here.`;
  } else {
    headline = `${k} of ${n} packets in ${what} are available here.`;
    const buffer = opts.bufferLimit !== undefined ? `the ${opts.bufferLimit}-packet buffer` : "this tab's packet buffer";
    detail.push(`The other ${n - k} were counted by the agent but not sent to the browser (rate-limited to 100 packet events/s) or have aged out of ${buffer}.`);
    detail.push('To inspect all of them, record a capture file (`capture <file.pcapng>`) and open it in an external analyzer at this time range.');
  }
  if (counted && info.late > 0) detail.push(`${n} includes ${info.late} late frames reported after the interval closed.`);
  if (info.notObservedMs > 0) {
    const why = info.notObservedReason ? ` (${DRILL_REASON_LABEL[info.notObservedReason]})` : '';
    detail.push(`Not observed for ${durationText(info.notObservedMs)} of this ${DRILL_INTERVAL_LABEL[info.interval]} interval${why}: the agent counted nothing then, and no packets from that time can be shown.`);
  }
  if (info.lossy) detail.push('Frames were lost before counting in this interval (dropped by the kernel or interface, unparseable, or skipped), so the agent\'s count is itself incomplete.');
  return { headline, detail };
}
