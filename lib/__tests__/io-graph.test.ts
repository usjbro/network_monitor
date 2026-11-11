// JAM-18 Task 3: browser IO graph history (lib/io-graph.ts).
import { describe, expect, it } from 'vitest';
import {
  RING_CAPACITY,
  aggregateValue,
  allowedIntervals,
  createHistory,
  finestAllowed,
  horizonText,
  ingestBuckets,
  ingestStatus,
  latestCoveredMs,
  newRequestId,
  query,
  rate,
  ticks,
} from '../io-graph';
import type { IoBucket, IoBuckets, IoSeriesStatus } from '../types';

const T0 = 1_794_120_000_000; // a whole minute

function status(revision: number, ids: string[], epoch = 'aaaabbbb'): IoSeriesStatus {
  return { revision, epoch, replayWaiting: false, series: ids.map((id) => ({ id, filter: '', ok: true })) };
}

function msg(over: Partial<IoBuckets> & { series: IoBuckets['series'] }): IoBuckets {
  return {
    revision: 1,
    epoch: 'aaaabbbb',
    bucketMs: 100,
    coveredFromMs: T0,
    coveredToMs: T0 + 1000,
    notObserved: [],
    loss: { kernelDropped: 0, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 },
    ...over,
  };
}

function series(id: string, buckets: IoBucket[], extra: Partial<IoBuckets['series'][number]> = {}) {
  return { id, late: 0, lateBuckets: [], buckets, ...extra };
}

function fullSecond(start: number, packets: number, bytes: number): Array<[number, number, number]> {
  return Array.from({ length: 10 }, (_, i) => [start + i * 100, packets, bytes] as [number, number, number]);
}

describe('roll-up', () => {
  it('coarser intervals are exact sums of the 100 ms buckets', () => {
    const h = createHistory();
    ingestStatus(h, status(1, ['all']));
    for (let s = 0; s < 120; s++) {
      ingestBuckets(h, msg({ coveredFromMs: T0 + s * 1000, coveredToMs: T0 + (s + 1) * 1000, series: [series('all', fullSecond(T0 + s * 1000, 3, 300))] }));
    }
    const fine = query(h, 'all', 100, T0, T0 + 120_000);
    const sec = query(h, 'all', 1000, T0, T0 + 120_000);
    const ten = query(h, 'all', 10000, T0, T0 + 120_000);
    const min = query(h, 'all', 60000, T0, T0 + 120_000);
    const total = (ps: { packets: number }[]) => ps.reduce((a, p) => a + p.packets, 0);
    expect([fine.length, sec.length, ten.length, min.length]).toEqual([1200, 120, 12, 2]);
    expect(total(fine)).toBe(3600);
    expect(total(sec)).toBe(3600);
    expect(total(ten)).toBe(3600);
    expect(total(min)).toBe(3600);
    expect(sec[0]).toMatchObject({ packets: 30, bytes: 3000, state: 'value' });
    expect(ten[0].packets).toBe(300);
    expect(min[1].packets).toBe(1800);
    expect(rate(sec[0], 'packets', 1000)).toBe(30);
    expect(rate(sec[0], 'bits', 1000)).toBe(24000);
    expect(rate(fine[0], 'packets', 100)).toBe(30);
  });
});

describe('zero, unknown and not observed stay distinct', () => {
  it('a covered empty bucket is a true zero; uncovered time is unknown; notObserved is its own state', () => {
    const h = createHistory();
    ingestStatus(h, status(1, ['all']));
    ingestBuckets(h, msg({
      coveredFromMs: T0, coveredToMs: T0 + 1000,
      notObserved: [{ fromMs: T0 + 300, toMs: T0 + 500, reason: 'interface_switch' }],
      series: [series('all', [[T0, 5, 50]])],
    }));
    const points = query(h, 'all', 100, T0 - 200, T0 + 1200);
    const at = (ms: number) => points.find((p) => p.startMs === ms)!;
    expect(at(T0 - 200).state).toBe('unknown');
    expect(at(T0)).toMatchObject({ state: 'value', packets: 5 });
    expect(at(T0 + 100)).toMatchObject({ state: 'value', packets: 0 });
    expect(at(T0 + 300).state).toBe('notObserved');
    expect(at(T0 + 400).state).toBe('notObserved');
    expect(at(T0 + 500).state).toBe('value');
    expect(at(T0 + 1000).state).toBe('unknown');
    // A coarser bucket overlapping a notObserved span reports that, the
    // more specific signal, ahead of "unknown".
    expect(query(h, 'all', 10000, T0, T0 + 10000)[0].state).toBe('notObserved');
  });

  it('a coarser bucket that is only partly covered is unknown, not a small value', () => {
    const h = createHistory();
    ingestBuckets(h, msg({ series: [series('all', [[T0, 5, 50]])] }));
    expect(query(h, 'all', 10000, T0, T0 + 10000)[0]).toMatchObject({ state: 'unknown', packets: 0 });
    expect(query(h, 'all', 1000, T0, T0 + 1000)[0]).toMatchObject({ state: 'value', packets: 5 });
  });

  it('a zero-length marker (replay_error) does not blank any bucket', () => {
    const h = createHistory();
    ingestBuckets(h, msg({ notObserved: [{ fromMs: T0 + 1000, toMs: T0 + 1000, reason: 'replay_error' }], series: [series('all', [])] }));
    expect(query(h, 'all', 100, T0, T0 + 1000).every((p) => p.state === 'value')).toBe(true);
    expect(h.markers).toEqual([{ ms: T0 + 1000, reason: 'replay_error' }]);
  });
});

describe('late frames and loss', () => {
  it('late frames are kept apart from on-time counts at every interval', () => {
    const h = createHistory();
    ingestBuckets(h, msg({ series: [series('all', [[T0, 4, 40]])] }));
    ingestBuckets(h, msg({ coveredFromMs: T0 + 1000, coveredToMs: T0 + 1000, series: [series('all', [], { lateBuckets: [[T0 + 100, 2, 20]] })] }));
    const fine = query(h, 'all', 100, T0, T0 + 200);
    expect(fine[0]).toMatchObject({ packets: 4, latePackets: 0 });
    expect(fine[1]).toMatchObject({ packets: 0, latePackets: 2 });
    expect(query(h, 'all', 1000, T0, T0 + 1000)[0]).toMatchObject({ packets: 4, latePackets: 2 });
  });

  it('unattributed late frames are recorded against their message span', () => {
    const h = createHistory();
    ingestBuckets(h, msg({ series: [series('all', [], { late: 7 })] }));
    expect(h.unplacedLate).toEqual([{ fromMs: T0, toMs: T0 + 1000, series: 0, frames: 7 }]);
    expect(h.unplacedLateTotal).toEqual([7]);
    // Shown on every interval the message span touches, apart from on-time counts.
    const points = query(h, 'all', 100, T0, T0 + 1000);
    expect(points.every((p) => p.unplacedLate === 7 && p.latePackets === 0 && p.packets === 0)).toBe(true);
    expect(query(h, 'all', 100, T0 + 1000, T0 + 1100)[0].unplacedLate).toBe(0);
  });

  it('loss shades the whole message span, never a single bucket', () => {
    const h = createHistory();
    ingestBuckets(h, msg({ loss: { kernelDropped: 3, ifDropped: 0, unparseable: 1, evaluationSkipped: 0 }, series: [series('all', [])] }));
    const fine = query(h, 'all', 100, T0, T0 + 1000);
    expect(fine.every((p) => p.lossy)).toBe(true);
    expect(query(h, 'all', 100, T0 + 1000, T0 + 1100)[0].lossy).toBe(false);
  });
});

describe('segments', () => {
  it('an epoch change starts a new history; the old counts are gone', () => {
    const h = createHistory();
    ingestBuckets(h, msg({ series: [series('all', [[T0, 9, 90]])] }));
    ingestBuckets(h, msg({ epoch: 'ccccdddd', coveredFromMs: T0 + 5000, coveredToMs: T0 + 6000, series: [series('all', [])] }));
    expect(h.epoch).toBe('ccccdddd');
    expect(query(h, 'all', 100, T0, T0 + 100)[0].state).toBe('unknown');
    expect(h.startedMs).toBe(T0 + 5000);
  });

  it('a new revision drops removed series and restarts history', () => {
    const h = createHistory();
    ingestStatus(h, status(1, ['a', 'b']));
    ingestBuckets(h, msg({ series: [series('a', [[T0, 1, 1]]), series('b', [[T0, 2, 2]])] }));
    ingestStatus(h, status(2, ['b']));
    expect(h.ids).toEqual(['b']);
    expect(query(h, 'a', 100, T0, T0 + 100)).toEqual([]);
    expect(query(h, 'b', 100, T0, T0 + 100)[0].state).toBe('unknown');
  });

  it('a rejected status changes nothing, and re-applying the same status is a no-op', () => {
    const h = createHistory();
    ingestStatus(h, status(1, ['a']));
    ingestBuckets(h, msg({ series: [series('a', [[T0, 1, 1]])] }));
    ingestStatus(h, { ...status(1, ['zzz']), rejected: 'conflict' });
    ingestStatus(h, status(1, ['a']));
    expect(query(h, 'a', 100, T0, T0 + 100)[0].packets).toBe(1);
  });

  it('a series the current segment does not know yet restarts the segment before anything is added', () => {
    const h = createHistory();
    ingestStatus(h, status(1, ['a']));
    ingestBuckets(h, msg({ series: [series('a', [[T0, 1, 1]]), series('b', [[T0, 2, 2]])] }));
    expect(h.ids).toEqual(['a', 'b']);
    expect(query(h, 'a', 100, T0, T0 + 100)[0].packets).toBe(1);
    expect(query(h, 'b', 100, T0, T0 + 100)[0].packets).toBe(2);
  });

  it('buckets arriving before their status still form a segment, without losing the first message', () => {
    const h = createHistory();
    ingestBuckets(h, msg({ series: [series('x', [[T0, 1, 1]]), series('y', [[T0, 2, 2]])] }));
    expect(query(h, 'x', 100, T0, T0 + 100)[0].packets).toBe(1);
    expect(query(h, 'y', 100, T0, T0 + 100)[0].packets).toBe(2);
  });
});

describe('retention', () => {
  it('the 100 ms ring wraps at capacity: older buckets become unknown, and the horizon says so', () => {
    const h = createHistory();
    const seconds = RING_CAPACITY[100] / 10 + 30; // 15.5 minutes of 100 ms buckets
    for (let s = 0; s < seconds; s++) {
      ingestBuckets(h, msg({ coveredFromMs: T0 + s * 1000, coveredToMs: T0 + (s + 1) * 1000, series: [series('all', fullSecond(T0 + s * 1000, 1, 1))] }));
    }
    expect(query(h, 'all', 100, T0, T0 + 100)[0].state).toBe('unknown');
    const end = T0 + seconds * 1000;
    expect(query(h, 'all', 100, end - 100, end)[0]).toMatchObject({ state: 'value', packets: 1 });
    // The 1 s ring (1 h) still has the start.
    expect(query(h, 'all', 1000, T0, T0 + 1000)[0]).toMatchObject({ state: 'value', packets: 10 });
    expect(horizonText(h, 100, 'UTC')).toContain('retention limit reached: 15 min at 100 ms');
    expect(horizonText(h, 1000, 'UTC')).not.toContain('retention limit');
    expect(horizonText(h, 1000, 'UTC')).toContain('History since');
  });

  it('a bucket older than the ring horizon is dropped, never written over newer data', () => {
    const h = createHistory();
    ingestBuckets(h, msg({ coveredFromMs: T0 + 1_000_000, coveredToMs: T0 + 1_001_000, series: [series('all', [[T0 + 1_000_000, 5, 5]])] }));
    // A late report for the bucket exactly one ring capacity older maps to
    // the same 100 ms slot as the newest bucket; it must not evict it.
    const sameSlot = T0 + 1_000_000 - RING_CAPACITY[100] * 100;
    ingestBuckets(h, msg({ coveredFromMs: T0 + 1_001_000, coveredToMs: T0 + 1_001_000, series: [series('all', [], { lateBuckets: [[sameSlot, 1, 1]] })] }));
    expect(query(h, 'all', 100, T0 + 1_000_000, T0 + 1_000_100)[0]).toMatchObject({ packets: 5, latePackets: 0 });
  });
});

describe('intervals and ticks', () => {
  it('disables intervals that would exceed 2000 points, with a reason', () => {
    const tenMinutes = allowedIntervals(T0, T0 + 600_000);
    expect(tenMinutes.find((i) => i.interval === 100)).toMatchObject({ allowed: false });
    expect(tenMinutes.find((i) => i.interval === 100)!.reason).toContain('6000 points');
    expect(tenMinutes.find((i) => i.interval === 1000)!.allowed).toBe(true);
    expect(finestAllowed(T0, T0 + 200_000)).toBe(100);
    expect(finestAllowed(T0, T0 + 200_100)).toBe(1000);
    expect(finestAllowed(T0, T0 + 10 * 86_400_000)).toBe(60000);
  });

  it('labels sub-second ticks with milliseconds and coarse ones without', () => {
    const fine = ticks(T0, T0 + 1000, 6, 'UTC');
    expect(fine[0].label).toMatch(/^\d\d:\d\d:\d\d\.\d{3}$/);
    const coarse = ticks(T0, T0 + 3_600_000, 6, 'UTC');
    expect(coarse.every((t) => /^\d\d:\d\d:\d\d$/.test(t.label))).toBe(true);
    expect(coarse.length).toBeGreaterThan(2);
    expect(coarse.length).toBeLessThanOrEqual(7);
  });

  it('labels across midnight and a DST change use wall-clock time', () => {
    // 2026-03-08 01:59:59 -> 03:00:00 in New York (spring forward).
    const beforeJump = Date.UTC(2026, 2, 8, 6, 59, 0);
    const labels = ticks(beforeJump, beforeJump + 120_000, 6, 'America/New_York').map((t) => t.label);
    expect(labels).toContain('03:00:00');
    expect(labels.some((l) => l.startsWith('01:59'))).toBe(true);
    const midnight = Date.UTC(2026, 10, 10, 23, 59, 0);
    expect(ticks(midnight, midnight + 120_000, 6, 'UTC').map((t) => t.label)).toContain('00:00:00');
  });

  it('latest covered time and request ids', () => {
    const h = createHistory();
    expect(latestCoveredMs(h)).toBeNull();
    ingestBuckets(h, msg({ series: [series('all', [])] }));
    ingestBuckets(h, msg({ coveredFromMs: T0 + 1000, coveredToMs: T0 + 2000, series: [series('all', [])] }));
    expect(latestCoveredMs(h)).toBe(T0 + 2000);
    expect(query(h, 'all', 1000, T0, T0 + 2000).map((p) => p.state)).toEqual(['value', 'value']);
    expect(newRequestId()).toMatch(/^[0-9a-f]{16}$/);
  });
});

// PR #306 review fixes.
describe('review: revisions (I1)', () => {
  it("a late tail of the replaced set's buckets, sent under the old revision, does not bring the old set back", () => {
    const h = createHistory();
    ingestStatus(h, status(1, ['a', 'b']));
    ingestBuckets(h, msg({ series: [series('a', [[T0, 1, 1]]), series('b', [[T0, 2, 2]])] }));
    // The new set counts nothing (every filter failed), so no new-revision buckets follow.
    ingestStatus(h, status(2, []));
    ingestBuckets(h, msg({ revision: 1, coveredFromMs: T0 + 1000, coveredToMs: T0 + 1500, series: [series('a', [[T0 + 1000, 3, 3]]), series('b', [])] }));
    expect(h.revision).toBe(2);
    expect(h.ids).toEqual([]);
    // And an older status in the same epoch is ignored too.
    ingestStatus(h, status(1, ['a', 'b']));
    expect(h.revision).toBe(2);
  });

  it('a newer revision arriving before its status still starts its segment', () => {
    const h = createHistory();
    ingestStatus(h, status(1, ['a']));
    ingestBuckets(h, msg({ revision: 2, series: [series('c', [[T0, 4, 4]])] }));
    expect(h.revision).toBe(2);
    expect(query(h, 'c', 100, T0, T0 + 100)[0].packets).toBe(4);
  });
});

describe('review: coverage, loss and not observed last as long as the rings (I2)', () => {
  it('sustained loss keeps its flag for all of retained history, not just the newest 512 messages', () => {
    const h = createHistory();
    const seconds = 1200; // 20 min, one lossy message per second
    for (let s = 0; s < seconds; s++) {
      ingestBuckets(h, msg({
        coveredFromMs: T0 + s * 1000, coveredToMs: T0 + (s + 1) * 1000,
        loss: { kernelDropped: 1, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 },
        series: [series('all', [[T0 + s * 1000, 1, 1]])],
      }));
    }
    expect(query(h, 'all', 1000, T0, T0 + 1000)[0]).toMatchObject({ state: 'value', lossy: true });
    expect(query(h, 'all', 60000, T0, T0 + 60000)[0]).toMatchObject({ state: 'value', lossy: true });
  });

  it('old backlog spans stay not observed, never drawn as zero', () => {
    const h = createHistory();
    for (let s = 0; s < 1200; s++) {
      ingestBuckets(h, msg({
        coveredFromMs: T0 + s * 1000, coveredToMs: T0 + (s + 1) * 1000,
        notObserved: [{ fromMs: T0 + s * 1000 + 500, toMs: T0 + s * 1000 + 600, reason: 'backlog' }],
        series: [series('all', [])],
      }));
    }
    const first = query(h, 'all', 1000, T0, T0 + 1000)[0];
    expect(first).toMatchObject({ state: 'notObserved', packets: 0, notObservedMs: 100, notObservedReason: 'backlog' });
    // At 1 min the partial share is reported, so the readout can say so.
    expect(query(h, 'all', 60000, T0, T0 + 60000)[0]).toMatchObject({ state: 'notObserved', notObservedMs: 6000 });
  });

  it('a duplicated or overlapping message is not counted twice (minor 9)', () => {
    const h = createHistory();
    const m = msg({ series: [series('all', fullSecond(T0, 2, 20))] });
    ingestBuckets(h, m);
    ingestBuckets(h, m);
    expect(query(h, 'all', 1000, T0, T0 + 1000)[0]).toMatchObject({ state: 'value', packets: 20 });
  });
});

describe('review: late frames are never dropped (I3)', () => {
  it('a late bucket older than every ring is kept on the message span', () => {
    const h = createHistory();
    const now = T0 + 2 * 86_400_000;
    ingestBuckets(h, msg({ coveredFromMs: now, coveredToMs: now + 1000, series: [series('all', [[now, 1, 1]])] }));
    ingestBuckets(h, msg({ coveredFromMs: now + 1000, coveredToMs: now + 1000, series: [series('all', [], { lateBuckets: [[T0, 5, 50]] })] }));
    expect(h.unplacedLateTotal).toEqual([5]);
    const at = query(h, 'all', 1000, now + 1000, now + 2000)[0];
    expect(at).toMatchObject({ unplacedLate: 5, packets: 0, latePackets: 0 });
  });

  it('the running total survives the side list being truncated', () => {
    const h = createHistory();
    for (let s = 0; s < 600; s++) ingestBuckets(h, msg({ coveredFromMs: T0 + s * 1000, coveredToMs: T0 + (s + 1) * 1000, series: [series('all', [], { late: 1 })] }));
    expect(h.unplacedLate.length).toBeLessThanOrEqual(512);
    expect(h.unplacedLateTotal).toEqual([600]);
  });
});

describe('review: windows never hide the newest data (I4)', () => {
  it('a window needing more than 2000 points keeps the newest ones', () => {
    const h = createHistory();
    const end = T0 + 3000 * 100;
    ingestBuckets(h, msg({ coveredFromMs: end - 1000, coveredToMs: end, series: [series('all', [[end - 100, 7, 7]])] }));
    const points = query(h, 'all', 100, T0, end);
    expect(points).toHaveLength(2000);
    expect(points[points.length - 1]).toMatchObject({ startMs: end - 100, packets: 7, state: 'value' });
  });

  it('counts interval-aligned points, so an unaligned window is not one over the limit', () => {
    expect(finestAllowed(T0 + 50, T0 + 50 + 200_000)).toBe(1000); // 2001 aligned points at 100 ms
  });
});

describe('review: horizon for sparse series (minor 1)', () => {
  it('reports the retention limit once the segment spans more than the ring, even with gaps', () => {
    const h = createHistory();
    ingestBuckets(h, msg({ series: [series('all', [[T0, 1, 1]])] }));
    const later = T0 + 20 * 60_000; // 20 min later: past the 15 min ring
    ingestBuckets(h, msg({ coveredFromMs: later, coveredToMs: later + 1000, series: [series('all', [[later, 1, 1]])] }));
    expect(horizonText(h, 100, 'UTC')).toContain('retention limit reached: 15 min at 100 ms');
    expect(horizonText(h, 1000, 'UTC')).not.toContain('retention limit');
  });
});

describe('review: ticks at hour-plus steps follow local wall clock (minor 7)', () => {
  it('hourly ticks land on the hour in a +5:30 zone', () => {
    const from = Date.UTC(2026, 10, 10, 0, 10, 0);
    const labels = ticks(from, from + 6 * 3_600_000, 6, 'Asia/Kolkata').map((t) => t.label);
    expect(labels.length).toBeGreaterThan(2);
    expect(labels.every((l) => /^\d\d:00:00$/.test(l))).toBe(true);
  });

  it('skip the missing hour across a spring-forward change, staying on the hour', () => {
    // New York, 2026-03-08: 02:00 local does not exist.
    const from = Date.UTC(2026, 2, 8, 5, 0, 0); // 00:00 EST
    const labels = ticks(from, from + 5 * 3_600_000, 6, 'America/New_York').map((t) => t.label);
    expect(labels).toEqual(['00:00:00', '01:00:00', '03:00:00', '04:00:00', '05:00:00']);
  });

  it('6-hourly ticks across days carry the date and align to local midnight', () => {
    const from = Date.UTC(2026, 10, 10, 3, 0, 0); // 22:00 EST on 9 Nov
    const labels = ticks(from, from + 24 * 3_600_000, 6, 'America/New_York').map((t) => t.label);
    expect(labels[0]).toMatch(/^10 Nov,? 00:00$/);
    expect(labels).toHaveLength(4);
  });
});

// JAM-18 Task 5 (spec D10): numeric-field aggregates in the history.
describe('aggregates', () => {
  function aggHistory() {
    const h = createHistory();
    ingestStatus(h, { revision: 1, epoch: 'aaaabbbb', replayWaiting: false, series: [{ id: 'win', filter: '', ok: true, aggregate: { fn: 'avg', field: 'tcp.window_size' } }] });
    ingestBuckets(h, msg({
      coveredFromMs: T0, coveredToMs: T0 + 2000,
      series: [series('win', [
        [T0, 1, 60, 1, 10, 10, 10],
        [T0 + 100, 3, 180, 3, 90, 20, 40],
        [T0 + 200, 2, 120, 0, 0, null, null], // matched frames, none had the field
        [T0 + 1000, 1, 60, 1, 7, 7, 7],
      ])],
    }));
    return h;
  }

  it('AVG is sum / count at every interval, never an average of averages', () => {
    const h = aggHistory();
    const sec = query(h, 'win', 1000, T0, T0 + 2000);
    // (10 + 90) / (1 + 3) = 25, not (10 + 30) / 2 = 20.
    expect(aggregateValue(sec[0], 'avg', 1000)).toBe(25);
    expect(aggregateValue(sec[1], 'avg', 1000)).toBe(7);
    const tenSec = query(h, 'win', 10000, T0, T0 + 10000);
    expect(tenSec[0].state).toBe('unknown'); // only 2 s of the 10 s are covered
    const fine = query(h, 'win', 100, T0, T0 + 300);
    expect(fine.map((p) => aggregateValue(p, 'avg', 100))).toEqual([10, 30, null]);
  });

  it('SUM, MIN and MAX roll up exactly; a count of 0 has no value', () => {
    const h = aggHistory();
    const sec = query(h, 'win', 1000, T0, T0 + 1000)[0];
    expect(sec).toMatchObject({ packets: 6, aggCount: 4, aggSum: 100, aggMin: 10, aggMax: 40 });
    expect([aggregateValue(sec, 'sum', 1000), aggregateValue(sec, 'min', 1000), aggregateValue(sec, 'max', 1000)]).toEqual([100, 10, 40]);
    const empty = query(h, 'win', 100, T0 + 200, T0 + 300)[0];
    expect(empty).toMatchObject({ state: 'value', packets: 2, aggCount: 0, aggMin: null, aggMax: null });
    for (const fn of ['sum', 'min', 'max', 'avg'] as const) expect(aggregateValue(empty, fn, 100)).toBeNull();
    // Rolled into the 1 min ring too, once the whole minute is covered.
    expect(aggregateValue(query(h, 'win', 60000, T0, T0 + 60000)[0], 'sum', 60000)).toBeNull();
    ingestBuckets(h, msg({ coveredFromMs: T0 + 2000, coveredToMs: T0 + 60000, series: [series('win', [])] }));
    const minute = query(h, 'win', 60000, T0, T0 + 60000)[0];
    expect(minute).toMatchObject({ aggCount: 5, aggSum: 107, aggMin: 7, aggMax: 40 });
  });

  it('a plain series has no aggregate values', () => {
    const h = createHistory();
    ingestBuckets(h, msg({ series: [series('all', [[T0, 4, 40]])] }));
    const p = query(h, 'all', 1000, T0, T0 + 1000)[0];
    expect(p).toMatchObject({ aggCount: 0, aggMin: null, aggMax: null });
    expect(aggregateValue(p, 'avg', 1000)).toBeNull();
  });

  it('unknown and not-observed intervals have no aggregate value', () => {
    const h = aggHistory();
    expect(aggregateValue(query(h, 'win', 1000, T0 + 5000, T0 + 6000)[0], 'sum', 1000)).toBeNull();
  });
});
