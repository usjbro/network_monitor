// JAM-18 Task 4 (KAN-111): click-through from an IO graph interval to the
// buffered packets in it (spec D7). drillDown reads the agent's counts for
// the interval; describeDrill states, from those counts and k (the buffered
// packets that match), exactly what the browser can show.
import { describe, expect, it } from 'vitest';
import { createHistory, describeDrill, drillDown, ingestBuckets, ingestStatus } from '../io-graph';
import type { IoBuckets } from '../types';

const T0 = 1_794_120_000_000;
const NO_LOSS = { kernelDropped: 0, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 };

function history(extra: Partial<IoBuckets> = {}, series: IoBuckets['series'] = [{ id: 'dns', late: 0, lateBuckets: [], buckets: [[T0, 40, 4000], [T0 + 500, 2, 200]] }]) {
  const h = createHistory();
  ingestStatus(h, { revision: 1, epoch: 'aaaabbbb', replayWaiting: false, series: [{ id: 'dns', filter: 'dns', ok: true }] });
  ingestBuckets(h, { revision: 1, epoch: 'aaaabbbb', bucketMs: 100, coveredFromMs: T0, coveredToMs: T0 + 1000, notObserved: [], loss: NO_LOSS, series, ...extra });
  return h;
}

const opts = { filter: 'dns', bufferLimit: 100, timeZone: 'UTC' };

describe('drillDown', () => {
  it("returns the agent's on-time and late counts for the interval, at any interval", () => {
    const h = history();
    ingestBuckets(h, { revision: 1, epoch: 'aaaabbbb', bucketMs: 100, coveredFromMs: T0 + 1000, coveredToMs: T0 + 1000, notObserved: [], loss: NO_LOSS,
      series: [{ id: 'dns', late: 0, lateBuckets: [[T0 + 100, 3, 300]], buckets: [] }] });
    expect(drillDown(h, 'dns', 1000, T0 + 400)).toMatchObject({ fromMs: T0, toMs: T0 + 1000, onTime: 42, late: 3, state: 'value', lossy: false, unplacedLate: 0 });
    expect(drillDown(h, 'dns', 100, T0)).toMatchObject({ fromMs: T0, toMs: T0 + 100, onTime: 40, late: 0 });
    expect(drillDown(h, 'nope', 1000, T0)).toBeNull();
  });
});

describe('describeDrill: the header is computed, never assumed', () => {
  it('all available', () => {
    const d = describeDrill(drillDown(history(), 'dns', 1000, T0)!, 42, opts);
    expect(d.headline).toBe('All 42 packets in 06:40:00.000–06:40:01.000 matching `dns` are available here.');
  });

  it('partial: names the rate limit and the buffer, and the external-analyzer path, never replay', () => {
    const d = describeDrill(drillDown(history(), 'dns', 1000, T0)!, 12, opts);
    expect(d.headline).toBe('12 of 42 packets in 06:40:00.000–06:40:01.000 matching `dns` are available here.');
    const text = [d.headline, ...d.detail].join(' ');
    expect(text).toContain('The other 30 were counted by the agent but not sent to the browser (rate-limited to 100 packet events/s) or have aged out of the 100-packet buffer.');
    expect(text).toContain('record a capture file (`capture <file.pcapng>`) and open it in an external analyzer at this time range');
    expect(text).not.toMatch(/replay/i);
  });

  it('late frames attributed to the interval count toward N, and are said so', () => {
    const h = history();
    ingestBuckets(h, { revision: 1, epoch: 'aaaabbbb', bucketMs: 100, coveredFromMs: T0 + 1000, coveredToMs: T0 + 1000, notObserved: [], loss: NO_LOSS,
      series: [{ id: 'dns', late: 0, lateBuckets: [[T0 + 100, 3, 300]], buckets: [] }] });
    const d = describeDrill(drillDown(h, 'dns', 1000, T0)!, 45, opts); // k <= on-time + late
    expect(d.headline).toBe('All 45 packets in 06:40:00.000–06:40:01.000 matching `dns` are available here.');
    expect(d.detail.join(' ')).toContain('45 includes 3 late frames');
  });

  it('k is never clamped: more packets than the agent attributed says the count is incomplete (late frames)', () => {
    const h = history({}, [{ id: 'dns', late: 4, lateBuckets: [], buckets: [[T0, 2, 200]] }]); // 4 late frames overflowed into the scalar
    const d = describeDrill(drillDown(h, 'dns', 1000, T0)!, 6, opts);
    expect(d.headline).toBe("6 packets in 06:40:00.000–06:40:01.000 matching `dns` are available here; the agent's count for this interval is incomplete (late frames).");
    expect(d.headline).not.toMatch(/of 2/);
  });

  it('a not-observed interval says so', () => {
    const h = history({ notObserved: [{ fromMs: T0 + 200, toMs: T0 + 700, reason: 'interface_switch' }] });
    const d = describeDrill(drillDown(h, 'dns', 1000, T0)!, 0, opts);
    expect(d.detail.join(' ')).toContain('Not observed for 500 ms of this 1 s interval (interface switch)');
  });

  it('an interval the tab holds no count for gives k without a total', () => {
    const d = describeDrill(drillDown(history(), 'dns', 1000, T0 + 5000)!, 3, opts);
    expect(d.headline).toBe('3 packets in 06:40:05.000–06:40:06.000 matching `dns` are available here.');
    expect(d.detail.join(' ')).toContain("This tab holds no agent count for this interval");
  });

  it('loss in the interval is stated, and an empty filter reads as every frame', () => {
    const h = history({ loss: { ...NO_LOSS, kernelDropped: 5 } });
    const d = describeDrill(drillDown(h, 'dns', 1000, T0)!, 42, { ...opts, filter: '' });
    expect(d.headline).toBe('All 42 packets in 06:40:00.000–06:40:01.000 (every frame) are available here.');
    expect(d.detail.join(' ')).toContain('Frames were lost before counting');
  });

  it('no packets counted and none buffered', () => {
    const h = history({}, [{ id: 'dns', late: 0, lateBuckets: [], buckets: [] }]);
    expect(describeDrill(drillDown(h, 'dns', 1000, T0)!, 0, opts).headline).toBe('The agent counted no packets in 06:40:00.000–06:40:01.000 matching `dns`.');
  });
});
