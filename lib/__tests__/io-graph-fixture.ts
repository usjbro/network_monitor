// A seeded IO graph history covering every point state (KAN-315): gaps,
// not-observed time, late frames, loss, aggregates and a wrapped ring.
import { createHash } from 'node:crypto';
import { createHistory, ingestBuckets, ingestStatus, type IoHistory } from '../io-graph';
import type { IoBucket, IoSeriesStatus } from '../types';

export const MIXED_T0 = 1_794_120_000_000;
export const MIXED_END = MIXED_T0 + 1_000_000;

export const mixedStatus: IoSeriesStatus = {
  revision: 3,
  epoch: 'aaaabbbb',
  replayWaiting: false,
  series: [
    { id: 'all', filter: '', ok: true },
    { id: 'dns', filter: 'dns', ok: true },
    { id: 'win', filter: 'tcp', ok: true, aggregate: { fn: 'avg', field: 'tcp.window_size' } },
  ],
};

export function mixedHistory(): IoHistory {
  let seed = 315;
  const rnd = (n: number) => {
    seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
    return Math.floor((seed / 2_147_483_648) * n);
  };
  const h = createHistory();
  ingestStatus(h, mixedStatus);
  for (let from = MIXED_T0; from < MIXED_END; from += 1000) {
    if (rnd(12) === 0) continue; // unknown: never covered
    const starts = Array.from({ length: 10 }, (_, i) => from + i * 100);
    const buckets = (): IoBucket[] => starts.filter(() => rnd(4) > 0).map((s) => [s, rnd(50), rnd(60_000)]);
    const win: IoBucket[] = starts.filter(() => rnd(3) > 0).map((s) => {
      const n = rnd(4);
      const lo = rnd(1000);
      return n === 0 ? [s, 1, 60, 0, 0, null, null] : [s, n, n * 60, n, n * (lo + 50), lo, lo + 100];
    });
    ingestBuckets(h, {
      revision: 3, epoch: 'aaaabbbb', bucketMs: 100, coveredFromMs: from, coveredToMs: from + 1000,
      notObserved: rnd(9) === 0 ? [{ fromMs: from + 200, toMs: from + 500, reason: rnd(2) ? 'backlog' : 'interface_switch' }] : [],
      loss: { kernelDropped: rnd(15) === 0 ? 1 : 0, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 },
      series: [
        { id: 'all', late: rnd(20) === 0 ? 2 : 0, lateBuckets: rnd(10) === 0 ? [[from - 700, 1, 60]] : [], buckets: buckets() },
        { id: 'dns', late: 0, lateBuckets: [], buckets: buckets() },
        { id: 'win', late: 0, lateBuckets: [], buckets: win },
      ],
    });
  }
  return h;
}

/** A digest that keeps undefined and non-finite values distinct. */
export function digest(value: unknown): string {
  const text = JSON.stringify(value, (_k, v) => (v === undefined || (typeof v === 'number' && !Number.isFinite(v)) ? `<${String(v)}>` : v));
  return createHash('sha256').update(text).digest('hex').slice(0, 16);
}
