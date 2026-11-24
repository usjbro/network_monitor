// KAN-131 (design D3): the browser's copy of the agent's four rankings,
// computed only from fields on the wire. Order: rank value descending, then
// lastSeenMs descending, then array position, which is the agent's insertion
// order. Pinned against the agent by testdata/rollup-rank.jsonl.
import { Endpoint } from './types';

export type RollupRanking = 'bytes' | 'packets' | 'rate' | 'recent';

export type RankedRow = Pick<
  Endpoint,
  'rxBytesTotal' | 'txBytesTotal' | 'rxPacketsTotal' | 'txPacketsTotal' | 'rxSpeed' | 'txSpeed' | 'lastSeenMs'
>;

export function rankValue(row: RankedRow, ranking: RollupRanking): number {
  switch (ranking) {
    case 'bytes':
      return row.rxBytesTotal + row.txBytesTotal;
    case 'packets':
      return row.rxPacketsTotal + row.txPacketsTotal;
    case 'rate':
      return row.rxSpeed + row.txSpeed;
    case 'recent':
      return row.lastSeenMs;
  }
}

export function rankRows<T extends RankedRow>(rows: readonly T[], ranking: RollupRanking): T[] {
  // Array.prototype.sort is stable, so full ties keep their array position.
  // Two infinite sums subtract to NaN, which counts as a tie.
  return [...rows].sort((a, b) => rankValue(b, ranking) - rankValue(a, ranking) || b.lastSeenMs - a.lastSeenMs);
}
