// KAN-131: the browser's ranking against the agent's. testdata/rollup-rank.jsonl
// is written by capture-agent/tests/rollup_rank_fixture.rs through the real
// encoder; `expected` is a full sort of every retained key, of which the event
// carries only the union of the four top N.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { mapConversationRollupEvent, mapEndpointRollupEvent } from '../agent-mapping';
import { rankRows, RollupRanking } from '../rollup-rank';
import { Conversation, Endpoint } from '../types';

interface FixtureLine {
  event: { type: string } & Record<string, unknown>;
  expected: Record<RollupRanking, string[]>;
  topN: number;
}

const lines: FixtureLine[] = readFileSync(join(__dirname, '..', '..', 'testdata', 'rollup-rank.jsonl'), 'utf8')
  .split('\n')
  .filter((l) => l.trim().length > 0)
  .map((l) => JSON.parse(l) as FixtureLine);

const RANKINGS: RollupRanking[] = ['bytes', 'packets', 'rate', 'recent'];

function rows(line: FixtureLine): (Endpoint | Conversation)[] {
  return line.event.type === 'endpoint_rollup'
    ? mapEndpointRollupEvent(line.event).rows
    : mapConversationRollupEvent(line.event).rows;
}

const key = (row: Endpoint | Conversation) => ('host' in row ? row.host : `${row.localAddr}|${row.remoteAddr}`);

describe('rankRows reproduces the agent top N', () => {
  it('the fixture has lines of both types', () => {
    expect([...new Set(lines.map((l) => l.event.type))].sort()).toEqual(['conversation_rollup', 'endpoint_rollup']);
  });

  lines.forEach((line, i) => {
    it.each(RANKINGS)(`line ${i + 1} (${line.event.type}, top ${line.topN}) by %s`, (ranking) => {
      expect(line.expected[ranking].length).toBeGreaterThan(0);
      expect(rankRows(rows(line), ranking).slice(0, line.topN).map(key)).toEqual(line.expected[ranking]);
    });
  });
});

describe('rankRows', () => {
  const row = (id: string, overrides: Partial<Endpoint> = {}) => ({
    id, rxBytesTotal: 0, txBytesTotal: 0, rxPacketsTotal: 0, txPacketsTotal: 0,
    rxSpeed: 0, txSpeed: 0, lastSeenMs: 0, ...overrides,
  });
  const ids = (ranked: { id: string }[]) => ranked.map((r) => r.id);

  it('sums both directions', () => {
    const input = [
      row('rx', { rxBytesTotal: 5, rxPacketsTotal: 5, rxSpeed: 5 }),
      row('both', { rxBytesTotal: 3, txBytesTotal: 3, rxPacketsTotal: 3, txPacketsTotal: 3, rxSpeed: 3, txSpeed: 3 }),
    ];
    for (const ranking of ['bytes', 'packets', 'rate'] as const) expect(ids(rankRows(input, ranking))).toEqual(['both', 'rx']);
  });

  it('breaks ties by lastSeenMs, then array position', () => {
    const input = [row('old', { lastSeenMs: 1 }), row('z', { lastSeenMs: 2 }), row('a', { lastSeenMs: 2 })];
    for (const ranking of RANKINGS) expect(ids(rankRows(input, ranking))).toEqual(['z', 'a', 'old']);
  });

  it('leaves the input unchanged', () => {
    const input = [row('a'), row('b', { rxBytesTotal: 1 })];
    expect(ids(rankRows(input, 'bytes'))).toEqual(['b', 'a']);
    expect(ids(input)).toEqual(['a', 'b']);
  });

  it('keeps every row when sums overflow to infinity', () => {
    const huge = { rxSpeed: Number.MAX_VALUE, txSpeed: Number.MAX_VALUE };
    const input = [row('small', { rxSpeed: 1 }), row('a', huge), row('b', huge)];
    expect(ids(rankRows(input, 'rate'))).toEqual(['a', 'b', 'small']);
  });
});
