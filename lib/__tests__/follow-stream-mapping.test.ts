// KAN-110 Task 3b: the `stream_data` mapper (docs/wire-protocol.md
// "stream_data"). The fixture is not hand-written: every line is what
// capture-agent/src/follow_response.rs encodes, and its
// `the_typescript_fixture_is_what_the_encoder_writes` test fails if the
// two ever differ (the JAM-150 lesson; see agent-wire-contract.test.ts).
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { mapStreamData } from '../agent-mapping';
import { FOLLOW_LIMITS } from '../types';

const ROOT = path.join(__dirname, '..', '..');
const lines: Record<string, unknown>[] = readFileSync(path.join(__dirname, 'fixtures', 'stream-data-samples.jsonl'), 'utf8')
  .trim()
  .split('\n')
  .map((l) => JSON.parse(l));
const [found, continued, disabled, mismatch, notFound, stale, busy] = lines;

function bytes(b64: string): string {
  return Buffer.from(b64, 'base64').toString('latin1');
}

// A deep copy of the found line with `edit` applied.
function edited(edit: (w: any) => void): unknown {
  const w = structuredClone(found);
  edit(w);
  return w;
}

describe('stream_data fixture from the real encoder', () => {
  it('maps a found page with masked bytes, gaps, ranges and turns', () => {
    const r = mapStreamData(found);
    expect(r).toMatchObject({ enabled: true, found: true, stale: false, generation: '000000000000feed:1', clientIsLocal: true, turnsNext: null });
    const c2s = r.directions.clientToServer;
    expect(c2s.classification).toBe('cleartext');
    expect(bytes(c2s.dataBase64)).toContain('Authorization: ****');
    expect(bytes(c2s.dataBase64)).not.toContain('s3cr3t');
    expect(bytes(c2s.dataBase64)).toHaveLength(c2s.nextOffset - c2s.offset);
    expect(c2s.gaps).toEqual([{ at: 63, missing: 10, reason: 'missing' }]);
    expect(c2s.redactedRanges.map((m) => m.reason)).toEqual(['credential', 'uncertain']);
    expect(r.turns.map((t) => t.dir)).toEqual(['c2s', 's2c', 'c2s', 's2c']);
    expect(r.lastTurn).toEqual({ index: 3, ...r.turns[3] });
  });

  it('maps a continuation page from an offset and a turn index', () => {
    const r = mapStreamData(continued);
    expect(r.directions.clientToServer.offset).toBe(16);
    expect(r.turnsFrom).toBe(1);
    expect(r.turns).toHaveLength(3);
    expect(r.lastTurn?.index).toBe(3);
  });

  it('maps every content-free reply without bytes', () => {
    expect(mapStreamData(disabled)).toMatchObject({ enabled: false, found: false, generation: null });
    expect(mapStreamData(mismatch)).toMatchObject({ enabled: true, found: false, unavailable: 'relay_port_mismatch' });
    expect(mapStreamData(notFound)).toMatchObject({ enabled: true, found: false, generation: null });
    expect(mapStreamData(stale)).toMatchObject({ found: true, stale: true, generation: '000000000000feed:1' });
    expect(mapStreamData(busy)).toMatchObject({ busy: true, found: false });
    for (const line of [disabled, mismatch, notFound, stale, busy]) {
      const r = mapStreamData(line);
      expect(r.directions.clientToServer.dataBase64).toBe('');
      expect(r.directions.serverToClient.dataBase64).toBe('');
      expect(r.turns).toEqual([]);
      expect(r.lastTurn).toBeNull();
    }
  });
});

describe('stream_data tolerance', () => {
  it('maps unknown enum values to unknown and ignores unknown fields', () => {
    const r = mapStreamData(
      edited((w) => {
        w.newField = { anything: true };
        w.unavailable = 'some_future_reason';
        const c2s = w.directions.clientToServer;
        c2s.classification = 'quic';
        c2s.stoppedReason = 'new_limit';
        c2s.gaps[0].reason = 'new_reason';
        c2s.redactedRanges[0].reason = 'new_reason';
        w.turns[0].dir = 'sideways';
        w.lastTurn.dir = 'sideways';
      }),
    );
    expect(r.unavailable).toBe('unknown');
    expect(r.directions.clientToServer.classification).toBe('unknown');
    expect(r.directions.clientToServer.stoppedReason).toBe('unknown');
    expect(r.directions.clientToServer.gaps[0].reason).toBe('unknown');
    expect(r.directions.clientToServer.redactedRanges[0].reason).toBe('unknown');
    expect(r.turns[0].dir).toBe('unknown');
    expect(r.lastTurn?.dir).toBe('unknown');
    expect(r).not.toHaveProperty('newField');
  });

  it('saturates u64 counters above MAX_SAFE_INTEGER', () => {
    const r = mapStreamData(
      edited((w) => {
        w.directions.clientToServer.seenBytes = 2 ** 60;
        w.directions.clientToServer.conflictingOverlapBytes = 2 ** 64;
        w.turns[0].firstSeenMs = 2 ** 63;
      }),
    );
    expect(r.directions.clientToServer.seenBytes).toBe(Number.MAX_SAFE_INTEGER);
    expect(r.directions.clientToServer.conflictingOverlapBytes).toBe(Number.MAX_SAFE_INTEGER);
    expect(r.turns[0].firstSeenMs).toBe(Number.MAX_SAFE_INTEGER);
  });
});

describe('stream_data strictness', () => {
  const page = (w: any) => w.directions.clientToServer;
  const cases: [string, (w: any) => void][] = [
    ['wrong type', (w) => (w.type = 'tcp_samples')],
    ['uppercase requestId', (w) => (w.requestId = w.requestId.toUpperCase())],
    ['short requestId', (w) => (w.requestId = 'abc')],
    ['long connectionId', (w) => (w.connectionId = 'x'.repeat(FOLLOW_LIMITS.connectionIdBytes + 1))],
    ['connectionId over its bytes, not its characters', (w) => (w.connectionId = '€'.repeat(43))],
    ['gap at the end of a non-empty page', (w) => (w.directions.clientToServer.gaps[0].at = w.directions.clientToServer.nextOffset)],
    ['range past the page', (w) => (w.directions.clientToServer.redactedRanges[1].len = 5)],
    ['non-canonical generation', (w) => (w.generation = '000000000000feed:01')],
    ['generation as number', (w) => (w.generation = 1)],
    ['string boolean', (w) => (w.found = 'true')],
    ['clientIsLocal string', (w) => (w.clientIsLocal = 'yes')],
    ['offset past the direction cap', (w) => (page(w).offset = FOLLOW_LIMITS.directionBytes + 1)],
    ['nextOffset before offset', (w) => (page(w).nextOffset = -1)],
    ['fractional offset', (w) => (page(w).storedBytes = 1.5)],
    ['string number', (w) => (page(w).storedBytes = '67')],
    ['data shorter than its span', (w) => (page(w).nextOffset -= 1)],
    ['data not base64', (w) => (page(w).dataBase64 = 'not base64!')],
    ['data over a page', (w) => (page(w).dataBase64 = 'A'.repeat(Math.ceil(FOLLOW_LIMITS.pageBytes / 3) * 4 + 4))],
    ['too many gaps', (w) => (page(w).gaps = Array(FOLLOW_LIMITS.pageGaps + 1).fill(page(w).gaps[0]))],
    ['too many ranges', (w) => (page(w).redactedRanges = Array(FOLLOW_LIMITS.pageRanges + 1).fill(page(w).redactedRanges[0]))],
    ['zero-length range', (w) => (page(w).redactedRanges[0].len = 0)],
    ['range past the cap', (w) => (page(w).redactedRanges[0].len = FOLLOW_LIMITS.directionBytes)],
    ['negative counter', (w) => (page(w).seenBytes = -1)],
    ['too many turns', (w) => (w.turns = Array(FOLLOW_LIMITS.pageTurns + 1).fill(w.turns[0]))],
    ['turnsNext not after this page', (w) => (w.turnsNext = 2)],
    ['turnsFrom past the flow cap', (w) => (w.turnsFrom = FOLLOW_LIMITS.flowTurns + 1)],
    ['lastTurn index past the cap', (w) => (w.lastTurn.index = FOLLOW_LIMITS.flowTurns)],
    ['directions missing', (w) => delete w.directions],
    ['busy string', (w) => (w.busy = 'yes')],
  ];
  it.each(cases)('rejects %s', (_, edit) => {
    expect(() => mapStreamData(edited(edit))).toThrow(/malformed stream_data/);
  });

  it('rejects a gap or range before a page that starts past 0', () => {
    const page = (continued as any).directions.clientToServer;
    expect(page.offset).toBe(16);
    expect(() => mapStreamData(continued)).not.toThrow();
    const gapBefore = structuredClone(continued) as any;
    gapBefore.directions.clientToServer.gaps = [{ at: 15, missing: 1, reason: 'missing' }];
    expect(() => mapStreamData(gapBefore)).toThrow(/gaps\[0\]: outside the page/);
    const rangeBefore = structuredClone(continued) as any;
    rangeBefore.directions.clientToServer.redactedRanges = [{ start: 15, len: 2, reason: 'credential' }];
    expect(() => mapStreamData(rangeBefore)).toThrow(/redactedRanges\[0\]: outside the page/);
  });

  it('never echoes captured bytes in its error', () => {
    try {
      mapStreamData(edited((w) => (w.directions.clientToServer.dataBase64 += '=')));
      expect.unreachable();
    } catch (e) {
      expect(String(e)).not.toContain('R0VU');
    }
  });
});

describe('Rust and TypeScript limits agree', () => {
  const rust = (file: string, name: string): number => {
    const src = readFileSync(path.join(ROOT, 'capture-agent', 'src', file), 'utf8');
    const m = src.match(new RegExp(`pub const ${name}: \\w+ = ([0-9_ *]+);`));
    if (!m) throw new Error(`${name} not found in ${file}`);
    return m[1].split('*').reduce((acc, n) => acc * Number(n.trim().replace(/_/g, '')), 1);
  };

  it('matches every limit the mapper enforces', () => {
    expect(FOLLOW_LIMITS).toEqual({
      lineBytes: rust('follow_response.rs', 'MAX_STREAM_DATA_LINE_BYTES'),
      directionBytes: rust('follow.rs', 'MAX_DIRECTION_BYTES'),
      pageBytes: rust('follow_response.rs', 'PAGE_DATA_BYTES'),
      pageGaps: rust('follow_response.rs', 'PAGE_GAPS'),
      pageRanges: rust('follow_response.rs', 'PAGE_RANGES'),
      pageTurns: rust('follow_response.rs', 'PAGE_TURNS'),
      flowTurns: rust('follow.rs', 'MAX_TURNS_PER_FLOW'),
      connectionIdBytes: rust('wire.rs', 'STREAM_MAX_CONNECTION_ID_BYTES'),
    });
  });

  it('keeps get_stream out of the generic control route', () => {
    expect(readFileSync(path.join(ROOT, 'app', 'api', 'control', 'route.ts'), 'utf8')).not.toContain('get_stream');
  });
});
