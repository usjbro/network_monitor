// JAM-18: the shared display-filter conformance corpus. The same file is run
// by capture-agent/tests/display_filter_conformance.rs against the Rust port,
// so the two implementations cannot drift apart silently. A failure here
// means the corpus is wrong or the TypeScript filter has a bug; never "fix" a
// case by editing it to match one side without checking the other.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { compileDisplayFilter } from '../display-filter';
import type { PacketFrame, WireField } from '../types';

type CorpusField = { path: string; type: WireField['type']; value?: WireField['value'] };
type CorpusCase = {
  name: string;
  filter: string;
  expect: boolean | { error: { message: string; token: string; position: number } };
};
type Corpus = { frameLen: number; fields: CorpusField[]; cases: CorpusCase[] };

const corpus: Corpus = JSON.parse(
  readFileSync(join(__dirname, '..', '..', 'testdata', 'display-filter-conformance.json'), 'utf8'),
);

const packet: PacketFrame = {
  id: 'p', timestamp: '', relativeTimeMs: 0, layer: 4, protocol: 'TCP', src: '', dst: '',
  length: corpus.frameLen, summary: '', hexDump: '', headerHexDump: '',
  fields: corpus.fields.map(f => ({ ...f, label: f.path, region: 'header', offset: 0, len: 0 })),
};

describe('display-filter conformance corpus (TypeScript)', () => {
  it('has cases', () => {
    expect(corpus.cases.length).toBeGreaterThan(100);
  });
  for (const c of corpus.cases) {
    it(c.name, () => {
      const result = compileDisplayFilter(c.filter);
      if (typeof c.expect === 'boolean') {
        if (!result.ok) throw new Error(`unexpected error: ${JSON.stringify(result.error)}`);
        expect(result.predicate({ kind: 'packet', packet })).toBe(c.expect);
      } else {
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.error).toEqual(c.expect.error);
      }
    });
  }
});
