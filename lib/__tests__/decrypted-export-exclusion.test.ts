// Decrypted TLS content must be structurally unreachable from export
// (JAM-147; spec Components §5, docs/security.md "Export crosses a narrower
// boundary than the live view").
//
// The real guarantee is a compile-time one: no function in lib/export.ts
// names DecryptedPayloadSegment in its signature, so a caller cannot even
// form the call. These tests are the runtime tripwires for the ways that
// guarantee could quietly erode later.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as exportModule from '../export';

describe('decrypted content is structurally unreachable from export', () => {
  it('exports exactly the closed set of functions, so a new one is a visible diff here', () => {
    // If someone adds an exporter later without thinking about decrypted
    // content, this fails and makes them come read this file.
    expect(Object.keys(exportModule).sort()).toEqual(['connectionsToCsv', 'downloadBlob', 'packetsToJson']);
  });

  it('never mentions DecryptedPayloadSegment anywhere in lib/export.ts', () => {
    // The structural half, asserted against the source itself: the type
    // cannot appear in a signature if it does not appear in the file. The
    // comment block naming it is excluded by checking only non-comment
    // lines, so the prose explaining the rule doesn't fail the rule.
    const source = readFileSync(join(__dirname, '..', 'export.ts'), 'utf8');
    const code = source
      .split('\n')
      .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
      .join('\n');
    expect(code).not.toContain('DecryptedPayloadSegment');
    expect(code).not.toContain('decryptedSegments');
  });

  it('connectionsToCsv cannot leak a decrypted field smuggled onto a connection object', () => {
    // Defence in depth against a future refactor widening
    // NetworkConnection to carry decrypted content: CSV_COLUMNS is a fixed
    // allowlist, not "every field on the object", so a new field cannot
    // become a new column for free.
    const conn = {
      id: 'c1',
      protocol: 'HTTPS/TLS',
      localAddr: '10.0.0.1',
      localPort: 51234,
      remoteAddr: '1.1.1.1',
      remotePort: 443,
      processName: 'test',
      pid: 1,
      rxBytesTotal: 0,
      txBytesTotal: 0,
      status: 'ESTABLISHED',
      decryptedPayload: 'THIS MUST NEVER APPEAR IN CSV OUTPUT',
    } as unknown as Parameters<typeof exportModule.connectionsToCsv>[0][number];

    const csv = exportModule.connectionsToCsv([conn], 1);

    expect(csv).not.toContain('THIS MUST NEVER APPEAR IN CSV OUTPUT');
    expect(csv).not.toContain('decryptedPayload');
  });

  // packetsToJson is deliberately pass-through — it is a JSON.stringify of
  // PacketFrame, so unlike connectionsToCsv it has no column allowlist and
  // WOULD serialize an extra field if one were smuggled onto a packet
  // object. Being honest about that asymmetry matters more than pretending
  // both exporters have the same shape of guarantee: for packets the
  // protection is that PacketFrame cannot carry decrypted content at all,
  // which the next test pins at the type level.
  it('PacketFrame itself declares no decrypted-content field', () => {
    const types = readFileSync(join(__dirname, '..', 'types.ts'), 'utf8');
    // Slice to the interface's own closing brace, not to the next
    // `export interface`: the comment block introducing
    // DecryptedPayloadSegment sits between them and legitimately uses the
    // word "decrypted", which would make this assertion fail on prose
    // rather than on a field.
    const start = types.indexOf('export interface PacketFrame {');
    const packetFrame = types.slice(start, types.indexOf('\n}', start) + 2);
    expect(packetFrame).not.toMatch(/decrypt/i);
    expect(packetFrame).not.toMatch(/plaintext/i);
    // Sanity check that the slice actually captured the interface, so this
    // can't pass by matching an empty string.
    expect(packetFrame).toContain('hexDump');
  });

  it('decrypted segments are a separate type from the packets the exporter takes', () => {
    // app/page.tsx holds `packets` and `decryptedSegments` in distinct
    // state, and only the former reaches packetsToJson. Passing a segment
    // is a compile error; this asserts the two types stayed distinct
    // rather than one being widened into the other.
    const types = readFileSync(join(__dirname, '..', 'types.ts'), 'utf8');
    expect(types).toContain('export interface DecryptedPayloadSegment');
    expect(types).toContain('export interface PacketFrame');
  });
});
