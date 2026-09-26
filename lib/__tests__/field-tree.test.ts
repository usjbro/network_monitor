import { describe, expect, it } from 'vitest';
import { buildFieldTree, mostSpecificFieldAtOffset } from '@/lib/field-tree';
import type { WireField } from '@/lib/types';

function field(overrides: Partial<WireField> & Pick<WireField, 'path' | 'label' | 'type'>): WireField {
  return { region: 'header', offset: 0, len: 1, ...overrides };
}

describe('buildFieldTree', () => {
  it('nests a leaf under its group', () => {
    const tree = buildFieldTree([
      field({ path: 'tcp', label: 'TCP', type: 'group' }),
      field({ path: 'tcp.src_port', label: 'Source Port', type: 'uint', group: 'tcp', value: 51000 }),
    ]);
    expect(tree).toHaveLength(1);
    expect(tree[0].field.path).toBe('tcp');
    expect(tree[0].children.map((node) => node.field.path)).toEqual(['tcp.src_port']);
  });

  it('nests multiple levels and handles children that precede their parent', () => {
    const tree = buildFieldTree([
      field({ path: 'tcp.flags.rst', label: 'RST', type: 'bool', group: 'tcp.flags', value: false }),
      field({ path: 'tcp', label: 'TCP', type: 'group' }),
      field({ path: 'tcp.flags', label: 'Flags', type: 'group', group: 'tcp' }),
      field({ path: 'tcp.flags.syn', label: 'SYN', type: 'bool', group: 'tcp.flags', value: true }),
    ]);
    expect(tree.map((node) => node.field.path)).toEqual(['tcp']);
    expect(tree[0].children.map((node) => node.field.path)).toEqual(['tcp.flags']);
    expect(tree[0].children[0].children.map((node) => node.field.path)).toEqual([
      'tcp.flags.rst',
      'tcp.flags.syn',
    ]);
  });

  it('preserves root order and promotes a field with an unknown parent', () => {
    const tree = buildFieldTree([
      field({ path: 'eth', label: 'Ethernet', type: 'group' }),
      field({ path: 'ip', label: 'IP', type: 'group' }),
      field({ path: 'orphan', label: 'Orphan', type: 'str', group: 'missing', value: 'x' }),
    ]);
    expect(tree.map((node) => node.field.path)).toEqual(['eth', 'ip', 'orphan']);
  });

  it('returns an empty tree for an empty field list', () => {
    expect(buildFieldTree([])).toEqual([]);
  });
});

describe('mostSpecificFieldAtOffset', () => {
  const tcp = field({ path: 'tcp', label: 'TCP', type: 'group', offset: 8, len: 6 });
  const flags = field({ path: 'tcp.flags', label: 'Flags', type: 'group', group: 'tcp', offset: 13, len: 1 });
  const syn = field({ path: 'tcp.flags.syn', label: 'SYN', type: 'bool', group: 'tcp.flags', value: true, offset: 13, len: 1 });
  const ack = field({ path: 'tcp.flags.ack', label: 'ACK', type: 'bool', group: 'tcp.flags', value: false, offset: 13, len: 1 });
  const srcPort = field({ path: 'tcp.src_port', label: 'Source Port', type: 'uint', group: 'tcp', value: 51000, offset: 8, len: 2 });
  const fields = [tcp, flags, syn, ack, srcPort];

  it('prefers a non-group leaf over an enclosing group', () => {
    expect(mostSpecificFieldAtOffset(fields, 8)?.path).toBe('tcp.src_port');
  });

  it('picks the first leaf in field order when multiple leaves share a byte', () => {
    expect(mostSpecificFieldAtOffset(fields, 13)?.path).toBe('tcp.flags.syn');
  });

  it('falls back to the smallest enclosing group when no leaf covers the byte', () => {
    expect(mostSpecificFieldAtOffset([tcp], 13)?.path).toBe('tcp');
  });

  it('returns null when no field covers the byte', () => {
    expect(mostSpecificFieldAtOffset(fields, 0)).toBeNull();
  });
});
