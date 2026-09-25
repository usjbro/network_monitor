import { describe, expect, it } from 'vitest';
import { buildFieldTree } from '@/lib/field-tree';
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
