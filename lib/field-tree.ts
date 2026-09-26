import type { WireField } from './types';

export interface FieldTreeNode {
  field: WireField;
  children: FieldTreeNode[];
}

/** Build parent/child relationships without requiring parent-first wire order. */
export function buildFieldTree(fields: WireField[]): FieldTreeNode[] {
  const nodes = new Map<string, FieldTreeNode>();
  for (const field of fields) {
    nodes.set(field.path, { field, children: [] });
  }

  const roots: FieldTreeNode[] = [];
  for (const field of fields) {
    const node = nodes.get(field.path)!;
    const parent = field.group ? nodes.get(field.group) : undefined;
    if (parent) {
      parent.children.push(node);
    } else {
      roots.push(node);
    }
  }
  return roots;
}

/**
 * Finds the field a hex-pane byte click should select. Sibling fields can
 * legitimately share a byte (a group and its leaf, or several bit flags in
 * one byte — see docs/wire-protocol.md), so this picks one deterministic
 * answer rather than a set: the covering field with the smallest byte
 * range, preferring a non-group leaf over an enclosing group, and the
 * first match in wire order when multiple leaves tie exactly.
 */
export function mostSpecificFieldAtOffset(fields: WireField[], index: number): WireField | null {
  const covering = fields.filter((f) => index >= f.offset && index < f.offset + f.len);
  if (covering.length === 0) return null;
  const leaves = covering.filter((f) => f.type !== 'group');
  const candidates = leaves.length > 0 ? leaves : covering;
  return candidates.reduce((best, f) => (f.len < best.len ? f : best));
}
