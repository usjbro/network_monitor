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
