'use client';

import React, { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { buildFieldTree, type FieldTreeNode } from '@/lib/field-tree';
import type { ThemeConfig, WireField } from '@/lib/types';

interface FieldTreeProps {
  fields: WireField[];
  theme: ThemeConfig;
  selectedPath: string | null;
  highlightedPaths: ReadonlySet<string>;
  onSelectField: (path: string | null) => void;
  onHoverField: (path: string | null) => void;
}

function formatValue(field: WireField): string | null {
  if (field.value === undefined) return null;
  if (typeof field.value === 'boolean') return field.value ? 'true' : 'false';
  return String(field.value);
}

function Row({ node, theme, selectedPath, highlightedPaths, onSelectField, onHoverField }: {
  node: FieldTreeNode;
  theme: ThemeConfig;
  selectedPath: string | null;
  highlightedPaths: ReadonlySet<string>;
  onSelectField: (path: string | null) => void;
  onHoverField: (path: string | null) => void;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const hasChildren = node.children.length > 0;
  const path = node.field.path;
  const isSelected = selectedPath === path;
  const highlighted = isSelected || highlightedPaths.has(path);
  const value = formatValue(node.field);

  return (
    <div>
      <div
        data-field-path={path}
        data-highlighted={highlighted ? 'true' : undefined}
        onClick={() => onSelectField(isSelected ? null : path)}
        onMouseEnter={() => onHoverField(path)}
        onMouseLeave={() => onHoverField(null)}
        className={`flex items-center space-x-1.5 py-0.5 px-1 rounded cursor-pointer text-[11px] ${highlighted ? theme.highlight : 'hover:bg-slate-800/60'}`}
      >
        {hasChildren ? (
          <button
            type="button"
            aria-label={`${collapsed ? 'Expand' : 'Collapse'} ${node.field.label}`}
            aria-expanded={!collapsed}
            onClick={(event) => { event.stopPropagation(); setCollapsed(!collapsed); }}
            className="text-slate-500"
          >
            {collapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          </button>
        ) : <span className="w-3" />}
        <span className="text-slate-300">{node.field.label}</span>
        {value !== null && <span className="text-emerald-400 font-mono">{value}</span>}
      </div>
      {hasChildren && !collapsed && (
        // A static Tailwind class, not a computed `style={{ paddingLeft }}` --
        // this app's CSP is `style-src 'self'` with no 'unsafe-inline' or
        // nonce carve-out for style attributes, so an inline style here would
        // be silently dropped by the browser, flattening the tree's nesting.
        // Indentation instead compounds through this wrapper's own DOM
        // nesting, one level per recursive call.
        <div className="pl-3.5">
          {node.children.map((child) => (
            <Row key={child.field.path} node={child} theme={theme}
              selectedPath={selectedPath} highlightedPaths={highlightedPaths}
              onSelectField={onSelectField} onHoverField={onHoverField} />
          ))}
        </div>
      )}
    </div>
  );
}

export const FieldTree: React.FC<FieldTreeProps> = ({ fields, theme, selectedPath, highlightedPaths, onSelectField, onHoverField }) => {
  const roots = buildFieldTree(fields);
  if (roots.length === 0) return null;
  return (
    <div className="space-y-0.5">
      {roots.map((node) => (
        <Row key={node.field.path} node={node} theme={theme}
          selectedPath={selectedPath} highlightedPaths={highlightedPaths}
          onSelectField={onSelectField} onHoverField={onHoverField} />
      ))}
    </div>
  );
};
