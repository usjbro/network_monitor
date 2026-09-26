'use client';

import React, { useRef, useState } from 'react';
import { ChevronDown, ChevronRight, Copy } from 'lucide-react';
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

// Copy affordance (JAM-11 scope item 4): abbreviation doubles as JAM-10
// filter syntax, so this is how a user discovers that grammar from the
// tree. `navigator.clipboard` is absent on a non-secure origin other than
// localhost, so failure is shown rather than silently doing nothing.
function CopyButton({ label, text }: { label: string; text: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  // A rapid second click must restart the reset window, not race the
  // first click's own — without clearing it, the first click's timer
  // still fires on schedule and reverts the second click's fresh
  // indicator back to idle early.
  const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={async (event) => {
        event.stopPropagation();
        if (resetTimer.current !== null) clearTimeout(resetTimer.current);
        try {
          await navigator.clipboard.writeText(text);
          setState('copied');
        } catch {
          setState('failed');
        }
        resetTimer.current = setTimeout(() => setState('idle'), 1500);
      }}
      className={`shrink-0 ${state === 'failed' ? 'text-rose-400' : state === 'copied' ? 'text-emerald-400' : 'text-slate-600 hover:text-emerald-400'}`}
    >
      <Copy className="h-2.5 w-2.5" />
    </button>
  );
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
        <span className="flex-1" />
        <CopyButton label={`Copy abbreviation for ${node.field.label}`} text={path} />
        {value !== null && <CopyButton label={`Copy value for ${node.field.label}`} text={value} />}
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
