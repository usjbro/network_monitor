'use client';

import React from 'react';
import type { Finding, ThemeConfig } from '@/lib/types';

export type FindingNavigateTarget = { kind: 'frame'; id: string } | { kind: 'flow'; id: string };

interface FindingsPanelProps {
  findings: Finding[];
  theme: ThemeConfig;
  onNavigate: (target: FindingNavigateTarget) => void;
}

const SEVERITY_CLASS: Record<Finding['severity'], string> = {
  error: 'bg-rose-950 text-rose-400 border-rose-800/60',
  warning: 'bg-amber-950 text-amber-400 border-amber-800/60',
  note: 'bg-slate-800 text-slate-300 border-slate-700',
  chat: 'bg-slate-900 text-slate-500 border-slate-800',
};

// The finding's navigation target, if any — a malformed-frame finding has
// neither a frameId nor a flowId, since parse_packet failing means no
// packet or flow was ever produced for it (see docs/wire-protocol.md's
// `finding` section). Not a bug to fix later: there is nothing to navigate
// to for that one code.
function targetFor(finding: Finding): FindingNavigateTarget | null {
  if (finding.frameId) return { kind: 'frame', id: finding.frameId };
  if (finding.flowId) return { kind: 'flow', id: finding.flowId };
  return null;
}

function FindingRow({ finding, theme, onNavigate }: { finding: Finding; theme: ThemeConfig; onNavigate: (target: FindingNavigateTarget) => void }) {
  const target = targetFor(finding);
  const badge = (
    <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold border whitespace-nowrap ${SEVERITY_CLASS[finding.severity]}`}>
      {finding.severity.toUpperCase()}
    </span>
  );
  const content = (
    <>
      {badge}
      <span className="flex-1 text-left text-slate-200">{finding.summary}</span>
    </>
  );
  if (!target) {
    return (
      <div className="flex items-center space-x-2 p-2 text-[11px]">
        {content}
      </div>
    );
  }
  return (
    <button
      type="button"
      onClick={() => onNavigate(target)}
      className={`flex items-center space-x-2 p-2 w-full text-[11px] hover:bg-slate-900/90 transition cursor-pointer ${theme.border}`}
    >
      {content}
    </button>
  );
}

export const FindingsPanel: React.FC<FindingsPanelProps> = ({ findings, theme, onNavigate }) => {
  if (findings.length === 0) {
    return (
      <div className="p-8 text-center text-slate-500 text-xs">
        No findings observed yet.
      </div>
    );
  }

  const byCode = new Map<Finding['code'], Finding[]>();
  for (const finding of findings) {
    const group = byCode.get(finding.code) ?? [];
    group.push(finding);
    byCode.set(finding.code, group);
  }

  return (
    <div className="space-y-3 font-mono text-xs p-3">
      {Array.from(byCode.entries()).map(([code, group]) => (
        <div key={code} className={`rounded border ${theme.border} ${theme.cardBg} overflow-hidden`}>
          <div className="bg-slate-950 px-3 py-2 border-b border-slate-800 text-[10px] text-slate-400 font-bold">
            {code.toUpperCase()} ({group.length})
          </div>
          <div className="divide-y divide-slate-800/80">
            {group.map((finding) => (
              <FindingRow key={finding.id} finding={finding} theme={theme} onNavigate={onNavigate} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};
