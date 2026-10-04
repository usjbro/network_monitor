'use client';

import React from 'react';
import { Timer } from 'lucide-react';
import type { ServiceTimeSummary, ThemeConfig } from '@/lib/types';
import { formatServiceTime } from '@/lib/service-time';

interface ServiceTimeViewProps {
  // null until the agent's first service_time_update tick — shown as "not
  // measured yet", never as a table of zeros.
  summaries: ServiceTimeSummary[] | null;
  theme: ThemeConfig;
}

function timing(us: number | undefined): string {
  return us === undefined ? '—' : formatServiceTime(us);
}

// JAM-15: per-protocol service response time — how long a DNS query or an
// HTTP/1.x request waited for its answer, measured at this capture point.
export const ServiceTimeView: React.FC<ServiceTimeViewProps> = ({ summaries, theme }) => {
  return (
    <div className={`rounded border ${theme.border} ${theme.cardBg} p-3 font-mono text-xs space-y-2`}>
      <div className="flex items-center space-x-2 text-slate-300 font-bold text-[11px]">
        <Timer className="h-3.5 w-3.5" />
        <span>SERVICE RESPONSE TIME</span>
      </div>
      {summaries === null ? (
        <div className="text-slate-500 text-[11px]">Not measured yet: waiting for the agent&apos;s first update.</div>
      ) : (
        <>
          <table className="w-full text-[11px]">
            <thead className="text-slate-500 text-[10px]">
              <tr>
                <th className="text-left font-normal">Protocol</th>
                <th className="text-right font-normal">Answered</th>
                <th className="text-right font-normal">Unanswered</th>
                <th className="text-right font-normal">Untracked</th>
                <th className="text-right font-normal">Min</th>
                <th className="text-right font-normal">Median</th>
                <th className="text-right font-normal">p95</th>
                <th className="text-right font-normal">Max</th>
              </tr>
            </thead>
            <tbody className="text-slate-200">
              {summaries.map((s) => (
                <tr key={s.protocol} aria-label={s.protocol}>
                  <td className="text-left text-emerald-400">{s.protocol}</td>
                  <td className="text-right">{s.answered}</td>
                  <td className={`text-right ${s.unanswered > 0 ? 'text-amber-400' : ''}`}>{s.unanswered}</td>
                  <td className="text-right">{s.untracked}</td>
                  <td className="text-right">{timing(s.minUs)}</td>
                  <td className="text-right">{timing(s.medianUs)}</td>
                  <td className="text-right">{timing(s.p95Us)}</td>
                  <td className="text-right">{timing(s.maxUs)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="text-[10px] text-slate-500 space-y-0.5">
            {summaries.filter((s) => s.sampleCount > 0).map((s) => (
              <div key={s.protocol}>
                Median and p95 over the most recent {s.sampleCount} {s.protocol} {s.sampleCount === 1 ? 'response' : 'responses'}; counts, min and max over the whole capture.
              </div>
            ))}
            <div>
              Time from request to response as seen at this capture point: server time plus one network round trip.
              Unanswered: no response within 5 s (DNS) or 30 s (HTTP). Untracked: requests past the agent&apos;s matching bounds.
            </div>
          </div>
        </>
      )}
    </div>
  );
};
