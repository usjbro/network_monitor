'use client';

// IO graph (JAM-18 Task 3): filter-defined series over a real time axis.
// Data comes from the agent's complete 100 ms bucket counts (io_buckets),
// held in lib/io-graph.ts. This component only renders and edits; the
// shared series set is changed by compare-and-swap against the latest
// io_series_status, never from a local copy.

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Activity } from 'lucide-react';
import type { IoSeriesStatus, ThemeConfig } from '@/lib/types';
import {
  IO_INTERVALS,
  allowedIntervals,
  finestAllowed,
  horizonText,
  latestCoveredMs,
  newRequestId,
  query,
  rate,
  ticks,
  type IoHistory,
  type IoInterval,
  type IoPoint,
  type Measure,
} from '@/lib/io-graph';

export type SetIoSeriesMessage = {
  type: 'set_io_series';
  baseEpoch: string;
  baseRevision: number;
  requestId: string;
  series: { id: string; filter: string }[];
};

interface IoGraphViewProps {
  history: IoHistory;
  /** history.version, passed so React re-renders when history changes. */
  version: number;
  status: IoSeriesStatus | null;
  connected: boolean;
  theme: ThemeConfig;
  /** POSTs a set_io_series; resolves false if the relay refused it. */
  onSend: (message: SetIoSeriesMessage) => Promise<boolean>;
  /** For tests: the clock used when there is no data yet. */
  now?: () => number;
  /** For tests: tick label time zone. */
  timeZone?: string;
}

const W = 1000;
const H = 260;
const M = { left: 64, right: 64, top: 12, bottom: 28 };
const PLOT_W = W - M.left - M.right;
const PLOT_H = H - M.top - M.bottom;
const MIN_SPAN = 2_000;
const MAX_SPAN = 7 * 86_400_000;
const DEFAULT_SPAN = 60_000;

// Series colours (layer colours from the rest of the UI), one per series slot.
const STROKES = [
  'stroke-emerald-400', 'stroke-sky-400', 'stroke-amber-400', 'stroke-fuchsia-400',
  'stroke-rose-400', 'stroke-lime-400', 'stroke-cyan-400', 'stroke-orange-400',
];
const SWATCHES = [
  'bg-emerald-400', 'bg-sky-400', 'bg-amber-400', 'bg-fuchsia-400',
  'bg-rose-400', 'bg-lime-400', 'bg-cyan-400', 'bg-orange-400',
];

const INTERVAL_LABEL: Record<IoInterval, string> = { 100: '100 ms', 1000: '1 s', 10000: '10 s', 60000: '1 min' };
const UNIT: Record<Measure, string> = { packets: 'pkt/s', bits: 'bit/s' };

export function formatSi(value: number): string {
  if (!Number.isFinite(value)) return '—';
  const abs = Math.abs(value);
  const units: [number, string][] = [[1e9, 'G'], [1e6, 'M'], [1e3, 'k']];
  for (const [scale, suffix] of units) {
    if (abs >= scale) return `${(value / scale).toFixed(abs / scale >= 100 ? 0 : 1)}${suffix}`;
  }
  return abs >= 100 || Number.isInteger(value) ? value.toFixed(0) : value.toFixed(1);
}

const REJECTION_TEXT: Record<string, string> = {
  conflict: 'Series changed in another tab: review the current set below and resend.',
  too_many_series: 'At most 8 series.',
  invalid_id: 'Series ids are 1–32 characters of a–z, 0–9 and "-".',
  duplicate_id: 'Series ids must be unique.',
  filter_too_long: 'A filter is longer than 2048 characters.',
  invalid_request_id: 'The request id was invalid.',
  invalid_epoch: 'The agent epoch was invalid.',
};

type DraftRow = { id: string; filter: string };

function draftFrom(status: IoSeriesStatus | null): DraftRow[] {
  return status ? status.series.map((s) => ({ id: s.id, filter: s.filter })) : [];
}

function nextId(rows: DraftRow[]): string {
  for (let i = 1; ; i++) if (!rows.some((r) => r.id === `s${i}`)) return `s${i}`;
}

export const IoGraphView: React.FC<IoGraphViewProps> = ({ history, version, status, connected, theme, onSend, now, timeZone }) => {
  const [span, setSpan] = useState(DEFAULT_SPAN);
  const [endMs, setEndMs] = useState<number | null>(null);
  const [follow, setFollow] = useState(true);
  const [chosen, setChosen] = useState<IoInterval>(1000);
  const [measures, setMeasures] = useState<Record<string, Measure>>({});
  const [draft, setDraft] = useState<DraftRow[]>([]);
  const [editing, setEditing] = useState(false);
  // Our last set_io_series, and a relay refusal if there was one. Whether
  // the agent has answered is derived from the status, never stored.
  const [sent, setSent] = useState<{ requestId: string; error?: string } | null>(null);
  const [hoverX, setHoverX] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const drag = useRef<{ x: number; end: number } | null>(null);

  // The agent's answer to our own request, matched by requestId. Once it
  // has answered (accepted or refused), the editor shows the agent's set,
  // which is authoritative; otherwise it shows the user's draft while they
  // edit, and the agent's set when they are not editing.
  const answer = sent && status && status.requestId === sent.requestId ? status : null;
  const pending = sent !== null && !sent.error && answer === null;
  const showingDraft = editing && answer === null;
  const rows = showingDraft ? draft : draftFrom(status);
  const message = sent?.error
    ?? (answer?.rejected ? (REJECTION_TEXT[answer.rejected] ?? `Refused: ${answer.rejected}`) : null);

  function edit(next: (current: DraftRow[]) => DraftRow[]) {
    const current = rows;
    setSent(null);
    setEditing(true);
    setDraft(next(current));
  }

  const latest = latestCoveredMs(history);
  const windowEnd = follow || endMs === null ? (latest ?? (now ?? Date.now)()) : endMs;
  const windowStart = windowEnd - span;
  const intervals = allowedIntervals(windowStart, windowEnd);
  const interval: IoInterval = intervals.find((i) => i.interval === chosen)?.allowed ? chosen : finestAllowed(windowStart, windowEnd);

  const ids = history.ids;
  const measureOf = (id: string): Measure => measures[id] ?? 'packets';

  const computed = useMemo(() => {
    const t0 = typeof performance !== 'undefined' ? performance.now() : 0;
    const perSeries = ids.map((id) => ({ id, points: query(history, id, interval, windowStart, windowEnd) }));
    const max: Record<Measure, number> = { packets: 0, bits: 0 };
    for (const s of perSeries) {
      const m = measureOf(s.id);
      for (const p of s.points) if (p.state === 'value') max[m] = Math.max(max[m], rate(p, m, interval));
    }
    const x = (ms: number) => M.left + ((ms - windowStart) / span) * PLOT_W;
    const paths = perSeries.map((s) => {
      const m = measureOf(s.id);
      const top = max[m] || 1;
      let d = '';
      let pen = false;
      for (const p of s.points) {
        if (p.state !== 'value') {
          pen = false;
          continue;
        }
        const px = x(p.startMs + interval / 2).toFixed(1);
        const py = (M.top + PLOT_H - (rate(p, m, interval) / top) * PLOT_H).toFixed(1);
        d += `${pen ? 'L' : 'M'}${px},${py}`;
        pen = true;
      }
      return { id: s.id, d };
    });
    const base: IoPoint[] = perSeries[0]?.points ?? [];
    const shaded = base
      .filter((p) => p.state !== 'value')
      .map((p) => ({ x: x(p.startMs), w: (interval / span) * PLOT_W, state: p.state }));
    const lossy = base.filter((p) => p.lossy).map((p) => x(p.startMs));
    const late = perSeries.flatMap((s, i) => s.points.filter((p) => p.latePackets > 0).map((p) => ({ x: x(p.startMs + interval / 2), i, n: p.latePackets })));
    if (typeof performance !== 'undefined' && typeof performance.measure === 'function') {
      try {
        performance.measure('io-graph-compute', { start: t0, end: performance.now() });
      } catch {
        // measure() is best effort (older engines)
      }
    }
    return { perSeries, max, paths, shaded, lossy, late };
    // measureOf reads `measures`; version tracks history mutation.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [history, version, ids, interval, windowStart, windowEnd, span, measures]);

  // Wheel zoom around the cursor. A non-passive listener, so the page does
  // not scroll while zooming.
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      zoomAround(e.deltaY < 0 ? 0.8 : 1.25, svgFraction(e.clientX));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  });

  function zoomAround(factor: number, frac: number) {
    const next = Math.min(MAX_SPAN, Math.max(MIN_SPAN, span * factor));
    setSpan(next);
    // While following live, zoom keeps the right edge on the newest data.
    if (follow) return;
    const anchor = windowStart + frac * span;
    setEndMs(anchor + (1 - frac) * next);
  }

  function pan(fraction: number) {
    setFollow(false);
    setEndMs(windowEnd + fraction * span);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement) return;
    if (e.key === 'ArrowLeft') { pan(-0.1); e.preventDefault(); }
    else if (e.key === 'ArrowRight') { pan(0.1); e.preventDefault(); }
    else if (e.key === '+' || e.key === '=') { zoomAround(0.8, 0.5); e.preventDefault(); }
    else if (e.key === '-' || e.key === '_') { zoomAround(1.25, 0.5); e.preventDefault(); }
    else if (e.key === 'End') { setFollow(true); setEndMs(null); e.preventDefault(); }
  }

  function svgFraction(clientX: number): number {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect || rect.width === 0) return 0;
    const vx = ((clientX - rect.left) / rect.width) * W;
    return Math.min(1, Math.max(0, (vx - M.left) / PLOT_W));
  }

  async function apply() {
    if (!status) return;
    const requestId = newRequestId();
    const series = rows.map((r) => ({ id: r.id.trim(), filter: r.filter }));
    setSent({ requestId });
    const ok = await onSend({ type: 'set_io_series', baseEpoch: status.epoch, baseRevision: status.revision, requestId, series });
    if (!ok) setSent({ requestId, error: 'The relay refused the request: check the series ids and filter lengths.' });
  }

  const hover = hoverX === null ? null : (() => {
    const t = windowStart + hoverX * span;
    const start = Math.floor(t / interval) * interval;
    return {
      t: start,
      rows: computed.perSeries.map((s, i) => ({ i, id: s.id, p: s.points.find((p) => p.startMs === start) })),
    };
  })();

  const tickList = ticks(windowStart, windowEnd, 6, timeZone);
  const usesBits = ids.some((id) => measureOf(id) === 'bits');
  const usesPackets = ids.some((id) => measureOf(id) === 'packets');
  const statusById = new Map(status?.series.map((s) => [s.id, s]) ?? []);

  return (
    <div
      className={`m-3 rounded border ${theme.border} ${theme.cardBg} p-3 font-mono text-xs space-y-3 outline-none`}
      tabIndex={0}
      onKeyDown={onKeyDown}
      data-testid="io-graph"
      aria-label="IO graph. Arrow keys pan, plus and minus zoom, End returns to live."
    >
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center space-x-2 text-slate-300 font-bold text-[11px]">
          <Activity className="h-3.5 w-3.5" />
          <span>IO GRAPH</span>
        </div>
        <label className="flex items-center gap-1 text-slate-400">
          interval
          <select
            className="bg-slate-950 border border-slate-700 rounded px-1 py-0.5 text-slate-200"
            value={interval}
            onChange={(e) => setChosen(Number(e.target.value) as IoInterval)}
            data-testid="io-interval"
          >
            {IO_INTERVALS.map((iv) => {
              const a = intervals.find((x) => x.interval === iv)!;
              return (
                <option key={iv} value={iv} disabled={!a.allowed} title={a.reason}>
                  {INTERVAL_LABEL[iv]}{a.allowed ? '' : ' (too many points)'}
                </option>
              );
            })}
          </select>
        </label>
        <span className="text-slate-500">window {formatSpan(span)}</span>
        <button
          className={`px-2 py-0.5 rounded border ${follow ? 'border-emerald-600 text-emerald-300' : 'border-slate-700 text-slate-400 hover:text-slate-200'}`}
          onClick={() => { setFollow(true); setEndMs(null); }}
          data-testid="io-follow"
        >
          {follow ? '● live' : '❚❚ paused (End: live)'}
        </button>
        <span className="text-slate-500" data-testid="io-horizon">{horizonText(history, interval, timeZone)}</span>
      </div>

      {!connected && <div className="text-amber-400">Agent not connected: the graph resumes when it reconnects.</div>}
      {status?.replayWaiting && (
        <div className="text-amber-300" data-testid="io-replay-waiting">
          Replay is waiting for series: add one and apply to start (REPLAY_WAIT_FOR_IO_SERIES).
        </div>
      )}

      {ids.length === 0 ? (
        <div className="text-slate-500 py-8 text-center" data-testid="io-empty">
          No IO graph series configured. Add one below; an empty filter counts every frame.
        </div>
      ) : (
        <div className="relative">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${W} ${H}`}
            preserveAspectRatio="none"
            className="w-full h-64 select-none cursor-crosshair"
            role="img"
            aria-label={`IO graph, ${ids.length} series, ${INTERVAL_LABEL[interval]} interval`}
            onPointerDown={(e) => { drag.current = { x: e.clientX, end: windowEnd }; (e.target as Element).setPointerCapture?.(e.pointerId); }}
            onPointerMove={(e) => {
              setHoverX(svgFraction(e.clientX));
              if (drag.current) {
                const rect = svgRef.current!.getBoundingClientRect();
                const dx = ((e.clientX - drag.current.x) / rect.width) * (W / PLOT_W) * span;
                setFollow(false);
                setEndMs(drag.current.end - dx);
              }
            }}
            onPointerUp={() => { drag.current = null; }}
            onPointerLeave={() => { drag.current = null; setHoverX(null); }}
          >
            {/* gridlines and time axis */}
            {tickList.map((t) => {
              const x = M.left + ((t.ms - windowStart) / span) * PLOT_W;
              return (
                <g key={t.ms}>
                  <line x1={x} x2={x} y1={M.top} y2={M.top + PLOT_H} className="stroke-slate-800" strokeWidth={1} />
                  <text x={x} y={H - 8} textAnchor="middle" className="fill-slate-500" fontSize={11}>{t.label}</text>
                </g>
              );
            })}
            <line x1={M.left} x2={M.left + PLOT_W} y1={M.top + PLOT_H} y2={M.top + PLOT_H} className="stroke-slate-600" />
            {usesPackets && <AxisLabels x={M.left - 6} anchor="end" max={computed.max.packets} unit={UNIT.packets} />}
            {usesBits && <AxisLabels x={M.left + PLOT_W + 6} anchor="start" max={computed.max.bits} unit={UNIT.bits} />}

            {/* unknown / not-observed shading */}
            {computed.shaded.map((s, i) => (
              <rect key={i} x={s.x} y={M.top} width={Math.max(s.w, 0.5)} height={PLOT_H}
                className={s.state === 'notObserved' ? 'fill-amber-900/40' : 'fill-slate-800/50'} />
            ))}
            {/* loss: red ticks along the bottom */}
            {computed.lossy.map((x, i) => (
              <line key={i} x1={x} x2={x} y1={M.top + PLOT_H - 6} y2={M.top + PLOT_H} className="stroke-red-500" strokeWidth={2} />
            ))}
            {/* series */}
            {computed.paths.map((p, i) => (
              <path key={p.id} d={p.d} fill="none" strokeWidth={1.5} vectorEffect="non-scaling-stroke"
                className={STROKES[i % STROKES.length]} data-testid={`io-path-${p.id}`} />
            ))}
            {/* late frames attributed to their interval */}
            {computed.late.map((l, k) => (
              <circle key={k} cx={l.x} cy={M.top + 4 + l.i * 4} r={2} className={STROKES[l.i % STROKES.length].replace('stroke', 'fill')}>
                <title>{`+${l.n} late`}</title>
              </circle>
            ))}
            {hoverX !== null && (
              <line x1={M.left + hoverX * PLOT_W} x2={M.left + hoverX * PLOT_W} y1={M.top} y2={M.top + PLOT_H} className="stroke-slate-400" strokeDasharray="3 3" />
            )}
          </svg>
          {hover && (
            <div className="absolute top-1 right-2 bg-slate-950/90 border border-slate-700 rounded px-2 py-1 space-y-0.5" data-testid="io-readout">
              <div className="text-slate-400">{new Date(hover.t).toLocaleTimeString(undefined, { timeZone })}</div>
              {hover.rows.map(({ i, id, p }) => (
                <div key={id} className="flex items-center gap-2">
                  <span className={`inline-block h-2 w-2 rounded-sm ${SWATCHES[i % SWATCHES.length]}`} />
                  <span className="text-slate-300">{id}</span>
                  <span className="text-slate-100">
                    {!p || p.state === 'unknown' ? 'unknown' : p.state === 'notObserved' ? 'not observed'
                      : `${formatSi(rate(p, measureOf(id), interval))} ${UNIT[measureOf(id)]}`}
                  </span>
                  {p && p.latePackets > 0 && <span className="text-amber-300">+{p.latePackets} late</span>}
                  {p?.lossy && <span className="text-red-400">incomplete</span>}
                </div>
              ))}
            </div>
          )}
          <div className="flex flex-wrap gap-3 text-[10px] text-slate-500 mt-1">
            <span><span className="inline-block h-2 w-3 bg-slate-800/80 mr-1" />unknown (not covered)</span>
            <span><span className="inline-block h-2 w-3 bg-amber-900/60 mr-1" />not observed</span>
            <span><span className="inline-block h-2 w-0.5 bg-red-500 mr-1" />frames lost before counting (interval incomplete)</span>
            <span>● late frames, kept apart from the line</span>
          </div>
        </div>
      )}

      <div className={`border-t ${theme.border} pt-2 space-y-1.5`} data-testid="io-editor">
        <div className="text-slate-400 text-[11px] font-bold">SERIES (shared by every tab)</div>
        {rows.map((row, i) => {
          const live = statusById.get(row.id);
          return (
            <div key={i} className="flex flex-wrap items-center gap-2">
              <span className={`inline-block h-2 w-2 rounded-sm ${SWATCHES[i % SWATCHES.length]}`} />
              <input
                aria-label={`series ${i + 1} id`}
                className="w-24 bg-slate-950 border border-slate-700 rounded px-1 py-0.5 text-slate-200"
                value={row.id}
                onChange={(e) => edit((cur) => cur.map((r, j) => (j === i ? { ...r, id: e.target.value } : r)))}
              />
              <input
                aria-label={`series ${i + 1} filter`}
                className="flex-1 min-w-[12rem] bg-slate-950 border border-slate-700 rounded px-1 py-0.5 text-slate-200"
                placeholder="display filter (empty = every frame)"
                value={row.filter}
                onChange={(e) => edit((cur) => cur.map((r, j) => (j === i ? { ...r, filter: e.target.value } : r)))}
              />
              <select
                aria-label={`series ${i + 1} measure`}
                className="bg-slate-950 border border-slate-700 rounded px-1 py-0.5 text-slate-200"
                value={measureOf(row.id)}
                onChange={(e) => setMeasures({ ...measures, [row.id]: e.target.value as Measure })}
              >
                <option value="packets">packets/s</option>
                <option value="bits">bits/s</option>
              </select>
              <button
                className="text-slate-500 hover:text-red-400"
                onClick={() => edit((cur) => cur.filter((_, j) => j !== i))}
                aria-label={`remove series ${i + 1}`}
              >
                ✕
              </button>
              {live?.error && !showingDraft && (
                <span className="text-red-400 w-full pl-4" data-testid={`io-error-${row.id}`}>
                  {live.error.message} at position {live.error.position}: <code>{live.error.token}</code> (not counted)
                </span>
              )}
            </div>
          );
        })}
        <div className="flex items-center gap-2">
          <button
            className="px-2 py-0.5 rounded border border-slate-700 text-slate-300 hover:text-slate-100 disabled:opacity-40"
            disabled={rows.length >= 8}
            onClick={() => edit((cur) => [...cur, { id: nextId(cur), filter: '' }])}
          >
            + series
          </button>
          <button
            className={`px-2 py-0.5 rounded border ${theme.border} ${theme.accent} disabled:opacity-40`}
            disabled={!status || !connected || pending}
            onClick={apply}
            data-testid="io-apply"
          >
            {pending ? 'applying…' : 'apply'}
          </button>
          {showingDraft && (
            <button className="text-slate-500 hover:text-slate-300" onClick={() => { setEditing(false); setSent(null); }}>
              discard changes
            </button>
          )}
          {message && <span className="text-amber-300" data-testid="io-message">{message}</span>}
        </div>
      </div>
    </div>
  );
};

function AxisLabels({ x, anchor, max, unit }: { x: number; anchor: 'start' | 'end'; max: number; unit: string }) {
  const steps = [0, 0.5, 1];
  return (
    <g>
      {steps.map((f) => (
        <text key={f} x={x} y={M.top + PLOT_H - f * PLOT_H + 4} textAnchor={anchor} className="fill-slate-500" fontSize={11}>
          {formatSi(max * f)}
        </text>
      ))}
      <text x={x} y={M.top + 8} textAnchor={anchor} className="fill-slate-400" fontSize={10} dy={12}>{unit}</text>
    </g>
  );
}

function formatSpan(ms: number): string {
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
  if (ms < 3_600_000) return `${(ms / 60_000).toFixed(ms < 600_000 ? 1 : 0)} min`;
  if (ms < 86_400_000) return `${(ms / 3_600_000).toFixed(1)} h`;
  return `${(ms / 86_400_000).toFixed(1)} d`;
}
