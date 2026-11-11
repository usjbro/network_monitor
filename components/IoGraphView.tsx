'use client';

// IO graph (JAM-18 Task 3): filter-defined series over a real time axis.
// Data comes from the agent's complete 100 ms bucket counts (io_buckets),
// held in lib/io-graph.ts. This component only renders and edits; the
// shared series set is changed by compare-and-swap: an edit records the
// (epoch, revision) it started from and sends exactly that as its base, so
// a change made meanwhile in another tab is refused by the agent, never
// silently overwritten.

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Activity } from 'lucide-react';
import type { IoSeriesStatus, ThemeConfig } from '@/lib/types';
import {
  IO_INTERVALS,
  MAX_HISTORY_MS,
  allowedIntervals,
  clock,
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
  /**
   * Click-through (JAM-18 Task 4): open the Packets view for one series'
   * interval [startMs, startMs + interval). Without it, no packet buttons.
   */
  onDrill?: (seriesId: string, interval: IoInterval, startMs: number) => void;
}

const W = 1000;
const H = 260;
const M = { left: 64, right: 64, top: 12, bottom: 28 };
const PLOT_W = W - M.left - M.right;
const PLOT_H = H - M.top - M.bottom;
const MIN_SPAN = 2_000;
// No window is wider than the longest ring (24 h at 1 min, 1 440 points),
// so the chart never needs more than MAX_POINTS and never drops the newest.
const MAX_SPAN = MAX_HISTORY_MS;
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
const REASON_LABEL: Record<string, string> = {
  interface_switch: 'interface switch', replay_error: 'replay error', backlog: 'backlog', unknown: 'unknown reason',
};

export function formatSi(value: number): string {
  if (!Number.isFinite(value)) return '—';
  const abs = Math.abs(value);
  const units: [number, string][] = [[1e9, 'G'], [1e6, 'M'], [1e3, 'k']];
  for (const [scale, suffix] of units) {
    if (abs >= scale) return `${(value / scale).toFixed(abs / scale >= 100 ? 0 : 1)}${suffix}`;
  }
  return abs >= 100 || Number.isInteger(value) ? value.toFixed(0) : value.toFixed(1);
}

const CONFLICT_TEXT = 'Series changed in another tab: review the current set below and resend.';
const STALE_DRAFT_TEXT = 'Series changed in another tab since you started editing: applying this draft will be refused. Discard it to see the current set.';
const UNANSWERED_TEXT = 'The series set changed before the agent answered this tab: review the current set below and resend if needed.';
const DISCONNECTED_TEXT = 'The connection dropped before the agent answered: review the current set below and resend if needed.';
const RELAY_REFUSED_TEXT = 'The relay refused the request: check the series ids and filter lengths.';

const REJECTION_TEXT: Record<string, string> = {
  conflict: CONFLICT_TEXT,
  too_many_series: 'At most 8 series.',
  invalid_id: 'Series ids are 1–32 characters of a–z, 0–9 and "-".',
  duplicate_id: 'Series ids must be unique.',
  filter_too_long: 'A filter is longer than 2048 characters.',
  invalid_request_id: 'The request id was invalid.',
  invalid_epoch: 'The agent epoch was invalid.',
};

type DraftRow = { key: string; id: string; filter: string };
type Base = { epoch: string; revision: number };
/** An open edit: its rows and the agent set it started from. */
type Draft = { rows: DraftRow[]; base: Base | null };
/** Our last set_io_series, latched once answered (or abandoned). */
type Sent = { requestId: string; base: Base; answer?: IoSeriesStatus; error?: string };
type View = { span: number; endMs: number | null; follow: boolean };

function rowsFrom(status: IoSeriesStatus | null): DraftRow[] {
  return status ? status.series.map((s) => ({ key: `cur-${s.id}`, id: s.id, filter: s.filter })) : [];
}

function baseOf(status: IoSeriesStatus | null): Base | null {
  return status ? { epoch: status.epoch, revision: status.revision } : null;
}

function sameBase(a: Base | null, status: IoSeriesStatus | null): boolean {
  return !!a && !!status && a.epoch === status.epoch && a.revision === status.revision;
}

function nextId(rows: DraftRow[]): string {
  for (let i = 1; ; i++) if (!rows.some((r) => r.id === `s${i}`)) return `s${i}`;
}

const clampSpan = (span: number) => Math.min(MAX_SPAN, Math.max(MIN_SPAN, span));

/** Zoom by `factor` around the fraction `frac` of the plot width. */
function zoomView(v: View, factor: number, frac: number): View {
  const span = clampSpan(v.span * factor);
  // While following live, zoom keeps the right edge on the newest data.
  if (v.follow || v.endMs === null) return { ...v, span };
  const anchor = v.endMs - v.span + frac * v.span;
  return { ...v, span, endMs: anchor + (1 - frac) * span };
}

/** Fraction of the plot width under `clientX`, for an svg element. */
function plotFraction(el: Element | null, clientX: number): number {
  const rect = el?.getBoundingClientRect();
  if (!rect || rect.width === 0) return 0;
  const vx = ((clientX - rect.left) / rect.width) * W;
  return Math.min(1, Math.max(0, (vx - M.left) / PLOT_W));
}

export const IoGraphView: React.FC<IoGraphViewProps> = ({ history, version, status, connected, theme, onSend, now, timeZone, onDrill }) => {
  const [view, setView] = useState<View>({ span: DEFAULT_SPAN, endMs: null, follow: true });
  const [chosen, setChosen] = useState<IoInterval>(1000);
  const [measures, setMeasures] = useState<Record<string, Measure>>({});
  const [draft, setDraft] = useState<Draft | null>(null);
  const [sent, setSent] = useState<Sent | null>(null);
  const [hoverX, setHoverX] = useState<number | null>(null);
  // A clicked interval stays shown (with its packet buttons) until Escape or
  // another click; held as a time so it survives pan, zoom and interval changes.
  const [pinnedMs, setPinnedMs] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const drag = useRef<{ x: number; end: number; moved: boolean } | null>(null);
  const pointers = useRef(new Map<number, number>());
  const pinch = useRef<number | null>(null);
  const newRowCount = useRef(0);

  // Latch the agent's answer to our own request the first time it is
  // seen. A later status (another tab's change, a reconnect bootstrap)
  // must not make an answered request look pending again. This is the
  // "adjust state when a prop changes" pattern: it runs during render,
  // only when status or connected changed.
  const [seen, setSeen] = useState({ status, connected });
  if (seen.status !== status || seen.connected !== connected) {
    setSeen({ status, connected });
    if (sent && !sent.answer && !sent.error) {
      if (status && status.requestId === sent.requestId) {
        setSent({ ...sent, answer: status });
        setDraft(null); // answered: the agent's set is authoritative
      } else if (!connected) {
        setSent({ ...sent, error: DISCONNECTED_TEXT });
        setDraft(null);
      } else if (status && status !== seen.status && (!sameBase(sent.base, status) || status.requestId === undefined)) {
        // The set moved, or the agent re-sent its state (reconnect),
        // without answering us: our request will not be answered.
        setSent({ ...sent, error: UNANSWERED_TEXT });
        setDraft(null);
      }
    }
  }

  const pending = sent !== null && !sent.answer && !sent.error;
  const rows = draft ? draft.rows : rowsFrom(status);
  const staleDraft = draft !== null && draft.base !== null && status !== null && !sameBase(draft.base, status);
  const message = sent?.error
    ?? (sent?.answer?.rejected ? (REJECTION_TEXT[sent.answer.rejected] ?? `Refused: ${sent.answer.rejected}`) : null)
    ?? (staleDraft && !pending ? STALE_DRAFT_TEXT : null);

  function edit(next: (current: DraftRow[]) => DraftRow[]) {
    if (pending) return;
    setSent(null);
    setDraft((d) => (d ? { ...d, rows: next(d.rows) } : { rows: next(rowsFrom(status)), base: baseOf(status) }));
  }

  function discard() {
    setDraft(null);
    setSent(null);
  }

  const latest = latestCoveredMs(history);
  const windowEnd = view.follow || view.endMs === null ? (latest ?? (now ?? Date.now)()) : view.endMs;
  const span = view.span;
  const windowStart = windowEnd - span;
  const intervals = allowedIntervals(windowStart, windowEnd);
  const interval: IoInterval = intervals.find((i) => i.interval === chosen)?.allowed ? chosen : finestAllowed(windowStart, windowEnd);

  const ids = history.ids;
  const measureOf = (id: string): Measure => measures[id] ?? 'packets';

  const computed = useMemo(() => timed('io-graph-compute', () => {
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
      let run = 0;
      for (const p of s.points) {
        if (p.state !== 'value') {
          // A lone point between gaps: a zero-length segment, drawn as a
          // dot by the round line cap.
          if (run === 1) d += 'l0,0';
          run = 0;
          continue;
        }
        const px = x(p.startMs + interval / 2).toFixed(1);
        const py = (M.top + PLOT_H - (rate(p, m, interval) / top) * PLOT_H).toFixed(1);
        d += `${run > 0 ? 'L' : 'M'}${px},${py}`;
        run++;
      }
      if (run === 1) d += 'l0,0';
      return { id: s.id, d };
    });
    const base: IoPoint[] = perSeries[0]?.points ?? [];
    const shaded = base
      .filter((p) => p.state !== 'value')
      .map((p) => ({ x: x(p.startMs), w: (interval / span) * PLOT_W, state: p.state }));
    const lossy = base.filter((p) => p.lossy).map((p) => x(p.startMs));
    const late = perSeries.flatMap((s, i) => s.points
      .filter((p) => p.latePackets > 0 || p.unplacedLate > 0)
      .map((p) => ({ x: x(p.startMs + interval / 2), i, n: p.latePackets, unplaced: p.unplacedLate })));
    const markers = history.markers
      .filter((mk) => mk.ms >= windowStart && mk.ms <= windowEnd)
      .map((mk) => ({ x: x(mk.ms), reason: mk.reason }));
    return { perSeries, max, paths, shaded, lossy, late, markers };
    // measureOf reads `measures`; version tracks history mutation.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [history, version, ids, interval, windowStart, windowEnd, span, measures]);

  // Wheel (and trackpad pinch, which arrives as ctrl+wheel) zooms around
  // the cursor. A non-passive listener, so the page does not scroll while
  // zooming; attached once per chart mount, and using functional updates so
  // a burst of wheel events never reads a stale span.
  const hasChart = ids.length > 0;
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const frac = plotFraction(el, e.clientX);
      setView((v) => zoomView(v, e.deltaY < 0 ? 0.8 : 1.25, frac));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [hasChart]);

  function pan(fraction: number) {
    setView((v) => ({ ...v, follow: false, endMs: (v.follow || v.endMs === null ? windowEnd : v.endMs) + fraction * v.span }));
  }

  function goLive() {
    setView((v) => ({ ...v, follow: true, endMs: null }));
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement) return;
    if (e.key === 'ArrowLeft') { pan(-0.1); e.preventDefault(); }
    else if (e.key === 'ArrowRight') { pan(0.1); e.preventDefault(); }
    else if (e.key === '+' || e.key === '=') { setView((v) => zoomView(v, 0.8, 0.5)); e.preventDefault(); }
    else if (e.key === '-' || e.key === '_') { setView((v) => zoomView(v, 1.25, 0.5)); e.preventDefault(); }
    else if (e.key === 'End') { goLive(); e.preventDefault(); }
    else if (e.key === 'Enter') { setPinnedMs(windowEnd - 1); e.preventDefault(); } // pin the newest interval
    else if (e.key === 'Escape') { setPinnedMs(null); e.preventDefault(); }
  }

  function onPointerDown(e: React.PointerEvent<SVGSVGElement>) {
    pointers.current.set(e.pointerId, e.clientX);
    (e.target as Element).setPointerCapture?.(e.pointerId);
    if (pointers.current.size === 2) {
      // Two fingers: pinch zoom instead of drag.
      const [a, b] = [...pointers.current.values()];
      pinch.current = Math.abs(a - b);
      drag.current = null;
    } else if (pointers.current.size === 1) {
      drag.current = { x: e.clientX, end: windowEnd, moved: false };
    }
  }

  function onPointerMove(e: React.PointerEvent<SVGSVGElement>) {
    setHoverX(plotFraction(svgRef.current, e.clientX));
    if (!pointers.current.has(e.pointerId)) return;
    pointers.current.set(e.pointerId, e.clientX);
    if (pointers.current.size === 2 && pinch.current !== null) {
      const [a, b] = [...pointers.current.values()];
      const dist = Math.abs(a - b);
      if (dist > 0 && pinch.current > 0) {
        const factor = pinch.current / dist;
        const frac = plotFraction(svgRef.current, (a + b) / 2);
        setView((v) => zoomView(v, factor, frac));
      }
      pinch.current = dist;
      return;
    }
    if (drag.current) {
      // A few pixels of jitter is still a click, not a pan.
      if (!drag.current.moved && Math.abs(e.clientX - drag.current.x) <= 3) return;
      drag.current.moved = true;
      const rect = svgRef.current!.getBoundingClientRect();
      const width = rect.width || 1;
      const dx = ((e.clientX - drag.current.x) / width) * (W / PLOT_W) * span;
      const end = drag.current.end - dx;
      setView((v) => ({ ...v, follow: false, endMs: end }));
    }
  }

  function onPointerEnd(e: React.PointerEvent<SVGSVGElement>) {
    if (e.type === 'pointerup' && drag.current && !drag.current.moved && pointers.current.size === 1) {
      setPinnedMs(windowStart + plotFraction(svgRef.current, e.clientX) * span);
    }
    pointers.current.delete(e.pointerId);
    if (pointers.current.size < 2) pinch.current = null;
    drag.current = null;
  }

  async function apply() {
    if (!status || pending) return;
    // An open draft sends the base it was built from; an untouched editor
    // re-sends the current set against the current revision.
    const base = draft?.base ?? baseOf(status)!;
    const requestId = newRequestId();
    const series = rows.map((r) => ({ id: r.id.trim(), filter: r.filter }));
    setSent({ requestId, base });
    const ok = await onSend({ type: 'set_io_series', baseEpoch: base.epoch, baseRevision: base.revision, requestId, series });
    if (!ok) setSent((s) => (s && s.requestId === requestId && !s.answer ? { ...s, error: RELAY_REFUSED_TEXT } : s));
  }

  const readoutAt = pinnedMs ?? (hoverX === null ? null : windowStart + hoverX * span);
  const hover = readoutAt === null ? null : (() => {
    const start = Math.floor(readoutAt / interval) * interval;
    return {
      t: start,
      pinned: pinnedMs !== null,
      rows: computed.perSeries.map((s, i) => ({ i, id: s.id, p: s.points.find((p) => p.startMs === start) })),
    };
  })();

  const tickList = ticks(windowStart, windowEnd, 6, timeZone);
  const usesBits = ids.some((id) => measureOf(id) === 'bits');
  const usesPackets = ids.some((id) => measureOf(id) === 'packets');
  const statusById = new Map(status?.series.map((s) => [s.id, s]) ?? []);
  const total = status?.series.length ?? ids.length;
  const counting = status ? status.series.filter((s) => s.ok).length : ids.length;
  const unplaced = ids
    .map((id, i) => ({ id, n: history.unplacedLateTotal[i] ?? 0 }))
    .filter((u) => u.n > 0);

  return (
    <div
      className={`m-3 rounded border ${theme.border} ${theme.cardBg} p-3 font-mono text-xs space-y-3 outline-none focus-visible:ring-1 focus-visible:ring-emerald-500`}
      tabIndex={0}
      onKeyDown={onKeyDown}
      data-testid="io-graph"
      role="region"
      aria-label="IO graph"
      aria-describedby="io-graph-keys"
    >
      <span id="io-graph-keys" className="sr-only">Arrow keys pan, plus and minus zoom, End returns to live, Enter pins the newest interval and Escape unpins. Click an interval to pin it and open its packets.</span>
      <span className="sr-only" aria-live="polite" data-testid="io-follow-announce">
        {view.follow ? 'Following live data' : 'Paused: press End to follow live data'}
      </span>
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
          className={`px-2 py-0.5 rounded border ${view.follow ? 'border-emerald-600 text-emerald-300' : 'border-slate-700 text-slate-400 hover:text-slate-200'}`}
          onClick={goLive}
          data-testid="io-follow"
        >
          {view.follow ? '● live' : '❚❚ paused (End: live)'}
        </button>
        <span className="text-slate-500" data-testid="io-series-count">
          Showing {counting} of {total} series
          {history.epochStartedMs !== null ? ` · agent session since ${clock(history.epochStartedMs, timeZone)}` : ''}
        </span>
        <span className="text-slate-500" data-testid="io-horizon">{horizonText(history, interval, timeZone)}</span>
      </div>

      {!connected && <div className="text-amber-400">Agent not connected: the graph resumes when it reconnects.</div>}
      {status?.replayWaiting && (
        <div className="text-amber-300" data-testid="io-replay-waiting">
          Replay is waiting for series: add one and apply to start (REPLAY_WAIT_FOR_IO_SERIES).
        </div>
      )}
      {unplaced.length > 0 && (
        <div className="text-amber-300" data-testid="io-unplaced-late">
          Late frames whose interval is no longer held (counted on their message span):{' '}
          {unplaced.map((u) => `${u.id} ${u.n}`).join(', ')}
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
            className="w-full h-64 select-none cursor-crosshair touch-none"
            role="img"
            aria-label={`IO graph, ${ids.length} series, ${INTERVAL_LABEL[interval]} interval`}
            data-testid="io-svg"
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerEnd}
            onPointerCancel={onPointerEnd}
            onPointerLeave={(e) => { onPointerEnd(e); setHoverX(null); }}
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
            {/* zero-length markers (e.g. a replay read error at end of file) */}
            {computed.markers.map((mk, i) => (
              <line key={`mk${i}`} x1={mk.x} x2={mk.x} y1={M.top} y2={M.top + PLOT_H} className="stroke-amber-500" strokeDasharray="2 2"
                data-testid="io-marker">
                <title>{`not observed: ${REASON_LABEL[mk.reason] ?? mk.reason}`}</title>
              </line>
            ))}
            {/* loss: red ticks along the bottom */}
            {computed.lossy.map((x, i) => (
              <line key={i} x1={x} x2={x} y1={M.top + PLOT_H - 6} y2={M.top + PLOT_H} className="stroke-red-500" strokeWidth={2} />
            ))}
            {/* series */}
            {computed.paths.map((p, i) => (
              <path key={p.id} d={p.d} fill="none" strokeWidth={1.5} strokeLinecap="round" vectorEffect="non-scaling-stroke"
                className={STROKES[i % STROKES.length]} data-testid={`io-path-${p.id}`} />
            ))}
            {/* late frames attributed to their interval */}
            {computed.late.map((l, k) => (
              <circle key={k} cx={l.x} cy={M.top + 4 + l.i * 4} r={2} className={STROKES[l.i % STROKES.length].replace('stroke', 'fill')}>
                <title>{l.n > 0 ? `+${l.n} late` : `+${l.unplaced} late (interval not known, within this message span)`}</title>
              </circle>
            ))}
            {hoverX !== null && (
              <line x1={M.left + hoverX * PLOT_W} x2={M.left + hoverX * PLOT_W} y1={M.top} y2={M.top + PLOT_H} className="stroke-slate-400" strokeDasharray="3 3" />
            )}
          </svg>
          {hover && (
            <div className="absolute top-1 right-2 bg-slate-950/90 border border-slate-700 rounded px-2 py-1 space-y-0.5" data-testid="io-readout">
              <div className="text-slate-400">
                {new Date(hover.t).toLocaleTimeString(undefined, { timeZone })}
                {hover.pinned && <span className="text-slate-500"> · pinned (Esc to clear)</span>}
              </div>
              {hover.rows.map(({ i, id, p }) => (
                <div key={id} className="flex items-center gap-2">
                  <span className={`inline-block h-2 w-2 rounded-sm ${SWATCHES[i % SWATCHES.length]}`} />
                  <span className="text-slate-300">{id}</span>
                  <span className="text-slate-100">{readout(p, measureOf(id), interval)}</span>
                  {p && p.latePackets > 0 && <span className="text-amber-300">+{p.latePackets} late</span>}
                  {p && p.unplacedLate > 0 && <span className="text-amber-300">+{p.unplacedLate} late (interval unknown)</span>}
                  {p?.lossy && <span className="text-red-400">incomplete</span>}
                  {hover.pinned && onDrill && (
                    <button type="button" data-testid={`io-drill-${id}`} onClick={() => onDrill(id, interval, hover.t)}
                      className="ml-1 px-1 rounded border border-sky-800/60 text-sky-300 hover:bg-sky-950">
                      packets →
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
          <div className="flex flex-wrap gap-3 text-[10px] text-slate-500 mt-1">
            <span><span className="inline-block h-2 w-3 bg-slate-800/80 mr-1" />unknown (not covered)</span>
            <span><span className="inline-block h-2 w-3 bg-amber-900/60 mr-1" />not observed (all or part of the interval)</span>
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
            <div key={row.key} className="flex flex-wrap items-center gap-2">
              <span className={`inline-block h-2 w-2 rounded-sm ${SWATCHES[i % SWATCHES.length]}`} />
              <input
                aria-label={`series ${i + 1} id`}
                className="w-24 bg-slate-950 border border-slate-700 rounded px-1 py-0.5 text-slate-200 disabled:opacity-60"
                value={row.id}
                disabled={pending}
                onChange={(e) => {
                  const id = e.target.value;
                  // The measure follows the row, not the old id.
                  setMeasures((m) => (m[row.id] && !m[id] ? { ...m, [id]: m[row.id] } : m));
                  edit((cur) => cur.map((r) => (r.key === row.key ? { ...r, id } : r)));
                }}
              />
              <input
                aria-label={`series ${i + 1} filter`}
                className="flex-1 min-w-[12rem] bg-slate-950 border border-slate-700 rounded px-1 py-0.5 text-slate-200 disabled:opacity-60"
                placeholder="display filter (empty = every frame)"
                value={row.filter}
                disabled={pending}
                onChange={(e) => {
                  const filter = e.target.value;
                  edit((cur) => cur.map((r) => (r.key === row.key ? { ...r, filter } : r)));
                }}
              />
              <select
                aria-label={`series ${i + 1} measure`}
                className="bg-slate-950 border border-slate-700 rounded px-1 py-0.5 text-slate-200"
                value={measureOf(row.id)}
                onChange={(e) => {
                  const measure = e.target.value as Measure;
                  setMeasures((m) => ({ ...m, [row.id]: measure }));
                }}
              >
                <option value="packets">packets/s</option>
                <option value="bits">bits/s</option>
              </select>
              <button
                className="text-slate-500 hover:text-red-400 disabled:opacity-40"
                disabled={pending}
                onClick={() => edit((cur) => cur.filter((r) => r.key !== row.key))}
                aria-label={`remove series ${i + 1}`}
              >
                ✕
              </button>
              {live?.error && !draft && (
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
            disabled={rows.length >= 8 || pending}
            onClick={() => edit((cur) => [...cur, { key: `new-${++newRowCount.current}`, id: nextId(cur), filter: '' }])}
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
          {draft && !pending && (
            <button className="text-slate-500 hover:text-slate-300" onClick={discard} data-testid="io-discard">
              discard changes
            </button>
          )}
          {message && <span className="text-amber-300" data-testid="io-message">{message}</span>}
        </div>
      </div>
    </div>
  );
};

/**
 * Runs `fn`, recording its duration as a performance measure (read by the
 * e2e frame-budget check). Best effort where measure() is unavailable.
 */
export function timed<T>(name: string, fn: () => T): T {
  const perf = typeof performance !== 'undefined' ? performance : null;
  const t0 = perf ? perf.now() : 0;
  const result = fn();
  if (perf && typeof perf.measure === 'function') {
    try {
      perf.measure(name, { start: t0, end: perf.now() });
    } catch {
      // older engines
    }
  }
  return result;
}

function readout(p: IoPoint | undefined, measure: Measure, interval: IoInterval): string {
  if (!p || p.state === 'unknown') return 'unknown';
  if (p.state === 'notObserved') {
    const why = p.notObservedReason ? ` (${REASON_LABEL[p.notObservedReason] ?? p.notObservedReason})` : '';
    const part = p.notObservedMs < interval ? `, ${formatSpan(p.notObservedMs)} of ${INTERVAL_LABEL[interval]}` : '';
    return `not observed${why}${part}`;
  }
  return `${formatSi(rate(p, measure, interval))} ${UNIT[measure]}`;
}

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
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
  if (ms < 3_600_000) return `${(ms / 60_000).toFixed(ms < 600_000 ? 1 : 0)} min`;
  if (ms < 86_400_000) return `${(ms / 3_600_000).toFixed(1)} h`;
  return `${(ms / 86_400_000).toFixed(1)} d`;
}
