'use client';

// TCP stream graphs (KAN-129 Task 4, spec D6): time/sequence with the ACK and
// receive-window overlays, RTT, throughput and advertised window, on one
// time axis. Pure series come from lib/tcp-graphs.ts; ticks, zoom and the
// pointer fraction from lib/time-axis.ts, shared with the IO graph. Samples
// the ring overwrote before they were read are a gap, never interpolated.

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, X } from 'lucide-react';
import type { ThemeConfig } from '@/lib/types';
import { series, throughput, throughputIntervalUs, type Direction, type LinePoint, type TcpGraphState } from '@/lib/tcp-graphs';
import { clock, plotFraction, ticks, zoomView, type TimeView } from '@/lib/time-axis';

interface TcpGraphsViewProps {
  state: TcpGraphState;
  /** HTTP status of the last failed poll (0: relay unreachable), or null. */
  error: number | null;
  theme: ThemeConfig;
  /** The connection's handshake RTT, drawn as the RTT plot's reference line (plan A4). */
  latencyMs?: number;
  onClose: () => void;
  /** For tests: tick label time zone. */
  timeZone?: string;
}

const W = 800;
const H = 130;
const M = { left: 64, right: 12, top: 8, bottom: 18 };
const PLOT_W = W - M.left - M.right;
const PLOT_H = H - M.top - M.bottom;
// The view is in µs here (TimeView's endMs field holds µs).
const MIN_SPAN_US = 1000;
const MAX_SPAN_US = 3_600_000_000;
const RED = '#ef4444';
const ACK = '#22c55e';
const WINDOW = '#eab308';
const DATA = '#38bdf8';
const INBOUND = '#c084fc';

const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });

function errorText(status: number): string {
  if (status === 429 || status === 503 || status === 504) return `Agent busy (HTTP ${status}): retrying every second.`;
  if (status === 0) return 'Relay unreachable: retrying every second.';
  return `Could not load samples (HTTP ${status}): retrying every second.`;
}

type Scale = { x: (tUs: number) => number; y: (v: number) => number };

function linear(min: number, max: number): (v: number) => number {
  const hi = max > min ? max : min + 1;
  return (v) => M.top + PLOT_H - ((v - min) / (hi - min)) * PLOT_H;
}

/** Min and max of `values`, or [0, 1] when there are none. */
function extent(values: number[]): [number, number] {
  let lo = Infinity;
  let hi = -Infinity;
  for (const v of values) {
    if (v < lo) lo = v;
    if (v > hi) hi = v;
  }
  return lo === Infinity ? [0, 1] : [lo, hi];
}

/** A value holds until the next sample: steps, never a slope between samples. */
function stepPath(lines: LinePoint[][], s: Scale): string {
  return lines
    .map((l) => l.map((p, i) => (i ? `H${s.x(p.tUs).toFixed(1)}V${s.y(p.value).toFixed(1)}` : `M${s.x(p.tUs).toFixed(1)},${s.y(p.value).toFixed(1)}`)).join(''))
    .join('');
}

/** One zero-length round-capped subpath per point: a dot. */
function dotPath(points: { tUs: number; v: number }[], s: Scale): string {
  return points.map((p) => `M${s.x(p.tUs).toFixed(1)},${s.y(p.v).toFixed(1)}h0`).join('');
}

const Plot: React.FC<{ testId: string; title: string; ticks: { x: number; label: string }[]; yTicks: { y: number; label: string }[]; showLabels: boolean; children: React.ReactNode }> = ({
  testId, title, ticks: xTicks, yTicks, showLabels, children,
}) => (
  <div>
    <div className="text-[10px] uppercase text-slate-500">{title}</div>
    <svg data-testid={testId} viewBox={`0 0 ${W} ${H}`} className="w-full h-auto" role="img" aria-label={title}>
      <defs>
        <clipPath id={`${testId}-clip`}>
          <rect x={M.left} y={M.top} width={PLOT_W} height={PLOT_H} />
        </clipPath>
      </defs>
      {xTicks.map((t) => (
        <g key={t.x}>
          <line x1={t.x} x2={t.x} y1={M.top} y2={M.top + PLOT_H} stroke="#334155" strokeWidth={0.5} />
          {showLabels && <text x={t.x} y={H - 4} fontSize={9} fill="#94a3b8" textAnchor="middle">{t.label}</text>}
        </g>
      ))}
      {yTicks.map((t) => (
        <text key={t.y} x={M.left - 4} y={t.y + 3} fontSize={9} fill="#94a3b8" textAnchor="end">{t.label}</text>
      ))}
      <rect x={M.left} y={M.top} width={PLOT_W} height={PLOT_H} fill="none" stroke="#334155" strokeWidth={0.5} />
      <g clipPath={`url(#${testId}-clip)`}>{children}</g>
    </svg>
  </div>
);

function yTicksOf(min: number, max: number, y: (v: number) => number, fmt: (v: number) => string) {
  const hi = max > min ? max : min + 1;
  return [min, (min + hi) / 2, hi].map((v) => ({ y: y(v), label: fmt(v) }));
}

export const TcpGraphsView: React.FC<TcpGraphsViewProps> = ({ state, error, theme, latencyMs, onClose, timeZone }) => {
  const [direction, setDirection] = useState<Direction>('outbound');
  // `fit`: the window spans every sample held and follows new ones.
  const [fit, setFit] = useState(true);
  const [view, setView] = useState<TimeView>({ span: MIN_SPAN_US, endMs: null, follow: true });
  const rootRef = useRef<HTMLDivElement | null>(null);

  const s = useMemo(() => series(state, direction), [state, direction]);
  const samples = state.samples;
  const oldest = samples.length ? samples[0].tUs : 0;
  const newest = samples.length ? samples[samples.length - 1].tUs : 0;
  const fitSpan = Math.min(MAX_SPAN_US, Math.max(MIN_SPAN_US, newest - oldest));
  const span = fit ? fitSpan : view.span;
  const end = fit || view.follow || view.endMs === null ? newest : view.endMs;
  const start = end - span;
  const current: TimeView = { span, endMs: fit || view.follow ? null : end, follow: fit || view.follow };

  function zoom(factor: number, frac: number) {
    setFit(false);
    setView(zoomView(current, factor, frac, MIN_SPAN_US, MAX_SPAN_US));
  }
  function pan(fraction: number) {
    setFit(false);
    setView({ span, follow: false, endMs: end + fraction * span });
  }

  // Wheel zoom needs a non-passive listener to keep the page from scrolling.
  const zoomRef = useRef(zoom);
  useEffect(() => {
    zoomRef.current = zoom;
  });
  const hasPlots = samples.length > 0;
  useEffect(() => {
    const el = rootRef.current?.querySelector('[data-testid="tcp-plots"]');
    if (!el) return;
    const onWheel = (e: Event) => {
      const w = e as WheelEvent;
      w.preventDefault();
      const svg = (w.target as Element | null)?.closest('svg') ?? null;
      zoomRef.current(w.deltaY < 0 ? 0.8 : 1.25, plotFraction(svg, w.clientX, W, M.left, PLOT_W));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [hasPlots]);

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === '+' || e.key === '=') zoom(0.5, 0.5);
    else if (e.key === '-' || e.key === '_') zoom(2, 0.5);
    else if (e.key === 'ArrowLeft') pan(-0.1);
    else if (e.key === 'ArrowRight') pan(0.1);
    else if (e.key === '0' || e.key === 'Home') setFit(true);
    else return;
    e.preventDefault();
  }

  const x = (tUs: number) => M.left + ((tUs - start) / span) * PLOT_W;
  const visible = (tUs: number) => tUs >= start && tUs <= end;
  const xTicks = ticks(start / 1000, end / 1000, 6, timeZone).map((t) => ({ x: x(t.ms * 1000), label: t.label }));

  // 1–2. Time/sequence with the ACK and receive-window lines.
  const seqVals = [
    ...s.data.filter((p) => visible(p.tUs)).map((p) => p.seqEnd),
    ...s.ack.flat().filter((p) => visible(p.tUs)).map((p) => p.value),
    ...s.window.flat().filter((p) => visible(p.tUs)).map((p) => p.value),
  ];
  const [seqMin, seqMax] = extent(seqVals);
  const seq: Scale = { x, y: linear(seqMin, seqMax) };
  const toDots = (retransmit: boolean) => dotPath(s.data.filter((p) => p.retransmit === retransmit).map((p) => ({ tUs: p.tUs, v: p.seqEnd })), seq);
  const zeroOfAdvertiser = s.zeroWindow[direction === 'outbound' ? 'inbound' : 'outbound'];

  // 3. RTT (ms), with the handshake reference line.
  const rttPoints = s.rtt.map((p) => ({ tUs: p.tUs, v: p.rttUs / 1000 }));
  const [, rttMax] = extent([...rttPoints.filter((p) => visible(p.tUs)).map((p) => p.v), ...(latencyMs !== undefined ? [latencyMs] : [])]);
  const rtt: Scale = { x, y: linear(0, rttMax) };

  // 4. Throughput, bytes per second, both directions.
  const binUs = throughputIntervalUs(span);
  const bins = useMemo(() => (hasPlots ? throughput(state, start, end, binUs) : []), [hasPlots, state, start, end, binUs]);
  const perSecond = 1e6 / binUs;
  const [, tpMax] = extent(bins.flatMap((b) => [b.outbound * perSecond, b.inbound * perSecond]));
  const tp: Scale = { x, y: linear(0, tpMax) };
  const steps = (key: 'outbound' | 'inbound') =>
    bins.map((b) => `M${x(b.startUs).toFixed(1)},${tp.y(b[key] * perSecond).toFixed(1)}H${x(b.startUs + binUs).toFixed(1)}`).join('');

  // 5. Advertised window per advertiser.
  const winVals = [...s.advertised.outbound, ...s.advertised.inbound].flat().filter((p) => visible(p.tUs)).map((p) => p.value);
  const [, winMax] = extent(winVals);
  const win: Scale = { x, y: linear(0, winMax) };
  const shade = (from: number, to: number) => ({ x: x(from), width: Math.max(2, x(to) - x(from)) });

  const horizon = s.horizon
    ? `samples since ${clock(s.horizon.sinceUs / 1000, timeZone)}; ${s.horizon.dropped} older dropped` +
      (s.horizon.gaps ? `; ${s.horizon.gaps} gap${s.horizon.gaps === 1 ? '' : 's'} where samples were overwritten before they were read` : '')
    : null;
  const status =
    state.found === false
      ? hasPlots
        ? 'The agent no longer tracks this flow; showing the samples already fetched.'
        : 'The agent has no samples for this flow: it is not tracked, or every sample ring was in use when it started.'
      : !hasPlots && error === null
        ? state.found === null ? 'Loading samples…' : 'No samples yet for this flow.'
        : null;

  return (
    <div
      ref={rootRef}
      data-testid="tcp-graphs"
      tabIndex={0}
      onKeyDown={onKeyDown}
      className={`p-3.5 rounded border ${theme.border} ${theme.cardBg} space-y-2 outline-none`}
      aria-label="TCP graphs: + and - zoom, arrows pan, 0 fits all samples"
    >
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center space-x-2 font-bold text-slate-200">
          <Activity className={`h-4 w-4 ${theme.accent}`} />
          <span>TCP GRAPHS</span>
          <span className="font-mono text-[11px] text-slate-400 font-normal">{state.connectionId}</span>
        </div>
        <div className="flex items-center space-x-2 text-[11px]">
          <label className="text-slate-400">
            Data{' '}
            <select
              data-testid="tcp-direction"
              value={direction}
              onChange={(e) => setDirection(e.target.value as Direction)}
              className="bg-slate-900 border border-slate-700 rounded px-1 text-slate-200"
            >
              <option value="outbound">outbound (this host sends)</option>
              <option value="inbound">inbound (this host receives)</option>
            </select>
          </label>
          <button onClick={onClose} aria-label="Close TCP graphs" className="p-1 rounded hover:bg-slate-800 text-slate-400">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div className="text-[11px] text-slate-400 space-y-0.5">
        {horizon && <div data-testid="tcp-horizon">{horizon}</div>}
        {s.note && <div data-testid="tcp-note" className="text-amber-400">{s.note}</div>}
        {status && <div data-testid="tcp-status">{status}</div>}
        {error !== null && <div data-testid="tcp-error" className="text-amber-400">{errorText(error)}</div>}
      </div>

      {hasPlots && (
        <div data-testid="tcp-plots" className="space-y-1">
          <Plot testId="tcp-plot-seq" title="Time / sequence (relative): data, ACK line, receive window" ticks={xTicks} showLabels={false} yTicks={yTicksOf(seqMin, seqMax, seq.y, (v) => compact.format(v))}>
            {zeroOfAdvertiser.map((z) => (
              <rect key={z.fromUs} data-testid="tcp-seq-zero-window" {...shade(z.fromUs, z.toUs)} y={M.top} height={PLOT_H} fill={RED} opacity={0.12} />
            ))}
            <path data-testid="tcp-window-path" d={stepPath(s.window, seq)} fill="none" stroke={WINDOW} strokeWidth={1} />
            <path data-testid="tcp-ack-path" d={stepPath(s.ack, seq)} fill="none" stroke={ACK} strokeWidth={1} />
            <path data-testid="tcp-data-path" d={toDots(false)} fill="none" stroke={DATA} strokeWidth={3} strokeLinecap="round" />
            <path data-testid="tcp-retransmit-path" d={toDots(true)} fill="none" stroke={RED} strokeWidth={4} strokeLinecap="round" />
            {s.controlMarks.map((m, i) => {
              const mx = x(m.tUs);
              const atEnd = mx > M.left + PLOT_W - 40;
              const colour = m.kind === 'RST' ? RED : '#e2e8f0';
              return (
                <g key={`${m.kind}-${m.tUs}-${m.outbound}`} data-testid={`tcp-mark-${m.kind}`}>
                  <line x1={mx} x2={mx} y1={M.top} y2={M.top + PLOT_H} stroke={colour} strokeDasharray="2 2" strokeWidth={0.75} />
                  {/* Neighbouring marks stack, so two FINs a few ms apart stay readable. */}
                  <text x={atEnd ? mx - 3 : mx + 3} y={M.top + 9 + (i % 3) * 10} fontSize={9} textAnchor={atEnd ? 'end' : 'start'} fill={colour}>
                    {m.kind} {m.outbound ? 'out' : 'in'}
                  </text>
                </g>
              );
            })}
          </Plot>
          <div className="text-[10px] text-slate-500">RTT: {s.rttLabel}</div>
          <Plot testId="tcp-plot-rtt" title="RTT (ms) per ACK, Karn's rule" ticks={xTicks} showLabels={false} yTicks={yTicksOf(0, rttMax, rtt.y, (v) => v.toFixed(v < 10 ? 2 : 0))}>
            {latencyMs !== undefined && (
              <line data-testid="tcp-rtt-ref" x1={M.left} x2={M.left + PLOT_W} y1={rtt.y(latencyMs)} y2={rtt.y(latencyMs)} stroke="#94a3b8" strokeDasharray="4 3" strokeWidth={1}>
                <title>handshake RTT {latencyMs} ms</title>
              </line>
            )}
            <path data-testid="tcp-rtt-path" d={dotPath(rttPoints, rtt)} fill="none" stroke={DATA} strokeWidth={3} strokeLinecap="round" />
          </Plot>
          <Plot testId="tcp-plot-throughput" title={`Throughput (bytes/s, ${binUs >= 1e6 ? `${binUs / 1e6} s` : `${binUs / 1000} ms`} bins): outbound, inbound`} ticks={xTicks} showLabels={false} yTicks={yTicksOf(0, tpMax, tp.y, (v) => compact.format(v))}>
            <path data-testid="tcp-throughput-outbound" d={steps('outbound')} fill="none" stroke={DATA} strokeWidth={1.5} />
            <path data-testid="tcp-throughput-inbound" d={steps('inbound')} fill="none" stroke={INBOUND} strokeWidth={1.5} />
          </Plot>
          <div className="text-[10px] text-slate-500">window: {s.windowLabel}</div>
          <Plot testId="tcp-plot-window" title="Advertised window (bytes): outbound, inbound; zero window shaded" ticks={xTicks} showLabels yTicks={yTicksOf(0, winMax, win.y, (v) => compact.format(v))}>
            {(['outbound', 'inbound'] as const).flatMap((d) =>
              s.zeroWindow[d].map((z) => (
                <rect key={`${d}-${z.fromUs}`} data-testid="tcp-zero-window" {...shade(z.fromUs, z.toUs)} y={M.top} height={PLOT_H} fill={RED} opacity={0.2} />
              )),
            )}
            <path data-testid="tcp-advertised-outbound" d={stepPath(s.advertised.outbound, win)} fill="none" stroke={DATA} strokeWidth={1} />
            <path data-testid="tcp-advertised-inbound" d={stepPath(s.advertised.inbound, win)} fill="none" stroke={INBOUND} strokeWidth={1} />
          </Plot>
        </div>
      )}
    </div>
  );
};
