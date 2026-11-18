// Time-axis helpers shared by the IO graph and the TCP graphs (KAN-129 plan
// P6): wall-clock tick labels, HH:MM:SS, and pan/zoom of a time window.
// Moved from lib/io-graph.ts, which re-exports them unchanged.

const TICK_STEPS = [
  100, 200, 500, 1000, 2000, 5000, 10000, 15000, 30000, 60000, 120000, 300000, 600000, 900000, 1800000, 3600000,
  7200000, 10800000, 21600000, 43200000, 86400000,
];

export interface Tick {
  ms: number;
  label: string;
}

const partsFormats = new Map<string, Intl.DateTimeFormat>();

/** The zone's offset from UTC at `ms` (local wall time minus UTC), in ms. */
export function zoneOffsetMs(ms: number, timeZone?: string): number {
  const key = timeZone ?? '';
  let fmt = partsFormats.get(key);
  if (!fmt) {
    fmt = new Intl.DateTimeFormat('en-US', {
      timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
    partsFormats.set(key, fmt);
  }
  const p: Record<string, number> = {};
  for (const part of fmt.formatToParts(new Date(ms))) if (part.type !== 'literal') p[part.type] = Number(part.value);
  const wall = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
  return wall - (ms - (((ms % 1000) + 1000) % 1000));
}

function localDay(ms: number, timeZone?: string): number {
  return Math.floor((ms + zoneOffsetMs(ms, timeZone)) / 86_400_000);
}

/**
 * About `target` labelled ticks across [fromMs, toMs). Labels are wall-clock
 * time in `timeZone` (the viewer's own by default), with milliseconds only
 * when the step is sub-second. Steps of a minute or more are aligned to
 * local wall-clock multiples (so hourly ticks land on the hour in a +5:30
 * zone, and across DST), and carry the date when the window spans days.
 */
export function ticks(fromMs: number, toMs: number, target = 6, timeZone?: string): Tick[] {
  const span = toMs - fromMs;
  if (!(span > 0)) return [];
  const step = TICK_STEPS.find((s) => span / s <= target) ?? TICK_STEPS[TICK_STEPS.length - 1];
  const withDate = step >= 3_600_000 && localDay(fromMs, timeZone) !== localDay(toMs - 1, timeZone);
  const format = new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZone,
    ...(withDate ? { day: 'numeric', month: 'short' } : { second: '2-digit' }),
    ...(step < 1000 ? { fractionalSecondDigits: 3 as const } : {}),
  });
  const out: Tick[] = [];
  const push = (t: number) => {
    if (t >= fromMs && t < toMs && (out.length === 0 || t > out[out.length - 1].ms)) out.push({ ms: t, label: format.format(new Date(t)) });
  };
  if (step < 60_000) {
    for (let t = Math.ceil(fromMs / step) * step; t < toMs; t += step) push(t);
    return out;
  }
  // Walk local wall-clock multiples of the step and map each back to UTC.
  let offset = zoneOffsetMs(fromMs, timeZone);
  for (let wall = Math.ceil((fromMs + offset) / step) * step, guard = 0; guard < 1000; wall += step, guard++) {
    let t = wall - offset;
    const actual = zoneOffsetMs(t, timeZone);
    if (actual !== offset) {
      t = wall - actual;
      offset = actual;
    }
    if (t >= toMs) break;
    push(t);
  }
  return out;
}

/** HH:MM:SS in `timeZone`. */
export function clock(ms: number, timeZone?: string): string {
  return new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZone }).format(new Date(ms));
}

/** A visible time window: its width and right edge (null while following live). */
export interface TimeView {
  span: number;
  endMs: number | null;
  follow: boolean;
}

/**
 * Zoom by `factor` around the fraction `frac` of the plot width, the span
 * clamped to [minSpan, maxSpan]. While following live, the right edge stays
 * on the newest data.
 */
export function zoomView<V extends TimeView>(v: V, factor: number, frac: number, minSpan: number, maxSpan: number): V {
  const span = Math.min(maxSpan, Math.max(minSpan, v.span * factor));
  if (v.follow || v.endMs === null) return { ...v, span };
  const anchor = v.endMs - v.span + frac * v.span;
  return { ...v, span, endMs: anchor + (1 - frac) * span };
}

/**
 * Fraction of the plot width under `clientX`, for an svg element drawn in a
 * viewBox `width` wide whose plot area starts at `left` and is `plotWidth` wide.
 */
export function plotFraction(el: Element | null, clientX: number, width: number, left: number, plotWidth: number): number {
  const rect = el?.getBoundingClientRect();
  if (!rect || rect.width === 0) return 0;
  const vx = ((clientX - rect.left) / rect.width) * width;
  return Math.min(1, Math.max(0, (vx - left) / plotWidth));
}
