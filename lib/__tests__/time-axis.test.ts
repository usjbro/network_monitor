// KAN-129 plan P6: the time-axis helpers moved out of lib/io-graph.ts are
// the same functions there, and zoomView keeps its anchor and clamps.
import { describe, expect, it } from 'vitest';
import * as io from '../io-graph';
import { clock, ticks, zoneOffsetMs, zoomView } from '../time-axis';

describe('time-axis', () => {
  it('is what lib/io-graph.ts re-exports', () => {
    expect(io.ticks).toBe(ticks);
    expect(io.clock).toBe(clock);
    expect(io.zoneOffsetMs).toBe(zoneOffsetMs);
  });

  it('zooms around the pointer and clamps the span', () => {
    const v = { span: 10_000, endMs: 100_000, follow: false };
    // Zoom in 2× at the left quarter: the time under the pointer stays put.
    const z = zoomView(v, 0.5, 0.25, 1000, 60_000);
    expect(z.span).toBe(5000);
    expect(z.endMs! - z.span + 0.25 * z.span).toBe(v.endMs - v.span + 0.25 * v.span);
    expect(zoomView(v, 0.01, 0.5, 1000, 60_000).span).toBe(1000);
    expect(zoomView(v, 100, 0.5, 1000, 60_000).span).toBe(60_000);
  });

  it('keeps the right edge live while following', () => {
    const v = { span: 10_000, endMs: null, follow: true, extra: 'kept' };
    expect(zoomView(v, 2, 0.1, 1000, 60_000)).toEqual({ span: 20_000, endMs: null, follow: true, extra: 'kept' });
  });
});
