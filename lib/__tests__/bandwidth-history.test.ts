import { describe, expect, it } from 'vitest';
import { appendBandwidthSample } from '@/lib/bandwidth-history';

describe('bandwidth history', () => {
  it('keeps only the newest 60 samples in order without mutating previous state', () => {
    let history: number[] = [];
    for (let sample = 0; sample < 60; sample++) {
      history = appendBandwidthSample(history, sample);
    }
    const next = appendBandwidthSample(history, 60);
    expect(next).toHaveLength(60);
    expect(next).toEqual(Array.from({ length: 60 }, (_, index) => index + 1));
    expect(history).toEqual(Array.from({ length: 60 }, (_, index) => index));
  });

  it('retains measured zero and fractional rates without filling missing samples', () => {
    const first = appendBandwidthSample([], 0);
    expect(first).toEqual([0]);
    expect(appendBandwidthSample(first, 0.125)).toEqual([0, 0.125]);
    expect(first).toEqual([0]);
  });
});
