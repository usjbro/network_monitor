// Coverage for lib/osi-engine.ts's pure functions/data: formatSpeed,
// formatBytes, STATIC_LAYER_INFO, and THEMES. Exercised transitively by
// many component tests already, but had no dedicated unit test.
import { describe, expect, it } from 'vitest';
import { STATIC_LAYER_INFO, THEMES, formatBytes, formatSpeed } from '@/lib/osi-engine';
import { TerminalTheme } from '@/lib/types';

describe('formatSpeed', () => {
  it.each([
    [0, '0 B/s'],
    [1023, '1023 B/s'],
    [1024, '1.0 KB/s'],
    [1024 * 1024 - 1, '1024.0 KB/s'],
    [1024 * 1024, '1.00 MB/s'],
    [1024 * 1024 * 1024 - 1, '1024.00 MB/s'],
    [1024 * 1024 * 1024, '1.00 GB/s'],
  ])('formats %i bytes/sec as %s', (input, expected) => {
    expect(formatSpeed(input)).toBe(expected);
  });
});

describe('formatBytes', () => {
  it.each([
    [0, '0 B'],
    [1023, '1023 B'],
    [1024, '1.0 KB'],
    [1024 * 1024 - 1, '1024.0 KB'],
    [1024 * 1024, '1.0 MB'],
    [1024 * 1024 * 1024 - 1, '1024.0 MB'],
    [1024 * 1024 * 1024, '1.00 GB'],
  ])('formats %i bytes as %s', (input, expected) => {
    expect(formatBytes(input)).toBe(expected);
  });
});

describe('STATIC_LAYER_INFO', () => {
  it('has an entry for every OSI layer 1 through 7', () => {
    expect(Object.keys(STATIC_LAYER_INFO).map(Number).sort()).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it('gives every layer a non-empty protocols list', () => {
    for (const info of Object.values(STATIC_LAYER_INFO)) {
      expect(info.protocols.length).toBeGreaterThan(0);
    }
  });

  it('spot-checks the expected PDU name per layer', () => {
    expect(STATIC_LAYER_INFO[4].pdu).toBe('Segment');
    expect(STATIC_LAYER_INFO[3].pdu).toBe('Packet');
    expect(STATIC_LAYER_INFO[2].pdu).toBe('Frame');
    expect(STATIC_LAYER_INFO[1].pdu).toBe('Bit');
  });
});

describe('THEMES', () => {
  const requiredStringFields: (keyof (typeof THEMES)['matrix'])[] = [
    'id',
    'name',
    'bg',
    'text',
    'border',
    'accent',
    'secondaryAccent',
    'highlight',
    'cardBg',
    'promptUser',
    'promptHost',
    'promptPath',
  ];

  it('gives every theme every required non-empty string field', () => {
    for (const key of Object.keys(THEMES) as TerminalTheme[]) {
      const theme = THEMES[key];
      for (const field of requiredStringFields) {
        expect(typeof theme[field]).toBe('string');
        expect((theme[field] as string).length).toBeGreaterThan(0);
      }
    }
  });

  it("keys each theme's id to match its own record key", () => {
    for (const key of Object.keys(THEMES) as TerminalTheme[]) {
      expect(THEMES[key].id).toBe(key);
    }
  });
});
