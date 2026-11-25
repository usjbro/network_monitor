// lib/__tests__/error-label.test.ts
import { describe, expect, it } from 'vitest';
import { errorLabel } from '../enrichment/error-label';

describe('errorLabel', () => {
  it.each([
    ['a code', Object.assign(new Error('198.51.100.7'), { code: 'ECONNRESET' }), 'ECONNRESET'],
    ['a name', new RangeError('198.51.100.7'), 'RangeError'],
    ['a cause', new TypeError('x', { cause: Object.assign(new Error('y'), { code: 'ENOTFOUND' }) }), 'TypeError (ENOTFOUND)'],
    ['an object with a code', { code: 'ECONNRESET', message: '198.51.100.7' }, 'ECONNRESET'],
    ['an object with neither', { message: '198.51.100.7' }, 'object'],
    ['a string', '198.51.100.7', 'string'],
    ['null', null, 'object'],
  ])('labels %s', (_name, err, expected) => {
    expect(errorLabel(err)).toBe(expected);
  });

  it('stops on a cause chain that loops or runs deep', () => {
    const a = new Error('a');
    const b = new TypeError('b', { cause: a });
    (a as { cause?: unknown }).cause = b;
    expect(errorLabel(a)).toBe('Error (TypeError (Error (…)))');
    let deep: Error = new Error('end');
    for (let i = 0; i < 100_000; i++) deep = new Error('x', { cause: deep });
    expect(errorLabel(deep)).toBe('Error (Error (Error (…)))');
  });
});
