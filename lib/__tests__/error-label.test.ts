// lib/__tests__/error-label.test.ts
import { describe, expect, it } from 'vitest';
import { errorLabel } from '../enrichment/error-label';

describe('errorLabel', () => {
  it.each([
    ['a code', Object.assign(new Error('198.51.100.7'), { code: 'ECONNRESET' }), 'ECONNRESET'],
    ['a name', new RangeError('198.51.100.7'), 'RangeError'],
    ['a cause', new TypeError('x', { cause: Object.assign(new Error('y'), { code: 'ENOTFOUND' }) }), 'TypeError (ENOTFOUND)'],
    ['an object that is not an error', { code: 'ECONNRESET', name: 'x' }, 'object'],
    ['an error named like an address', Object.assign(new Error('x'), { name: '198.51.100.7' }), 'Error'],
    ['an error with an IPv6 code', Object.assign(new Error('x'), { code: '2001:db8::1' }), 'Error'],
    ['an error with a very long code', Object.assign(new Error('x'), { code: 'E'.repeat(100) }), 'Error'],
    ['a string', '198.51.100.7', 'string'],
    ['null', null, 'object'],
  ])('labels %s', (_name, err, expected) => {
    expect(errorLabel(err)).toBe(expected);
  });

  it('never throws', () => {
    const hostile = new Error('x');
    Object.defineProperty(hostile, 'code', { get() { throw new Error('198.51.100.7'); } });
    expect(errorLabel(hostile)).toBe('unlabelled error');
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    expect(errorLabel(revoked.proxy)).toBe('unlabelled error');
  });

  it('takes one argument', () => {
    expect(errorLabel.length).toBe(1);
    const err = new Error('a', { cause: new Error('b', { cause: new Error('c') }) });
    expect([err, err, err].map(errorLabel)).toEqual(Array(3).fill('Error (Error (Error))'));
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
