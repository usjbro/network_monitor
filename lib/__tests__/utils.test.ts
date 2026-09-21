// Minimal smoke coverage for cn() — a thin clsx+tailwind-merge wrapper;
// both dependencies are independently tested upstream, so this only
// proves the wrapper composes them correctly.
import { describe, expect, it } from 'vitest';
import { cn } from '@/lib/utils';

describe('cn', () => {
  it('joins truthy class names and drops falsy ones', () => {
    expect(cn('a', false && 'b', 'c')).toBe('a c');
  });
});
