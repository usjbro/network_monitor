// KAN-129 Task 2 (spec D5): admission is per reply type: at most N requests
// in flight relay-wide, one per key, each holding a byte reservation until
// its lease is released.
import { describe, expect, it } from 'vitest';
import { Admission } from '../agent-admission';

describe('Admission', () => {
  it('admits up to maxInFlight distinct keys, then refuses', () => {
    const admission = new Admission({ maxInFlight: 4, reservationBytes: 256 * 1024 });
    const leases = ['a', 'b', 'c', 'd'].map((key) => admission.tryAcquire(key));
    expect(leases.every(Boolean)).toBe(true);
    expect(admission.tryAcquire('e')).toBeNull();
    expect(admission.inFlight()).toBe(4);
    expect(admission.reservedBytes()).toBe(1024 * 1024);
  });

  it('admits one request per key', () => {
    const admission = new Admission({ maxInFlight: 4, reservationBytes: 1 });
    const first = admission.tryAcquire('conn');
    expect(first).not.toBeNull();
    expect(admission.tryAcquire('conn')).toBeNull();
    first!.release();
    expect(admission.tryAcquire('conn')).not.toBeNull();
  });

  it('release is idempotent and frees exactly one slot', () => {
    const admission = new Admission({ maxInFlight: 2, reservationBytes: 10 });
    const a = admission.tryAcquire('a')!;
    admission.tryAcquire('b');
    a.release();
    a.release();
    expect(admission.inFlight()).toBe(1);
    expect(admission.reservedBytes()).toBe(10);
    expect(admission.tryAcquire('c')).not.toBeNull();
    expect(admission.tryAcquire('d')).toBeNull();
  });

  it('a stale lease cannot release a newer holder of the same key', () => {
    const admission = new Admission({ maxInFlight: 2, reservationBytes: 1 });
    const old = admission.tryAcquire('k')!;
    old.release();
    admission.tryAcquire('k');
    old.release();
    expect(admission.tryAcquire('k')).toBeNull();
  });
});
