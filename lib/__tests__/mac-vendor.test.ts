import { describe, expect, it, vi } from 'vitest';
import { lookupMacVendor } from '@/lib/mac-vendor';

describe('offline MAC vendor lookup', () => {
  it('resolves a registered OUI without making a network request', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    expect(lookupMacVendor('00:00:0c:12:34:56')).toBe('Cisco Systems, Inc');
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it('returns unknown for unassigned, malformed, and locally administered MACs', () => {
    expect(lookupMacVendor('02:00:0c:12:34:56')).toBeUndefined();
    expect(lookupMacVendor('00:08:33:12:34:56')).toBeUndefined();
    expect(lookupMacVendor('ff:ff:ff:ff:ff:ff')).toBeUndefined();
    expect(lookupMacVendor('not-a-mac')).toBeUndefined();
  });
});
