import assignments from '@/lib/data/ieee-ma-l.json';

const vendors = assignments as Record<string, string>;

/** Resolve an IEEE MA-L assignment locally. Randomized, multicast, synthetic,
 * malformed, and unassigned addresses deliberately have no vendor label. */
export function lookupMacVendor(mac: string): string | undefined {
  const normalized = mac.replace(/[:-]/g, '').toUpperCase();
  if (!/^[0-9A-F]{12}$/.test(normalized) || normalized === '000000000000') return undefined;
  const firstOctet = Number.parseInt(normalized.slice(0, 2), 16);
  if ((firstOctet & 0x03) !== 0) return undefined;
  return vendors[normalized.slice(0, 6)];
}
