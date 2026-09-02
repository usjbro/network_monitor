// lib/enrichment/scope-filter.ts

export function ipToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

export function cidrContains(cidr: string, ip: string): boolean {
  const [base, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const baseInt = ipToInt(base);
  const ipInt = ipToInt(ip);
  if (baseInt === null || ipInt === null || !Number.isInteger(bits)) return false;
  if (bits === 0) return true;
  const mask = bits >= 32 ? 0xffffffff : (~0 << (32 - bits)) >>> 0;
  return (baseInt & mask) === (ipInt & mask);
}

// IPv4 ranges that can never resolve to a meaningful RIR/registrar record —
// short-circuited before any lookup is even queued (spec Components §1).
const IPV4_RESERVED: string[] = [
  '10.0.0.0/8',       // RFC1918
  '172.16.0.0/12',    // RFC1918
  '192.168.0.0/16',   // RFC1918
  '127.0.0.0/8',       // loopback
  '169.254.0.0/16',    // link-local
  '100.64.0.0/10',     // CGNAT
  '224.0.0.0/4',        // multicast
];

function isIPv6PrivateOrReserved(ip: string): boolean {
  const lower = ip.toLowerCase();
  // IPv4-mapped IPv6 (::ffff:a.b.c.d, or the rarer ::a.b.c.d form) embeds a
  // real IPv4 address in the low 32 bits — unwrap it and re-check against
  // the IPv4 reserved list, so e.g. "::ffff:192.168.1.1" is still caught as
  // private rather than falling through as if it were a public v6 address.
  const mappedMatch = lower.match(/^::(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (mappedMatch) {
    return IPV4_RESERVED.some((cidr) => cidrContains(cidr, mappedMatch[1]));
  }
  return (
    lower === '::1' ||
    lower.startsWith('fe80:') ||       // link-local
    lower.startsWith('fc') || lower.startsWith('fd') || // unique local
    lower.startsWith('ff')             // multicast
  );
}

export function isPrivateOrReserved(ip: string): boolean {
  if (ip.includes(':')) return isIPv6PrivateOrReserved(ip);
  return IPV4_RESERVED.some((cidr) => cidrContains(cidr, ip));
}
