// JAM-15: request/response links and service-time display, read from the
// derived fields the agent appends to a matched response
// (`dns.time_us`/`http.time_us`, and `*.response_to` when the request was
// itself sent as a packet event). See docs/wire-protocol.md.
import type { PacketFrame } from './types';

export interface ResponseLink {
  protocol: 'DNS' | 'HTTP';
  serviceTimeUs: number;
  // Absent when the request was never sent to the UI (the agent's
  // packet-event rate limit skipped it): there is nothing to link to.
  requestId?: string;
}

const PROTOCOLS = [
  { prefix: 'dns', protocol: 'DNS' },
  { prefix: 'http', protocol: 'HTTP' },
] as const;

export function responseLinkOf(packet: PacketFrame): ResponseLink | null {
  for (const { prefix, protocol } of PROTOCOLS) {
    const time = packet.fields.find((f) => f.path === `${prefix}.time_us`);
    if (time && typeof time.value === 'number') {
      const requestTo = packet.fields.find((f) => f.path === `${prefix}.response_to`);
      return {
        protocol,
        serviceTimeUs: time.value,
        requestId: typeof requestTo?.value === 'string' ? requestTo.value : undefined,
      };
    }
  }
  return null;
}

// The buffered response that answered `requestId`, if it's still buffered.
export function answeredBy(requestId: string, packets: PacketFrame[]): PacketFrame | undefined {
  return packets.find((p) => responseLinkOf(p)?.requestId === requestId);
}

// Microseconds below 1 ms, so a cached DNS answer doesn't read as "0 ms".
export function formatServiceTime(us: number): string {
  if (us < 1_000) return `${us} µs`;
  if (us < 1_000_000) return `${(us / 1_000).toFixed(1)} ms`;
  return `${(us / 1_000_000).toFixed(2)} s`;
}
