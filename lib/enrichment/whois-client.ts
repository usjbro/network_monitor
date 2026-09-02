// lib/enrichment/whois-client.ts
import net from 'node:net';

export interface WhoisAllowlistEntry {
  matches: (target: string) => boolean;
  host: string;
  port?: number;
  fieldPatterns: Record<string, RegExp>;
}

const MAX_RESPONSE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;

// Capped at 5 entries deliberately — each one requires its own free-text
// parser maintained against adversarial/malformed input (spec Scope: "'zero
// new npm dependencies' describes the transport, not the effort"). Extend
// only via a reviewed, deliberate change, never opportunistically. This
// legacy port-43 fallback only ever runs when a domain has no RDAP service
// at all (spec §4) — most TLDs today do, so this list stays intentionally
// short.
export const WHOIS_ALLOWLIST: WhoisAllowlistEntry[] = [
  {
    matches: (target) => target.endsWith('.de'),
    host: 'whois.denic.de',
    fieldPatterns: { org: /^Organisation:\s*(.+)$/m },
  },
];

export function queryWhois(
  entry: WhoisAllowlistEntry,
  target: string,
  opts: { timeoutMs?: number } = {},
): Promise<string | null> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: entry.host, port: entry.port ?? 43 });
    let received = 0;
    const chunks: Buffer[] = [];
    let settled = false;

    const finish = (result: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };

    const timer = setTimeout(() => finish(null), timeoutMs);

    socket.on('connect', () => socket.write(`${target}\r\n`));
    socket.on('data', (chunk) => {
      received += chunk.length;
      if (received > MAX_RESPONSE_BYTES) {
        finish(null); // aborted mid-read, treated as a failure — never buffered in full
        return;
      }
      chunks.push(chunk);
    });
    socket.on('end', () => finish(Buffer.concat(chunks).toString('utf8')));
    socket.on('error', () => finish(null));
  });
}
