// lib/enrichment/reverse-dns.ts
//
// Extended tier (spec §4 "Reverse DNS + domain registrant"): a thin wrapper
// around Node's built-in dns.promises.reverse() (no new dependency) used to
// populate the connection's `remoteHostname` as the prerequisite for a
// domain-level RDAP/WHOIS registrant lookup (Task 13/14). Deliberately a
// standalone module — the `resolveFn` injection point lets callers (and
// tests) substitute the resolver without touching global `node:dns` state.
import { promises as dns } from 'node:dns';

export async function reverseDnsLookup(
  ip: string,
  opts: { timeoutMs?: number; resolveFn?: typeof dns.reverse } = {},
): Promise<string | null> {
  const resolveFn = opts.resolveFn ?? dns.reverse;
  const timeoutMs = opts.timeoutMs ?? 10_000;

  try {
    const hostnames = await Promise.race([
      resolveFn(ip),
      new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error('reverse-dns timeout')), timeoutMs)),
    ]);
    return hostnames[0] ?? null;
  } catch {
    // Any failure (no PTR record, resolver error, timeout) is a normal,
    // expected outcome, not an error to surface — spec's Error handling
    // section: "remoteHostname stays unpopulated ... not surfaced as an error".
    return null;
  }
}
