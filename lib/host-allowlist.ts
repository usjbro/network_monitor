// Host-header allowlist for every request the relay serves (JAM-176).
//
// Why: under DNS rebinding an attacker's domain re-resolves to 127.0.0.1,
// so the browser treats the attacker's page as same-origin with this app.
// That defeats lib/same-origin.ts (Sec-Fetch-Site reads `same-origin`) and
// lets the page read /api/stream — including decrypted_payload events,
// since a request without x-mtls-verified counts as direct loopback (see
// lib/mtls-gate.ts). The one thing the attacker can't change is the Host
// header: the browser always sends the attacker's own hostname. So only
// loopback names, plus hostnames the operator explicitly lists for the
// Caddy LAN front door (deploy/README.md step 5), are served.

/** Loopback names a browser can only reach this app by on purpose. */
const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1']);

/** `ALLOWED_HOSTS`: comma-separated extra hostnames, ports ignored. */
export function parseAllowedHosts(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((h) => normalizeHostname(h.trim()))
    .filter((h) => h.length > 0);
}

/** Lowercases and strips any port, IPv6 brackets, and a trailing dot. */
function normalizeHostname(host: string): string {
  let name = host.toLowerCase();
  if (name.startsWith('[')) {
    const end = name.indexOf(']');
    name = end === -1 ? '' : name.slice(1, end);
  } else {
    const colon = name.indexOf(':');
    if (colon !== -1) name = name.slice(0, colon);
  }
  return name.endsWith('.') ? name.slice(0, -1) : name;
}

export function isAllowedHost(hostHeader: string | null, extraHosts: string[]): boolean {
  if (!hostHeader) return false;
  const name = normalizeHostname(hostHeader);
  if (name.length === 0) return false;
  return LOOPBACK_HOSTNAMES.has(name) || extraHosts.includes(name);
}
