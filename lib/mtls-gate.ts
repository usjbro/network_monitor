// The single source of truth for "is this request direct loopback access,
// with no Caddy mTLS reverse proxy in front at all" — signaled by the
// absence of the x-mtls-verified header Caddy injects on every request it
// proxies (see deploy/Caddyfile). Every module that needs to tell direct
// loopback dev usage apart from traffic proxied through deploy/'s mTLS
// front door shares this one check, then applies its own policy on top —
// see lib/decrypted-payload-gate.ts (allows direct access OR a
// verified-proxied request) and lib/csp.ts (allows direct access only;
// even a verified-proxied request stays on the strict policy).
export function isDirectLoopbackAccess(request: Request): boolean {
  return request.headers.get('x-mtls-verified') === null;
}
