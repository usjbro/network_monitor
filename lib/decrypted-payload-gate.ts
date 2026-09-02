// Gates `decrypted_payload` events (Tier B — opt-in decrypted TLS content)
// separately from every other event type on the SSE stream: those events
// are refused outright unless the request is either (a) direct loopback
// dev usage with no reverse proxy in front at all (no `x-mtls-verified`
// header present — the capture agent's own `127.0.0.1:9990` bind and the
// stream route's Next.js `-H 127.0.0.1` bind are the only gate in that
// case), or (b) proxied through deploy/Caddyfile's mTLS reverse proxy AND
// carrying a verified client certificate. A present-but-false header
// (proxied, but the client cert didn't verify) is refused — Caddy's
// `client_auth require_and_verify` would already reject the connection
// before it got this far in practice, but this is a defense-in-depth check
// on the application side, not the only one. See docs/wire-protocol.md's
// `decrypted_payload` section.
//
// Kept in its own module (not exported directly from
// app/api/stream/route.ts) because Next.js's typed-routes build step
// rejects any named export from a route.ts file other than the
// recognized HTTP-method handlers and a small fixed set of config
// exports — `npm run build` fails type checking otherwise
// ("OmitWithTag<...> does not satisfy the constraint '{ [x: string]:
// never }'"). This module is imported (not re-exported) by
// app/api/stream/route.ts, and imported directly by its own test.
export function isDecryptedPayloadAllowed(request: Request): boolean {
  const header = request.headers.get('x-mtls-verified');
  if (header === null) return true; // no Caddy in front — direct loopback access
  return header === 'true';
}
