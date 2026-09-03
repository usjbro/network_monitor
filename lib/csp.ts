import { isDirectLoopbackAccess } from './mtls-gate';

// Builds this app's Content-Security-Policy header value. Kept separate
// from middleware.ts so the dev-only 'unsafe-eval' carve-out's gating logic
// is directly unit-testable without needing to construct a real
// NextRequest.
export function buildCsp(nonce: string, request: Request): string {
  // Next.js dev mode's Fast Refresh/HMR client (react-refresh-utils'
  // runtime.js) evaluates code via eval() to apply hot updates — without
  // 'unsafe-eval' here, that throws an uncaught EvalError partway through
  // the webpack entry chunk on every `next dev` page load, which can abort
  // execution before app-level mount-time code (e.g. opening the
  // capture-agent EventSource) ever runs.
  //
  // Gated on BOTH conditions below, not NODE_ENV alone:
  // - `NODE_ENV === 'development'` (allow-listed, not `!== 'production'`
  //   deny-listed) so any unexpected/stray NODE_ENV value fails closed to
  //   the strict policy, rather than silently shipping 'unsafe-eval'
  //   whenever NODE_ENV just isn't exactly 'production'.
  // - `isDirectLoopbackAccess` (lib/mtls-gate.ts) — deploy/README.md's
  //   "Running" section documents `npm run dev` as an accepted alternative
  //   to `npm run start` for the actual LAN-facing, mTLS-authenticated
  //   session, so NODE_ENV alone can't distinguish "someone browsing
  //   loopback dev mode" from "real authenticated LAN traffic hitting the
  //   same dev server." Note this is *stricter* than
  //   lib/decrypted-payload-gate.ts's isDecryptedPayloadAllowed, which also
  //   shares this same primitive: that one additionally allows a
  //   verified-proxied request (`x-mtls-verified: true`) through, but eval
  //   stays off even for a *verified* proxied request here — there's no
  //   reason a real LAN client would ever need it.
  const isDirectLoopbackDev = process.env.NODE_ENV === 'development' && isDirectLoopbackAccess(request);

  return [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDirectLoopbackDev ? ` 'unsafe-eval'` : ''}`,
    `style-src 'self'`,
    `img-src 'self' data:`,
    `connect-src 'self'`,
    `frame-ancestors 'none'`,
    `base-uri 'self'`,
    `object-src 'none'`,
  ].join('; ');
}
