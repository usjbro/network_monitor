import { NextRequest, NextResponse } from 'next/server';

// Cross-site request rejection for the app's state-changing POST routes
// (JAM-151).
//
// Why this is needed at all: none of these routes are authenticated — the
// security posture (docs/security.md) is "loopback-only, or mTLS-gated by
// Caddy". That reasoning holds for *processes* that can reach the port, but
// not for a browser: a page on any origin the operator happens to visit can
// POST to http://127.0.0.1:3000/api/control through their own browser.
// Next's `request.json()` ignores Content-Type, so a cross-origin fetch
// sending `Content-Type: text/plain` is a CORS *simple* request — no
// preflight, the request is delivered and the side effect happens. The
// attacker can't read the response, and doesn't need to: the effects are
// the point (pause the capture, retarget the BPF filter, or — since
// JAM-146 — start writing a capture file to a path of their choosing).
//
// CSP does not help here: it constrains what the attacking page may load,
// not what this endpoint accepts.

/** Sec-Fetch-Site values that are not cross-site. */
const SAFE_FETCH_SITES = new Set([
  'same-origin', // our own page's fetch
  'none', // user-initiated: address bar, bookmark, devtools
]);

/**
 * True when the request should be refused as cross-site.
 *
 * Three cases, in order:
 *
 * 1. `Sec-Fetch-Site` present — trust it. Sent by every current browser,
 *    set by the browser itself and unforgeable by page script. Only
 *    `same-origin` and `none` pass. `same-site` is deliberately rejected
 *    too: site is computed from the registrable domain and ignores port,
 *    so on loopback another local service on a different port counts as
 *    same-site, which is exactly the neighbour we don't want trusting.
 *
 * 2. No `Sec-Fetch-Site` but an `Origin` — compare it to this request's own
 *    origin and require an exact match. Covers an older browser that sends
 *    Origin but not Sec-Fetch-Site.
 *
 * 3. Neither header — allow. A browser always attaches at least one of them
 *    to a cross-origin POST, so their joint absence means the caller is not
 *    a browser: curl, a test, or `bin/osi-inspect.js`, which POSTs
 *    register_decrypt_eligible to /api/control with only a Content-Type
 *    header. Rejecting here would break that CLI while adding no protection
 *    against the browser-driven attack this guards.
 */
export function isCrossSiteRequest(request: NextRequest): boolean {
  const fetchSite = request.headers.get('sec-fetch-site');
  if (fetchSite) return !SAFE_FETCH_SITES.has(fetchSite);

  const origin = request.headers.get('origin');
  if (origin) {
    try {
      return new URL(origin).origin !== new URL(request.url).origin;
    } catch {
      // An unparseable Origin is not something to give the benefit of the
      // doubt to.
      return true;
    }
  }

  return false;
}

/**
 * Guard for the top of a state-changing route handler: returns a 403
 * response to return as-is when the request is cross-site, or `null` when
 * it may proceed.
 */
export function rejectIfCrossSite(request: NextRequest): NextResponse | null {
  if (!isCrossSiteRequest(request)) return null;
  return NextResponse.json({ error: 'cross-site request rejected' }, { status: 403 });
}
