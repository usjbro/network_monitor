import { NextRequest, NextResponse } from 'next/server';
import { buildCsp } from '@/lib/csp';
import { isAllowedHost, parseAllowedHosts } from '@/lib/host-allowlist';

export function middleware(request: NextRequest) {
  // DNS-rebinding guard (JAM-176) — before anything else, for every path.
  if (!isAllowedHost(request.headers.get('host'), parseAllowedHosts(process.env.ALLOWED_HOSTS))) {
    return new NextResponse('Misdirected Request: host not allowed', { status: 421 });
  }

  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const csp = buildCsp(nonce, request);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set('Content-Security-Policy', csp);
  return response;
}
