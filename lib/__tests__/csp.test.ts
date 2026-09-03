import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildCsp } from '@/lib/csp';

function fakeRequest(headers: Record<string, string> = {}) {
  return { headers: new Headers(headers) } as unknown as Request;
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('buildCsp', () => {
  it('includes unsafe-eval for direct loopback dev-mode access (no proxy header)', () => {
    vi.stubEnv('NODE_ENV', 'development');
    const csp = buildCsp('nonce123', fakeRequest());
    expect(csp).toContain(`'unsafe-eval'`);
  });

  // deploy/README.md documents `npm run dev` as an accepted alternative to
  // `npm run start` for the actual LAN-facing, Caddy-proxied session — so a
  // request that reaches this dev server via Caddy must stay strict even
  // though NODE_ENV is 'development', matching the mTLS-verified case.
  it('excludes unsafe-eval when proxied through Caddy with a verified cert, even in dev mode', () => {
    vi.stubEnv('NODE_ENV', 'development');
    const csp = buildCsp('nonce123', fakeRequest({ 'x-mtls-verified': 'true' }));
    expect(csp).not.toContain('unsafe-eval');
  });

  it('excludes unsafe-eval when proxied through Caddy without a verified cert, even in dev mode', () => {
    vi.stubEnv('NODE_ENV', 'development');
    const csp = buildCsp('nonce123', fakeRequest({ 'x-mtls-verified': 'false' }));
    expect(csp).not.toContain('unsafe-eval');
  });

  it('excludes unsafe-eval in production, direct loopback', () => {
    vi.stubEnv('NODE_ENV', 'production');
    const csp = buildCsp('nonce123', fakeRequest());
    expect(csp).not.toContain('unsafe-eval');
  });

  // Allow-listed on '=== development', not deny-listed on '!== production':
  // an unexpected/stray NODE_ENV value (typo, a leaked CI/test value, an
  // unset var) must fail closed to the strict policy, not silently ship
  // unsafe-eval just because it happens not to equal the literal string
  // 'production'.
  it('excludes unsafe-eval for an unrecognized NODE_ENV value (fails closed)', () => {
    vi.stubEnv('NODE_ENV', 'staging');
    const csp = buildCsp('nonce123', fakeRequest());
    expect(csp).not.toContain('unsafe-eval');
  });

  it('embeds the given nonce in script-src', () => {
    vi.stubEnv('NODE_ENV', 'production');
    const csp = buildCsp('abc123', fakeRequest());
    expect(csp).toContain(`'nonce-abc123'`);
  });

  it('keeps every other directive unchanged regardless of dev/prod', () => {
    vi.stubEnv('NODE_ENV', 'production');
    const csp = buildCsp('n', fakeRequest());
    expect(csp).toContain(`default-src 'self'`);
    expect(csp).toContain(`style-src 'self'`);
    expect(csp).toContain(`img-src 'self' data:`);
    expect(csp).toContain(`connect-src 'self'`);
    expect(csp).toContain(`frame-ancestors 'none'`);
    expect(csp).toContain(`base-uri 'self'`);
    expect(csp).toContain(`object-src 'none'`);
  });
});
