// Coverage for the Host allowlist (JAM-176): DNS rebinding makes an
// attacker's page same-origin with the relay, so the JAM-151 Sec-Fetch-Site
// check can't stop it — only the Host header still names the attacker's
// domain.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { isAllowedHost, parseAllowedHosts } from '@/lib/host-allowlist';
import { middleware } from '@/middleware';

describe('isAllowedHost', () => {
  it.each(['127.0.0.1:3000', 'localhost:3000', 'LOCALHOST:3000', 'localhost', 'localhost.:3000', '[::1]:3000', 'localhost:8443'])(
    'allows loopback Host %s',
    (host) => {
      expect(isAllowedHost(host, [])).toBe(true);
    },
  );

  it.each([
    'attacker.example:3000', // the DNS-rebinding case
    'attacker.example',
    'localhost.attacker.example:3000',
    '127.0.0.1.nip.io:3000',
    '192.168.1.20:3000',
    '',
  ])('rejects foreign Host %s', (host) => {
    expect(isAllowedHost(host, [])).toBe(false);
  });

  it('rejects a missing Host header', () => {
    expect(isAllowedHost(null, [])).toBe(false);
  });

  it('allows an operator-configured LAN hostname, on any port, case-insensitively', () => {
    const extra = parseAllowedHosts(' MyMac.local , other.lan ');
    expect(isAllowedHost('mymac.local', extra)).toBe(true);
    expect(isAllowedHost('MyMac.local:443', extra)).toBe(true);
    expect(isAllowedHost('other.lan', extra)).toBe(true);
    expect(isAllowedHost('attacker.example', extra)).toBe(false);
  });

  it('drops malformed ALLOWED_HOSTS entries instead of truncating them to a different name', () => {
    // A URL or an unbracketed IPv6 address used to be cut at its first ':'
    // (`https://mymac.local` -> `https`, `fe80::1` -> `fe80`), silently
    // allowing a name the operator never meant.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(parseAllowedHosts('https://mymac.local,fe80::1,mymac.local/x,good.lan,[fe80::1]:443')).toEqual([
      'good.lan',
      'fe80::1',
    ]);
    expect(warn).toHaveBeenCalledTimes(3);
    warn.mockRestore();
  });

  it('parses an unset or empty ALLOWED_HOSTS to no extra hosts', () => {
    expect(parseAllowedHosts(undefined)).toEqual([]);
    expect(parseAllowedHosts('')).toEqual([]);
    expect(parseAllowedHosts(' , ')).toEqual([]);
  });
});

describe('middleware Host enforcement', () => {
  const original = process.env.ALLOWED_HOSTS;
  afterEach(() => {
    if (original === undefined) delete process.env.ALLOWED_HOSTS;
    else process.env.ALLOWED_HOSTS = original;
  });

  function request(path: string, host: string, init: { method?: string } = {}): NextRequest {
    return new NextRequest(`http://127.0.0.1:3000${path}`, { method: init.method ?? 'GET', headers: { host } });
  }

  it.each([
    ['/', 'GET'],
    ['/api/stream', 'GET'],
    ['/api/control', 'POST'],
  ])('rejects a rebinding request to %s with 421', (path, method) => {
    const response = middleware(request(path, 'attacker.example:3000', { method }));
    expect(response.status).toBe(421);
  });

  it('lets a loopback request through with the CSP header set', () => {
    const response = middleware(request('/api/control', '127.0.0.1:3000', { method: 'POST' }));
    expect(response.status).toBe(200);
    expect(response.headers.get('content-security-policy')).toContain("default-src 'self'");
  });

  it('honours ALLOWED_HOSTS at request time', () => {
    process.env.ALLOWED_HOSTS = 'mymac.local';
    expect(middleware(request('/', 'mymac.local')).status).toBe(200);
    expect(middleware(request('/', 'attacker.example')).status).toBe(421);
  });
});
