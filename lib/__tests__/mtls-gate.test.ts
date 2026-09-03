import { describe, expect, it } from 'vitest';
import { isDirectLoopbackAccess } from '@/lib/mtls-gate';

function fakeRequest(headers: Record<string, string> = {}) {
  return { headers: new Headers(headers) } as unknown as Request;
}

describe('isDirectLoopbackAccess', () => {
  it('is true when there is no x-mtls-verified header at all (no Caddy in front)', () => {
    expect(isDirectLoopbackAccess(fakeRequest())).toBe(true);
  });

  it('is false when proxied through Caddy with a verified client cert', () => {
    expect(isDirectLoopbackAccess(fakeRequest({ 'x-mtls-verified': 'true' }))).toBe(false);
  });

  it('is false when proxied through Caddy without a verified client cert', () => {
    expect(isDirectLoopbackAccess(fakeRequest({ 'x-mtls-verified': 'false' }))).toBe(false);
  });
});
