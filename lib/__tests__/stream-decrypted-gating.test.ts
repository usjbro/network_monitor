import { describe, expect, it } from 'vitest';
import { isDecryptedPayloadAllowed } from '@/app/api/stream/route';

function fakeRequest(headers: Record<string, string>) {
  return { headers: new Headers(headers) } as unknown as Request;
}

describe('isDecryptedPayloadAllowed', () => {
  it('allows a direct request with no proxy headers (loopback dev usage)', () => {
    expect(isDecryptedPayloadAllowed(fakeRequest({}))).toBe(true);
  });

  it('allows a request proxied through Caddy with a verified client cert', () => {
    expect(isDecryptedPayloadAllowed(fakeRequest({ 'x-mtls-verified': 'true' }))).toBe(true);
  });

  it('refuses a request proxied through Caddy without a verified client cert', () => {
    expect(isDecryptedPayloadAllowed(fakeRequest({ 'x-mtls-verified': 'false' }))).toBe(false);
  });
});
