// lib/__tests__/enrichment-referral-allowlist.test.ts
import { describe, expect, it } from 'vitest';
import { isAllowedReferralHost } from '../enrichment/referral-allowlist';

describe('isAllowedReferralHost', () => {
  it('allows a known registrar RDAP host', () => {
    expect(isAllowedReferralHost('https://rdap.verisign.com/com/v1/domain/example.com')).toBe(true);
  });
  it('rejects a host not on the allowlist', () => {
    expect(isAllowedReferralHost('https://attacker.example/rdap/')).toBe(false);
  });
  it('rejects a referral pointing at a loopback/internal address — the realistic SSRF target', () => {
    expect(isAllowedReferralHost('http://127.0.0.1:9990/pause')).toBe(false);
    expect(isAllowedReferralHost('http://localhost:9990/')).toBe(false);
    expect(isAllowedReferralHost('http://[::1]:9990/')).toBe(false);
  });
  it('returns false rather than throwing on an unparseable URL', () => {
    expect(isAllowedReferralHost('not a url at all')).toBe(false);
  });
});
