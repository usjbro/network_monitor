// lib/enrichment/referral-allowlist.ts

// Small, maintained allowlist of registrar RDAP hosts for thin gTLDs that
// require a registry->registrar referral (spec Scope, "extended tier").
// Deliberately kept small — each addition is a reviewed, deliberate change,
// not grown opportunistically. A referral to any other host, including any
// loopback/private address, resolves to "unavailable" rather than being
// followed (see lib/enrichment/rdap-client.ts's referral-following code).
const REGISTRAR_RDAP_ALLOWLIST = new Set([
  'rdap.verisign.com',
  'rdap.publicinterestregistry.org',
]);

export function isAllowedReferralHost(url: string): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  return REGISTRAR_RDAP_ALLOWLIST.has(host);
}
