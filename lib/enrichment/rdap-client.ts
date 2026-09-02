// lib/enrichment/rdap-client.ts
import { isAllowedReferralHost } from './referral-allowlist';

export type RdapResult =
  | { ok: true; json: unknown }
  | { ok: false; reason: 'timeout' | 'too_large' | 'http_error' | 'redirect' | 'circuit_open' | 'backoff' | 'network'; status?: number };

// Result of a registry fetch followed by an optional registrar referral
// (Task 13, extended tier). Only ever adds `referralFollowed` on a
// successful outcome — a failure from the *initial* registry fetch is
// returned completely unchanged (no extra fields), since no referral was
// ever attempted or even considered.
export type RdapReferralResult = RdapResult | { ok: true; json: unknown; referralFollowed: boolean };

// Pulls candidate referral URLs out of an RDAP response body per the
// RFC 7480-style conventions the spec calls out: top-level `links` entries
// with `rel: 'related'`, and the same shape nested under `notices[].links`.
// This reads *untrusted* third-party response JSON — same defensive posture
// as lib/enrichment-mapping.ts's extract* functions: never throw, tolerate
// any shape.
function extractReferralCandidates(json: unknown): string[] {
  const out: string[] = [];
  try {
    const obj = json as Record<string, unknown>;
    if (!obj || typeof obj !== 'object') return out;

    const collectFrom = (links: unknown) => {
      if (!Array.isArray(links)) return;
      for (const link of links) {
        const rel = (link as Record<string, unknown>)?.rel;
        const href = (link as Record<string, unknown>)?.href;
        if (rel === 'related' && typeof href === 'string') out.push(href);
      }
    };

    collectFrom(obj.links);
    const notices = Array.isArray(obj.notices) ? obj.notices : [];
    for (const notice of notices) {
      collectFrom((notice as Record<string, unknown>)?.links);
    }
  } catch {
    // fall through — return whatever was collected before the failure
  }
  return out;
}

const REQUEST_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 256 * 1024;
const BACKOFF_START_MS = 30_000;
const BACKOFF_CAP_MS = 30 * 60_000;
const BREAKER_WINDOW_MS = 10 * 60_000;
const BREAKER_TRIP_COUNT = 3;
const BREAKER_COOLDOWN_MS = 60 * 60_000;

export function computeBackoffDelayMs(consecutive429s: number, retryAfterSec?: number): number {
  const exp = BACKOFF_START_MS * Math.pow(2, Math.max(0, consecutive429s - 1));
  const capped = Math.min(exp, BACKOFF_CAP_MS);
  const retryAfterMs = retryAfterSec ? retryAfterSec * 1000 : 0;
  return Math.max(capped, retryAfterMs);
}

interface HostState {
  consecutive429s: number;
  backoffUntil: number;
  trip429Timestamps: number[];
  circuitOpenUntil: number;
}

export class RdapClient {
  private hostState = new Map<string, HostState>();

  constructor(
    private fetchImpl: typeof fetch = fetch,
    private now: () => number = Date.now,
  ) {}

  private stateFor(host: string): HostState {
    let s = this.hostState.get(host);
    if (!s) {
      s = { consecutive429s: 0, backoffUntil: 0, trip429Timestamps: [], circuitOpenUntil: 0 };
      this.hostState.set(host, s);
    }
    return s;
  }

  async fetch(url: string): Promise<RdapResult> {
    const host = new URL(url).host;
    const state = this.stateFor(host);
    const now = this.now();
    if (now < state.circuitOpenUntil) return { ok: false, reason: 'circuit_open' };
    if (now < state.backoffUntil) return { ok: false, reason: 'backoff' };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await this.fetchImpl(url, {
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': 'osi-netstriker-enrichment/1.0' },
      });

      if ((response as Response & { type?: string }).type === 'opaqueredirect') {
        // Per the Fetch spec, an opaqueredirect response always carries status 0 —
        // there is no usable status code to report here.
        return { ok: false, reason: 'redirect', status: undefined };
      }
      if (response.status >= 300 && response.status < 400) {
        return { ok: false, reason: 'redirect', status: response.status };
      }

      if (response.status === 429) {
        state.consecutive429s += 1;
        state.trip429Timestamps = [...state.trip429Timestamps, now].filter((t) => now - t <= BREAKER_WINDOW_MS);
        const retryAfterHeader = response.headers.get('retry-after');
        const retryAfterSec = retryAfterHeader ? Number(retryAfterHeader) : undefined;
        state.backoffUntil = now + computeBackoffDelayMs(state.consecutive429s, retryAfterSec);
        if (state.trip429Timestamps.length >= BREAKER_TRIP_COUNT) {
          state.circuitOpenUntil = now + BREAKER_COOLDOWN_MS;
        }
        return { ok: false, reason: 'http_error', status: 429 };
      }

      state.consecutive429s = 0;

      if (!response.ok) {
        return { ok: false, reason: 'http_error', status: response.status };
      }

      const reader = response.body?.getReader();
      if (!reader) return { ok: false, reason: 'network' };
      let received = 0;
      const chunks: Uint8Array[] = [];
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > MAX_RESPONSE_BYTES) {
          controller.abort();
          return { ok: false, reason: 'too_large' };
        }
        chunks.push(value);
      }
      const text = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
      return { ok: true, json: JSON.parse(text) };
    } catch {
      if (controller.signal.aborted) return { ok: false, reason: 'timeout' };
      return { ok: false, reason: 'network' };
    } finally {
      clearTimeout(timer);
    }
  }

  // Extended tier (Task 13): thin gTLD registries (e.g. .com/.net via
  // Verisign) respond to a domain RDAP query with a registry-level stub
  // that refers the caller to the registrar's own RDAP service for the
  // actual registrant. This method fetches `url`, and — only if the
  // response carries a `rel: 'related'` referral link whose host is on the
  // reviewed registrar allowlist (lib/enrichment/referral-allowlist.ts) —
  // follows it through this same hardened `fetch` path (timeout/size-cap/
  // backoff/circuit-breaker all apply identically to the referral request).
  // A referral to any other host, including a loopback/private address, is
  // never dialed: the lookup falls back to the original registry response,
  // just marked as not having followed a referral.
  async fetchWithReferral(url: string): Promise<RdapReferralResult> {
    const result = await this.fetch(url);
    if (!result.ok) return result;

    const candidates = extractReferralCandidates(result.json);
    const referralUrl = candidates.find((u) => isAllowedReferralHost(u));
    if (!referralUrl) return { ...result, referralFollowed: false };

    const referralResult = await this.fetch(referralUrl);
    if (referralResult.ok) return { ...referralResult, referralFollowed: true };

    // The registrar referral itself failed (timeout/5xx/etc) — fall back to
    // the registry's own response rather than failing the whole lookup;
    // it typically has no registrant entity, which resolves to
    // "Unavailable" downstream (Task 15), not an error.
    return { ...result, referralFollowed: false };
  }
}
