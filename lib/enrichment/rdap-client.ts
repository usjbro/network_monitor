// lib/enrichment/rdap-client.ts

export type RdapResult =
  | { ok: true; json: unknown }
  | { ok: false; reason: 'timeout' | 'too_large' | 'http_error' | 'redirect' | 'circuit_open' | 'backoff' | 'network'; status?: number };

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
}
