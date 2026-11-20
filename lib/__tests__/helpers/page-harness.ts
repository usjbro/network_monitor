// Shared harness for tests that render the whole page (app/page.tsx) and
// drive it through a fake SSE feed and a fake fetch: KAN-129's TCP graphs
// and KAN-130's flow ladder.
import { act } from '@testing-library/react';
import { vi } from 'vitest';

export class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) { FakeEventSource.instances.push(this); }
  close(): void {}
}

/** Delivers one SSE event to the page. */
export function emit(data: unknown): void {
  act(() => FakeEventSource.instances[0].onmessage!({ data: JSON.stringify(data) } as MessageEvent));
}

export const TCP = {
  id: 'Tcp-192.168.1.10:51000-93.184.216.34:443', protocol: 'HTTPS/TLS', appLayerProtocol: 'HTTPS/TLS', transportProtocol: 'TCP',
  osiStack: 'x', localAddr: '192.168.1.10', localPort: 51000, remoteAddr: '93.184.216.34', remotePort: 443,
  processName: 'Safari', pid: 1234, rxSpeed: 0, txSpeed: 0, rxBytesTotal: 0, txBytesTotal: 0,
  latencyMs: 12, packetLoss: 0, status: 'ESTABLISHED', encryption: 'TLS', sparkline: [],
};

export const T0 = 1_794_120_000_000_000;

/** A `tcp_samples` reply of `count` outbound 10-byte ACK segments from `fromIndex`, 1 ms apart. */
export function tcpSamplesReply(fromIndex: number, count: number) {
  const n = Array.from({ length: count }, (_, i) => fromIndex + i);
  return {
    type: 'tcp_samples', connectionId: TCP.id, found: true, stale: false, generation: '00000000feedbeef:1', handshakeSeen: true,
    windowScale: null, seqBase: { outbound: 0, inbound: 0 }, relativeTo: 'isn', firstIndex: 0, nextIndex: fromIndex + count, more: false, droppedOlder: 0,
    samples: {
      tUs: n.map((i) => (i === fromIndex ? T0 + i * 1000 : 1000)), seq: n.map((i) => i * 10), ack: n.map(() => 0), win: n.map(() => 100),
      len: n.map(() => 10), flags: n.map(() => 16), mark: n.map(() => 1), rttUs: n.map(() => 0),
    },
  };
}

export interface SamplesRequest { connectionId: string; generation?: string; fromIndex: number }
type FakeResponse = { ok: boolean; status: number; json: () => Promise<unknown> };

/**
 * Installs the fake EventSource, a fetch that hands `/api/tcp-samples`
 * bodies to `onSamples` (recording each in `calls`), and a matchMedia stub.
 * Call `restore` after each test.
 */
export function installPageEnv(onSamples: (body: SamplesRequest) => FakeResponse) {
  FakeEventSource.instances = [];
  const calls: SamplesRequest[] = [];
  const originalEventSource = global.EventSource;
  const originalFetch = global.fetch;
  global.EventSource = FakeEventSource as unknown as typeof EventSource;
  global.fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === '/api/tcp-samples') {
      const body = JSON.parse(String(init?.body)) as SamplesRequest;
      calls.push(body);
      return onSamples(body);
    }
    return { ok: true, status: 200, json: async () => ({ ok: true }) };
  }) as unknown as typeof fetch;
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: false, media: query, onchange: null, addListener: vi.fn(), removeListener: vi.fn(),
    addEventListener: vi.fn(), removeEventListener: vi.fn(), dispatchEvent: vi.fn(),
  }));
  return {
    calls,
    restore() {
      global.EventSource = originalEventSource;
      global.fetch = originalFetch;
    },
  };
}

/** A 200 response with `body`. */
export function ok(body: unknown): FakeResponse {
  return { ok: true, status: 200, json: async () => body };
}
