// @vitest-environment jsdom
// KAN-129 Task 4: the "TCP graphs" entry point. A button only on TCP flows
// in the Sockets view, next to Trace Route; opening it polls
// /api/tcp-samples once per second while open and live, and stops on close;
// the RTT reference line comes from the connection's latencyMs (plan A4).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import TerminalApp from '@/app/page';
import { ConnectionsView } from '@/components/ConnectionsView';
import { THEMES } from '@/lib/osi-engine';
import type { NetworkConnection } from '@/lib/types';

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) { FakeEventSource.instances.push(this); }
  close(): void {}
}

function emit(data: unknown): void {
  act(() => FakeEventSource.instances[0].onmessage!({ data: JSON.stringify(data) } as MessageEvent));
}

const TCP = {
  id: 'Tcp-192.168.1.10:51000-93.184.216.34:443', protocol: 'HTTPS/TLS', appLayerProtocol: 'HTTPS/TLS', transportProtocol: 'TCP',
  osiStack: 'x', localAddr: '192.168.1.10', localPort: 51000, remoteAddr: '93.184.216.34', remotePort: 443,
  processName: 'Safari', pid: 1234, rxSpeed: 0, txSpeed: 0, rxBytesTotal: 0, txBytesTotal: 0,
  latencyMs: 12, packetLoss: 0, status: 'ESTABLISHED', encryption: 'TLS', sparkline: [],
};
const UDP = { ...TCP, id: 'Udp-192.168.1.10:5353-224.0.0.251:5353', transportProtocol: 'UDP', protocol: 'MDNS', appLayerProtocol: 'MDNS' };

const T0 = 1_794_120_000_000_000;
function reply(fromIndex: number, count: number) {
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

describe('ConnectionsView TCP graphs button', () => {
  const theme = Object.values(THEMES)[0];
  afterEach(cleanup);

  it('is offered next to Trace Route on TCP flows only', () => {
    const onOpen = vi.fn();
    const { rerender } = render(
      <ConnectionsView connections={[TCP as NetworkConnection]} theme={theme} onTraceRoute={() => {}} onOpenTcpGraphs={onOpen} />,
    );
    fireEvent.click(screen.getByRole('button', { name: /tcp graphs/i }));
    expect(onOpen).toHaveBeenCalledWith(TCP.id);
    rerender(<ConnectionsView connections={[UDP as NetworkConnection]} theme={theme} onTraceRoute={() => {}} onOpenTcpGraphs={onOpen} />);
    expect(screen.queryByRole('button', { name: /tcp graphs/i })).toBeNull();
  });

  it('is absent without a handler', () => {
    render(<ConnectionsView connections={[TCP as NetworkConnection]} theme={theme} onTraceRoute={() => {}} />);
    expect(screen.queryByRole('button', { name: /tcp graphs/i })).toBeNull();
  });
});

describe('TCP graphs from the Sockets view', () => {
  let originalEventSource: typeof EventSource;
  let originalFetch: typeof fetch;
  let samplesCalls: { connectionId: string; generation?: string; fromIndex: number }[];
  let samplesStatus: number;

  beforeEach(() => {
    FakeEventSource.instances = [];
    samplesCalls = [];
    samplesStatus = 200;
    originalEventSource = global.EventSource;
    global.EventSource = FakeEventSource as unknown as typeof EventSource;
    originalFetch = global.fetch;
    global.fetch = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === '/api/tcp-samples') {
        const body = JSON.parse(String(init?.body));
        samplesCalls.push(body);
        if (samplesStatus !== 200) return { ok: false, status: samplesStatus, json: async () => ({ error: 'busy' }) };
        return { ok: true, status: 200, json: async () => reply(body.fromIndex, 3) };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    }) as unknown as typeof fetch;
    window.matchMedia = vi.fn().mockImplementation((query: string) => ({
      matches: false, media: query, onchange: null, addListener: vi.fn(), removeListener: vi.fn(),
      addEventListener: vi.fn(), removeEventListener: vi.fn(), dispatchEvent: vi.fn(),
    }));
  });

  afterEach(() => {
    cleanup();
    global.EventSource = originalEventSource;
    global.fetch = originalFetch;
  });

  function open(connection: typeof TCP = TCP) {
    render(<TerminalApp />);
    emit({ type: 'connection_status', connected: true });
    emit({ type: 'connection_update', connection });
    fireEvent.click(screen.getByTestId('tab-connections'));
    fireEvent.click(screen.getByRole('button', { name: /tcp graphs/i }));
  }

  it('polls once per second from nextIndex while open, and stops on close', async () => {
    open();
    await screen.findByTestId('tcp-plot-seq');
    expect(samplesCalls[0]).toEqual({ connectionId: TCP.id, fromIndex: 0 });
    await waitFor(() => expect(samplesCalls.length).toBeGreaterThanOrEqual(2), { timeout: 2500 });
    expect(samplesCalls[1]).toEqual({ connectionId: TCP.id, generation: '00000000feedbeef:1', fromIndex: 3 });
    // The RTT reference line is the connection's handshake latency.
    expect(screen.getByTestId('tcp-rtt-ref')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /close tcp graphs/i }));
    expect(screen.queryByTestId('tcp-graphs')).toBeNull();
    const after = samplesCalls.length;
    await new Promise((r) => setTimeout(r, 1300));
    expect(samplesCalls.length).toBe(after);
  });

  it('pauses polling while the capture is not live', async () => {
    open();
    await screen.findByTestId('tcp-plot-seq');
    emit({ type: 'connection_status', connected: false });
    const after = samplesCalls.length;
    await new Promise((r) => setTimeout(r, 1300));
    expect(samplesCalls.length).toBe(after);
    // The samples already held stay on screen.
    expect(screen.getByTestId('tcp-plot-seq')).toBeInTheDocument();
  });

  it('omits the reference line without a handshake RTT, and shows a retry message when busy', async () => {
    samplesStatus = 429;
    const { latencyMs: _omit, ...noLatency } = TCP;
    void _omit;
    open(noLatency as typeof TCP);
    expect(await screen.findByTestId('tcp-error')).toHaveTextContent(/busy.*retrying/i);
    expect(screen.queryByTestId('tcp-plot-seq')).toBeNull();
    samplesStatus = 200;
    await screen.findByTestId('tcp-plot-seq', {}, { timeout: 2500 });
    expect(screen.queryByTestId('tcp-error')).toBeNull();
    expect(screen.queryByTestId('tcp-rtt-ref')).toBeNull();
  });
});
