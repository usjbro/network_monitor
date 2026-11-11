// @vitest-environment jsdom
// JAM-18 Task 4 (KAN-111): IO graph -> Packets click-through, through the
// page's own stream handling (spec D7).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import TerminalApp from '@/app/page';

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) { FakeEventSource.instances.push(this); }
  close(): void {}
}

const T0 = Math.floor(Date.now() / 1000) * 1000 - 10_000;

function emit(data: unknown): void {
  act(() => FakeEventSource.instances[0].onmessage!({ data: JSON.stringify(data) } as MessageEvent));
}

function packet(id: string, ms: number, port: number) {
  return {
    type: 'packet',
    packet: {
      id, timestamp: String(ms), relativeTimeMs: 0, layer: 4, protocol: 'UDP', src: '10.0.0.1', dst: '10.0.0.2',
      length: 64, summary: `frame ${id}`, hexDump: '', headerHexDump: '',
      fields: [{ path: 'udp.dst_port', type: 'uint', value: port, region: 'header', offset: 0, len: 2 }],
    },
  };
}

describe('IO graph click-through', () => {
  let originalEventSource: typeof EventSource;
  let originalFetch: typeof fetch;

  beforeEach(() => {
    FakeEventSource.instances = [];
    originalEventSource = global.EventSource;
    global.EventSource = FakeEventSource as unknown as typeof EventSource;
    originalFetch = global.fetch;
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) }) as unknown as typeof fetch;
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

  it("opens Packets for the pinned interval with the series' own filter and a computed header", async () => {
    render(<TerminalApp />);
    emit({ type: 'io_series_status', revision: 1, epoch: 'aaaabbbb', replayWaiting: false, series: [{ id: 'dns', filter: 'udp.dst_port == 53', ok: true }] });
    emit({
      type: 'io_buckets', revision: 1, epoch: 'aaaabbbb', bucketMs: 100, coveredFromMs: T0, coveredToMs: T0 + 1000, notObserved: [],
      loss: { kernelDropped: 0, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 },
      series: [{ id: 'dns', late: 0, lateBuckets: [], buckets: [[T0, 3, 300]] }],
    });
    emit(packet('in-dns', T0 + 10, 53));
    emit(packet('in-other', T0 + 20, 443));
    emit(packet('out-dns', T0 + 1500, 53));

    fireEvent.click(screen.getByTestId('tab-io'));
    const graph = await screen.findByTestId('io-graph');
    await waitFor(() => expect(screen.getByTestId('io-path-dns')).toBeInTheDocument());
    fireEvent.keyDown(graph, { key: 'Enter' }); // pins the newest interval: [T0, T0 + 1000)
    fireEvent.click(screen.getByTestId('io-drill-dns'));

    const header = await screen.findByTestId('drill-header');
    expect(header).toHaveTextContent('1 of 3 packets');
    expect(header).toHaveTextContent('matching `udp.dst_port == 53`');
    const rows = Array.from(document.querySelectorAll('[data-packet-row]')).map((r) => r.textContent ?? '');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toContain('frame in-dns');

    // Clearing restores the full feed.
    fireEvent.click(screen.getByTestId('drill-clear'));
    expect(screen.queryByTestId('drill-header')).toBeNull();
    expect(document.querySelectorAll('[data-packet-row]')).toHaveLength(3);
  });
});
