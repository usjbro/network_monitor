// @vitest-environment jsdom
// KAN-129 Task 4: the "TCP graphs" entry point. A button only on TCP flows
// in the Sockets view, next to Trace Route; opening it polls
// /api/tcp-samples once per second while open and live, and stops on close;
// the RTT reference line comes from the connection's latencyMs (plan A4).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import TerminalApp from '@/app/page';
import { ConnectionsView } from '@/components/ConnectionsView';
import { THEMES } from '@/lib/osi-engine';
import type { NetworkConnection } from '@/lib/types';
import { emit, installPageEnv, ok, tcpSamplesReply, TCP, type SamplesRequest } from './helpers/page-harness';

const UDP = { ...TCP, id: 'Udp-192.168.1.10:5353-224.0.0.251:5353', transportProtocol: 'UDP', protocol: 'MDNS', appLayerProtocol: 'MDNS' };

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
  let env: ReturnType<typeof installPageEnv>;
  let samplesCalls: SamplesRequest[];
  let samplesStatus: number;

  beforeEach(() => {
    samplesStatus = 200;
    env = installPageEnv((body) =>
      samplesStatus !== 200 ? { ok: false, status: samplesStatus, json: async () => ({ error: 'busy' }) } : ok(tcpSamplesReply(body.fromIndex, 3)));
    samplesCalls = env.calls;
  });

  afterEach(() => {
    cleanup();
    env.restore();
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

  it('keeps the samples held when TCP graphs is clicked again for the open flow', async () => {
    open();
    await screen.findByTestId('tcp-plot-seq');
    emit({ type: 'connection_status', connected: false });
    fireEvent.click(screen.getByRole('button', { name: /^tcp graphs$/i }));
    expect(screen.getByTestId('tcp-plot-seq')).toBeInTheDocument();
  });

  it('stops polling when the Sockets tab is left, and resumes on return', async () => {
    open();
    await screen.findByTestId('tcp-plot-seq');
    fireEvent.click(screen.getByTestId('tab-dashboard'));
    const after = samplesCalls.length;
    await new Promise((r) => setTimeout(r, 1300));
    expect(samplesCalls.length).toBe(after);
    fireEvent.click(screen.getByTestId('tab-connections'));
    expect(screen.getByTestId('tcp-plot-seq')).toBeInTheDocument();
    await waitFor(() => expect(samplesCalls.length).toBeGreaterThan(after), { timeout: 2500 });
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
