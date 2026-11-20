// @vitest-environment jsdom
// KAN-130 Task 4: the Ladder entry point and click-through. The Ladder
// button opens the TCP panel on its ladder tab; both tabs share one poller
// (plan P8); a linked arrow opens its frame in the Packets view (plan P7).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import TerminalApp from '@/app/page';
import { emit, installPageEnv, ok, T0, tcpSamplesReply, TCP, type SamplesRequest } from './helpers/page-harness';

function packet(id: string, index: number) {
  const v = (path: string, value: number | boolean) => ({ path, label: path, type: typeof value === 'boolean' ? 'bool' : 'uint', value, region: 'header', offset: 0, len: 1 });
  return {
    type: 'packet',
    packet: {
      id, timestamp: String(Math.floor((T0 + index * 1000) / 1000)), relativeTimeMs: 0, layer: 4, protocol: 'TCP',
      src: '192.168.1.10:51000', dst: '93.184.216.34:443', length: 60, summary: `frame ${id}`, hexDump: '', headerHexDump: '',
      fields: [v('tcp.seq', index * 10), v('tcp.ack_number', 0), v('tcp.flags.syn', false), v('tcp.flags.ack', true), v('tcp.flags.fin', false), v('tcp.flags.rst', false)],
    },
  };
}

describe('Flow ladder from the Sockets view', () => {
  let env: ReturnType<typeof installPageEnv>;
  let samplesCalls: SamplesRequest[];

  beforeEach(() => {
    env = installPageEnv((body) => ok(tcpSamplesReply(body.fromIndex, body.fromIndex === 0 ? 3 : 0)));
    samplesCalls = env.calls;
  });

  afterEach(() => {
    cleanup();
    env.restore();
  });

  function openLadder() {
    render(<TerminalApp />);
    emit({ type: 'connection_status', connected: true });
    emit({ type: 'connection_update', connection: TCP });
    fireEvent.click(screen.getByTestId('tab-connections'));
    fireEvent.click(screen.getByRole('button', { name: /^ladder$/i }));
  }

  it('opens the panel on its ladder tab, offered on TCP flows next to TCP graphs', async () => {
    openLadder();
    expect(await screen.findByTestId('flow-ladder')).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByTestId('ladder-row-arrow')).toHaveLength(3));
    expect(screen.getByRole('tab', { name: 'Ladder' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.queryByTestId('tcp-plots')).toBeNull();
  });

  it('shares one poller between the tabs', async () => {
    openLadder();
    await waitFor(() => expect(screen.getAllByTestId('ladder-row-arrow')).toHaveLength(3));
    fireEvent.click(screen.getByRole('tab', { name: 'Graphs' }));
    expect(screen.getByTestId('tcp-plot-seq')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: 'Ladder' }));
    // TCP graphs on the flow already open keeps its samples and just switches tab.
    fireEvent.click(screen.getByRole('button', { name: /^tcp graphs$/i }));
    expect(screen.getByTestId('tcp-plots')).toBeInTheDocument();
    await waitFor(() => expect(samplesCalls.length).toBeGreaterThanOrEqual(2), { timeout: 2500 });
    // One poller: only the first request starts from 0; the rest follow nextIndex.
    expect(samplesCalls.filter((c) => c.fromIndex === 0)).toHaveLength(1);
    expect(samplesCalls.slice(1).every((c) => c.generation === '00000000feedbeef:1' && c.fromIndex === 3)).toBe(true);
  });

  it('opens a linked arrow\'s frame in the Packets view, selected', async () => {
    openLadder();
    emit(packet('pkt-one', 1));
    await waitFor(() => expect(screen.getAllByTestId('ladder-row-arrow')).toHaveLength(3));
    const arrows = screen.getAllByTestId('ladder-row-arrow');
    expect(screen.getAllByTestId('ladder-linked')).toHaveLength(1);
    fireEvent.click(arrows[1]);
    await waitFor(() => expect(document.querySelector('[data-packet-row][data-selected="true"]')).toHaveTextContent('frame pkt-one'));
    expect(screen.queryByTestId('flow-ladder')).toBeNull();
  });
});
