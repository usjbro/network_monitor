// @vitest-environment jsdom
// KAN-129 Task 4: TcpGraphsView renders spec D6's plots for a short fixture
// flow: retransmissions red, RST/FIN marked, zero window shaded, horizon and
// midstream note, the direction selector, the RTT reference line (A4), and
// a retry message instead of an empty plot.
import { afterEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { TcpGraphsView } from '@/components/TcpGraphsView';
import { THEMES } from '@/lib/osi-engine';
import { accumulate, emptyState, type TcpGraphState } from '@/lib/tcp-graphs';
import { TCP_SAMPLE_FLAG as F, TCP_SAMPLE_MARK as M, type TcpSample, type TcpSamplesPage } from '@/lib/types';

afterEach(cleanup);

const ID = 'Tcp-192.168.1.10:51000-93.184.216.34:443';
const T0 = Date.UTC(2026, 10, 17, 12, 0, 0) * 1000;
const theme = Object.values(THEMES)[0];

function s(tUs: number, outbound: boolean, over: Partial<TcpSample> = {}): TcpSample {
  const mark = (outbound ? M.OUTBOUND : 0) | (over.mark ?? 0);
  return { tUs, seq: 0, ack: 0, win: 1000, len: 0, flags: F.ACK, rttUs: 0, ...over, mark, outbound };
}

/** Handshake, 6 data/ACK pairs (the 3rd retransmitted, a zero window after the 4th), then FIN. */
function flow(): TcpSample[] {
  const out = [s(T0, true, { flags: F.SYN }), s(T0 + 1000, false, { flags: F.SYN | F.ACK, ack: 1 }), s(T0 + 2000, true, { seq: 1, ack: 1 })];
  let t = T0 + 2000;
  for (let i = 0; i < 6; i++) {
    out.push(s((t += 1000), true, { seq: 1 + i * 100, ack: 1, len: 100, mark: i === 2 ? M.RETRANSMIT : 0 }));
    const zero = i === 3;
    out.push(s((t += 500), false, { seq: 1, ack: 1 + (i + 1) * 100, win: zero ? 0 : 2560, mark: zero ? M.ZERO_WINDOW | M.RTT : M.WIN_SCALED | M.RTT, rttUs: 400 + i * 10 }));
  }
  out.push(s((t += 1000), true, { flags: F.FIN | F.ACK, seq: 601, ack: 1 }));
  return out;
}

function stateOf(samples: TcpSample[], over: Partial<Extract<TcpSamplesPage, { stale: false }>> = {}): TcpGraphState {
  return accumulate(emptyState(ID), {
    found: true, stale: false, connectionId: ID, generation: '00000000feedbeef:1', handshakeSeen: true,
    windowScale: { local: 7, remote: 7 }, seqBase: { outbound: 0, inbound: 0 }, relativeTo: 'isn',
    firstIndex: 0, nextIndex: samples.length, more: false, droppedOlder: 0, samples, head: null, labels: [], ...over,
  });
}

function view(state: TcpGraphState, props: Partial<React.ComponentProps<typeof TcpGraphsView>> = {}) {
  return render(<TcpGraphsView state={state} error={null} theme={theme} onClose={() => {}} timeZone="UTC" {...props} />);
}

describe('TcpGraphsView', () => {
  it('renders the sequence, RTT, throughput and window plots for a fixture flow', () => {
    view(stateOf(flow()));
    for (const id of ['tcp-plot-seq', 'tcp-plot-rtt', 'tcp-plot-throughput', 'tcp-plot-window']) expect(screen.getByTestId(id)).toBeInTheDocument();
    // Five ordinary data segments, one retransmission, drawn in red.
    expect(screen.getByTestId('tcp-data-path').getAttribute('d')?.match(/M/g)).toHaveLength(5);
    const red = screen.getByTestId('tcp-retransmit-path');
    expect(red.getAttribute('d')?.match(/M/g)).toHaveLength(1);
    expect(red).toHaveAttribute('stroke', '#ef4444');
    // ACK, receive-window and advertised-window values hold until the next
    // sample: steps, never a slope between samples.
    for (const id of ['tcp-ack-path', 'tcp-window-path', 'tcp-advertised-inbound', 'tcp-advertised-outbound']) {
      const d = screen.getByTestId(id).getAttribute('d') ?? '';
      expect(d, id).toMatch(/H/);
      expect(d, id).not.toMatch(/L/);
    }
    const fin = screen.getAllByTestId('tcp-mark-FIN');
    expect(fin).toHaveLength(1);
    // The newest sample is at the right edge: its label must stay inside the plot.
    expect(fin[0].querySelector('text')).toHaveAttribute('text-anchor', 'end');
    expect(screen.getAllByTestId('tcp-zero-window')).toHaveLength(1);
    expect(screen.getByTestId('tcp-rtt-path').getAttribute('d')?.match(/M/g)).toHaveLength(6);
    expect(screen.getByTestId('tcp-throughput-outbound').getAttribute('d')).toMatch(/M/);
  });

  it('labels the horizon, RTT capture point and window scaling', () => {
    view(stateOf(flow()));
    expect(screen.getByTestId('tcp-horizon')).toHaveTextContent('samples since 12:00:00; 0 older dropped');
    expect(screen.getByText("RTT: round trip from this host's capture point")).toBeInTheDocument();
    expect(screen.getByText('window: scaled')).toBeInTheDocument();
    expect(screen.queryByTestId('tcp-note')).toBeNull();
  });

  it('shows the midstream note and an unscaled window', () => {
    view(stateOf(flow(), { relativeTo: 'firstSeen', handshakeSeen: false, windowScale: null }));
    expect(screen.getByTestId('tcp-note')).toHaveTextContent('handshake not captured: sequence relative to first seen segment; window unscaled');
    expect(screen.getByText('window: unscaled (handshake not seen)')).toBeInTheDocument();
  });

  it('switches direction: inbound has no data here and its RTT is ACK delay', () => {
    view(stateOf(flow()));
    fireEvent.change(screen.getByTestId('tcp-direction'), { target: { value: 'inbound' } });
    expect(screen.getByTestId('tcp-data-path').getAttribute('d') ?? '').toBe('');
    expect(screen.getByText("RTT: this host's ACK delay (not network latency)")).toBeInTheDocument();
  });

  it('draws the handshake RTT reference line only when latencyMs is known', () => {
    const { unmount } = view(stateOf(flow()), { latencyMs: 12 });
    expect(screen.getByTestId('tcp-rtt-ref')).toBeInTheDocument();
    unmount();
    view(stateOf(flow()));
    expect(screen.queryByTestId('tcp-rtt-ref')).toBeNull();
  });

  it('shows a retry message, not an empty plot, when the agent is busy', () => {
    const { unmount } = view(emptyState(ID), { error: 429 });
    expect(screen.getByTestId('tcp-error')).toHaveTextContent(/busy.*retrying/i);
    expect(screen.queryByTestId('tcp-plot-seq')).toBeNull();
    unmount();
    // With samples already held, they stay on screen under the message.
    view(stateOf(flow()), { error: 504 });
    expect(screen.getByTestId('tcp-error')).toHaveTextContent(/retrying/i);
    expect(screen.getByTestId('tcp-plot-seq')).toBeInTheDocument();
  });

  it('says when the flow has gone and when nothing has arrived yet', () => {
    const { unmount } = view(accumulate(stateOf(flow()), { found: false, connectionId: ID }));
    expect(screen.getByTestId('tcp-status')).toHaveTextContent(/no longer tracks this flow/i);
    unmount();
    view(emptyState(ID));
    expect(screen.getByTestId('tcp-status')).toHaveTextContent(/loading/i);
    cleanup();
    // Never had samples: no ring (all were in use when the flow started), or not tracked.
    view(accumulate(emptyState(ID), { found: false, connectionId: ID }));
    expect(screen.getByTestId('tcp-status')).toHaveTextContent(/has no samples for this flow/i);
  });

  it('fits the time range of the samples even when a replay steps back in time', () => {
    // A merged or reordered capture: the newest sample by index is not the latest.
    const samples = [...flow(), s(T0 + 500, false, { seq: 1, ack: 601, win: 2560 })];
    view(stateOf(samples));
    const xs = [...(screen.getByTestId('tcp-data-path').getAttribute('d') ?? '').matchAll(/M([-\d.]+),/g)].map((m) => Number(m[1]));
    expect(xs).toHaveLength(5);
    // All inside the plot (left margin 64, right edge 788).
    for (const x of xs) expect(x).toBeGreaterThanOrEqual(64), expect(x).toBeLessThanOrEqual(788);
  });

  it('is a labelled region for the keys it handles', () => {
    view(stateOf(flow()));
    expect(screen.getByRole('region', { name: /tcp graphs/i })).toBe(screen.getByTestId('tcp-graphs'));
  });

  it('zooms with the keyboard and closes', () => {
    const onClose = vi.fn();
    view(stateOf(flow()), { onClose });
    const before = screen.getByTestId('tcp-data-path').getAttribute('d');
    fireEvent.keyDown(screen.getByTestId('tcp-graphs'), { key: '+' });
    expect(screen.getByTestId('tcp-data-path').getAttribute('d')).not.toBe(before);
    fireEvent.click(screen.getByRole('button', { name: /close/i }));
    expect(onClose).toHaveBeenCalled();
  });
});
