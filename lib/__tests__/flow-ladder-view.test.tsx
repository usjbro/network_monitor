// @vitest-environment jsdom
// KAN-130 Task 4: the ladder view (spec D6), the Graphs | Ladder tab strip,
// PacketStreamView's focus prop (plan P7) and the Ladder entry button.
import { afterEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { FlowLadderView } from '@/components/FlowLadderView';
import { TcpGraphsView } from '@/components/TcpGraphsView';
import { PacketStreamView } from '@/components/PacketStreamView';
import { ConnectionsView } from '@/components/ConnectionsView';
import { THEMES } from '@/lib/osi-engine';
import type { IndexedSample, TcpGraphState } from '@/lib/tcp-graphs';
import { BASE, LADDER_ID as ID, s, state } from './helpers/ladder-fixtures';
import { TCP_SAMPLE_FLAG as F, TCP_SAMPLE_MARK as M, type NetworkConnection, type PacketFrame, type TcpSampleLabel } from '@/lib/types';

afterEach(cleanup);

const T0 = Date.UTC(2026, 10, 20, 12, 0, 0) * 1000;
const theme = Object.values(THEMES)[0];
const CONN = {
  id: ID, localAddr: '192.168.1.10', localPort: 51000, remoteAddr: '93.184.216.34', remotePort: 443, transportProtocol: 'TCP',
} as NetworkConnection;

function handshake(): IndexedSample[] {
  return [
    s(0, T0, true, { flags: F.SYN }),
    s(1, T0 + 1_500, false, { flags: F.SYN | F.ACK, ack: 1 }),
    s(2, T0 + 3_000, true, { seq: 1, ack: 1 }),
    s(3, T0 + 4_000, true, { flags: F.PSH | F.ACK, seq: 1, ack: 1, len: 517 }),
    s(4, T0 + 9_000, false, { flags: F.PSH | F.ACK, seq: 1, ack: 518, len: 1400 }),
  ];
}

const helloLabel: TcpSampleLabel = { index: 3, kind: 'tls_client_hello', text: 'ClientHello (SNI: example.com)' };
const httpLabel: TcpSampleLabel = { index: 4, kind: 'http_response', text: 'HTTP 200 OK' };

function frameFor(sample: IndexedSample, id: string): PacketFrame {
  const own = sample.outbound ? BASE.outbound : BASE.inbound;
  const other = sample.outbound ? BASE.inbound : BASE.outbound;
  const [src, dst] = sample.outbound ? ['192.168.1.10:51000', '93.184.216.34:443'] : ['93.184.216.34:443', '192.168.1.10:51000'];
  const v = (path: string, value: number | boolean) => ({ path, label: path, type: typeof value === 'boolean' ? 'bool' : 'uint', value, region: 'header', offset: 0, len: 1 }) as const;
  return {
    id, timestamp: String(Math.floor(sample.tUs / 1000)), relativeTimeMs: 0, layer: 4, protocol: 'TCP', src, dst, length: 60, summary: `frame ${id}`,
    hexDump: '', headerHexDump: '',
    fields: [
      v('tcp.seq', own + sample.seq), v('tcp.ack_number', other + sample.ack),
      v('tcp.flags.syn', (sample.flags & F.SYN) !== 0), v('tcp.flags.ack', (sample.flags & F.ACK) !== 0),
      v('tcp.flags.fin', (sample.flags & F.FIN) !== 0), v('tcp.flags.rst', (sample.flags & F.RST) !== 0),
    ],
  };
}

function ladder(st: TcpGraphState, props: Partial<React.ComponentProps<typeof FlowLadderView>> = {}) {
  const onOpenFrame = vi.fn(() => null as string | null);
  const utils = render(
    <FlowLadderView state={st} connection={CONN} packets={[]} bufferLimit={100} theme={theme} onOpenFrame={onOpenFrame} timeZone="UTC" {...props} />,
  );
  return { ...utils, onOpenFrame: (props.onOpenFrame as typeof onOpenFrame | undefined) ?? onOpenFrame };
}

const rows = () => screen.getAllByTestId(/^ladder-row-/);

describe('FlowLadderView', () => {
  it('draws the handshake as labelled arrows between two lifelines', () => {
    ladder(state(handshake(), { labels: new Map([[3, helloLabel], [4, httpLabel]]) }));
    expect(screen.getByTestId('ladder-local')).toHaveTextContent('192.168.1.10:51000');
    expect(screen.getByTestId('ladder-remote')).toHaveTextContent('93.184.216.34:443');
    const arrows = screen.getAllByTestId('ladder-row-arrow');
    expect(arrows.map((r) => r.getAttribute('data-direction'))).toEqual(['out', 'in', 'out', 'out', 'in']);
    expect(arrows.map((r) => within(r).getByTestId('ladder-text').textContent)).toEqual([
      'SYN', 'SYN,ACK', 'ACK', 'PSH,ACK len=517 · ClientHello (SNI: example.com)', 'PSH,ACK len=1400 · HTTP 200 OK',
    ]);
    expect(arrows.map((r) => within(r).getByTestId('ladder-time').textContent)).toEqual([
      '+0.000 ms', '+1.500 ms', '+3.000 ms', '+4.000 ms', '+9.000 ms',
    ]);
  });

  it('colours by layer: TCP L4, TLS L6, HTTP L7', () => {
    ladder(state(handshake(), { labels: new Map([[3, helloLabel], [4, httpLabel]]) }));
    const text = screen.getAllByTestId('ladder-text');
    expect(text[0].className).toContain('text-sky-400');
    expect(text[3].className).toContain('text-teal-400');
    expect(text[4].className).toContain('text-emerald-400');
  });

  it('marks retransmissions and RST with the warning colour, in text as well', () => {
    const samples = handshake();
    samples[4] = { ...samples[4], mark: samples[4].mark | M.RETRANSMIT };
    samples.push(s(5, T0 + 10_000, true, { flags: F.RST }));
    ladder(state(samples));
    const text = screen.getAllByTestId('ladder-text');
    expect(text[4]).toHaveTextContent('retransmission');
    expect(text[4].className).toContain('text-red-400');
    expect(text[5]).toHaveTextContent('RST');
    expect(text[5].className).toContain('text-red-400');
  });

  it('shows the header: relative sequence, horizon and source note', () => {
    ladder(state(handshake()));
    expect(screen.getByTestId('ladder-header')).toHaveTextContent('sequence relative to ISN');
    expect(screen.getByTestId('ladder-header')).toHaveTextContent('segments since 12:00:00.000');
    expect(screen.getByTestId('ladder-header')).toHaveTextContent('complete within the retained window; not sampled');
    cleanup();
    ladder(state(handshake(), { meta: { handshakeSeen: false, windowScale: null, seqBase: BASE, relativeTo: 'firstSeen' } }));
    expect(screen.getByTestId('ladder-header')).toHaveTextContent('sequence relative to first seen segment');
  });

  it('collapses bulk runs, and marks gaps and elided rows', () => {
    const samples = handshake();
    let t = T0 + 9_000;
    for (let i = 5; i < 25; i++) samples.push(s(i, (t += 100_000), i % 2 === 0, { len: i % 2 === 0 ? 1000 : 0 }));
    samples.push(s(40, (t += 1000), true, { flags: F.FIN | F.ACK }));
    ladder(state(samples));
    expect(screen.getByTestId('ladder-row-run')).toHaveTextContent('20 segments over 1.900 s · → 10 data, 10.00 kB · ← 10 ACKs');
    expect(screen.getByTestId('ladder-row-gap')).toHaveTextContent('15 segments not retained');

    cleanup();
    const many = Array.from({ length: 250 }, (_, i) => s(i, T0 + i, true, { len: 1, mark: M.RETRANSMIT }));
    ladder(state(many));
    expect(screen.getByTestId('ladder-row-elided')).toHaveTextContent('50 rows not shown (50 segments)');
    expect(rows()).toHaveLength(201);
  });

  it('opens a linked arrow in the packet view and shows why when it cannot', () => {
    const samples = handshake();
    const packets = [frameFor(samples[3], 'pkt-hello')];
    const onOpenFrame = vi.fn().mockReturnValueOnce(null).mockReturnValueOnce('This frame has left the packet view.');
    ladder(state(samples), { packets, onOpenFrame });
    const arrows = screen.getAllByTestId('ladder-row-arrow');
    expect(within(arrows[3]).getByTestId('ladder-linked')).toBeInTheDocument();
    expect(arrows[3]).toHaveAccessibleName(/in packet view/);
    expect(within(arrows[0]).queryByTestId('ladder-linked')).toBeNull();
    fireEvent.click(arrows[3]);
    expect(onOpenFrame).toHaveBeenCalledWith('pkt-hello');
    fireEvent.click(arrows[3]);
    expect(screen.getByTestId('ladder-notice')).toHaveTextContent('This frame has left the packet view.');
  });

  it('shows an unlinked arrow\'s details and why it is not in the packet view', () => {
    ladder(state(handshake()), { bufferLimit: 250 });
    fireEvent.click(screen.getAllByTestId('ladder-row-arrow')[1]);
    const details = screen.getByTestId('ladder-details');
    expect(details).toHaveTextContent('inbound');
    expect(details).toHaveTextContent('SYN,ACK');
    expect(details).toHaveTextContent('ack 1');
    expect(details).toHaveTextContent('Not in the packet view: packet events are sampled at 100 per second and the view keeps the newest 250.');
  });

  it('moves between rows with the arrow keys and follows a link with Enter', () => {
    const samples = handshake();
    const onOpenFrame = vi.fn(() => null);
    ladder(state(samples), { packets: [frameFor(samples[1], 'pkt-synack')], onOpenFrame });
    const all = rows();
    all[0].focus();
    fireEvent.keyDown(all[0], { key: 'ArrowDown' });
    expect(document.activeElement).toBe(all[1]);
    fireEvent.keyDown(all[1], { key: 'End' });
    expect(document.activeElement).toBe(all[all.length - 1]);
    fireEvent.keyDown(all[all.length - 1], { key: 'Home' });
    expect(document.activeElement).toBe(all[0]);
    fireEvent.keyDown(all[0], { key: 'ArrowDown' });
    fireEvent.keyDown(all[1], { key: 'Enter' });
    expect(onOpenFrame).toHaveBeenCalledWith('pkt-synack');
  });

  it('says so when there is no history, while loading, and when stale', () => {
    ladder(state([], { found: false }));
    expect(screen.getByTestId('ladder-status')).toHaveTextContent('No segment history for this flow.');
    cleanup();
    ladder(state([], { found: null }));
    expect(screen.getByTestId('ladder-status')).toHaveTextContent('Loading segments');
    cleanup();
    ladder(state(handshake(), { found: false }));
    expect(screen.getByTestId('ladder-status')).toHaveTextContent('no longer tracks this flow');
    expect(screen.getAllByTestId('ladder-row-arrow')).toHaveLength(5);
  });

  it('renders label text as text, never markup', () => {
    const evil: TcpSampleLabel = { index: 3, kind: 'http_request', text: 'HTTP GET /<img src=x onerror=alert(1)>' };
    const { container } = ladder(state(handshake(), { labels: new Map([[3, evil]]) }));
    expect(container.querySelector('img')).toBeNull();
    expect(screen.getAllByTestId('ladder-text')[3]).toHaveTextContent('<img src=x onerror=alert(1)>');
  });
});

describe('TcpGraphsView tabs', () => {
  const st = state(handshake());
  it('shows the ladder on the Ladder tab and switches with the tab strip', () => {
    const onTab = vi.fn();
    render(<TcpGraphsView state={st} error={null} theme={theme} onClose={() => {}} tab="ladder" onTab={onTab} ladder={<div data-testid="the-ladder" />} timeZone="UTC" />);
    expect(screen.getByTestId('the-ladder')).toBeInTheDocument();
    expect(screen.queryByTestId('tcp-plots')).toBeNull();
    expect(screen.getByRole('tab', { name: 'Ladder' })).toHaveAttribute('aria-selected', 'true');
    fireEvent.click(screen.getByRole('tab', { name: 'Graphs' }));
    expect(onTab).toHaveBeenCalledWith('graphs');
  });

  it('keeps the plots on the Graphs tab, and has no tab strip without a ladder', () => {
    const { rerender } = render(<TcpGraphsView state={st} error={null} theme={theme} onClose={() => {}} tab="graphs" onTab={() => {}} ladder={<div data-testid="the-ladder" />} timeZone="UTC" />);
    expect(screen.getByTestId('tcp-plots')).toBeInTheDocument();
    expect(screen.queryByTestId('the-ladder')).toBeNull();
    rerender(<TcpGraphsView state={st} error={null} theme={theme} onClose={() => {}} timeZone="UTC" />);
    expect(screen.queryByRole('tab')).toBeNull();
  });
});

describe('PacketStreamView focusPacketId', () => {
  const frames = handshake().map((x, i) => frameFor(x, `pkt-${i}`));

  it('clears its own filters, selects the frame and reports back', () => {
    const onFocusHandled = vi.fn();
    const { rerender } = render(<PacketStreamView packets={frames} theme={theme} onClearPackets={() => {}} />);
    fireEvent.change(screen.getByPlaceholderText(/filter live pcap stream/i), { target: { value: 'nothing-matches' } });
    expect(document.querySelectorAll('[data-packet-row]')).toHaveLength(0);
    rerender(<PacketStreamView packets={frames} theme={theme} onClearPackets={() => {}} focusPacketId="pkt-3" onFocusHandled={onFocusHandled} />);
    expect(screen.getByPlaceholderText(/filter live pcap stream/i)).toHaveValue('');
    const selected = document.querySelector('[data-packet-row][data-selected="true"]');
    expect(selected).toHaveTextContent('frame pkt-3');
    expect(onFocusHandled).toHaveBeenCalledTimes(1);
  });

  it('changes nothing for an id it does not hold, and still reports back', () => {
    const onFocusHandled = vi.fn();
    render(<PacketStreamView packets={frames} theme={theme} onClearPackets={() => {}} focusPacketId="pkt-gone" onFocusHandled={onFocusHandled} />);
    expect(document.querySelector('[data-packet-row][data-selected="true"]')).toHaveTextContent('frame pkt-0');
    expect(onFocusHandled).toHaveBeenCalledTimes(1);
  });
});

describe('ConnectionsView Ladder button', () => {
  const FULL = {
    ...CONN, protocol: 'HTTPS/TLS', appLayerProtocol: 'HTTPS/TLS', osiStack: 'x', processName: 'Safari', pid: 1, rxSpeed: 0, txSpeed: 0,
    rxBytesTotal: 0, txBytesTotal: 0, packetLoss: 0, status: 'ESTABLISHED', encryption: 'TLS', sparkline: [],
  } as NetworkConnection;
  it('is offered on TCP flows only, next to TCP graphs', () => {
    const onOpenLadder = vi.fn();
    const { rerender } = render(<ConnectionsView connections={[FULL]} theme={theme} onOpenTcpGraphs={() => {}} onOpenLadder={onOpenLadder} />);
    fireEvent.click(screen.getByRole('button', { name: /^ladder$/i }));
    expect(onOpenLadder).toHaveBeenCalledWith(ID);
    rerender(<ConnectionsView connections={[{ ...FULL, transportProtocol: 'UDP' } as NetworkConnection]} theme={theme} onOpenTcpGraphs={() => {}} onOpenLadder={onOpenLadder} />);
    expect(screen.queryByRole('button', { name: /^ladder$/i })).toBeNull();
  });
});
