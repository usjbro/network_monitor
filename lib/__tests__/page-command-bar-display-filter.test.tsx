// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import TerminalApp from '@/app/page';

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) { FakeEventSource.instances.push(this); }
  close(): void {}
}

function runCommand(command: string): void {
  const input = screen.getByPlaceholderText(/Type CLI command/i);
  fireEvent.change(input, { target: { value: command } });
  fireEvent.submit(input.closest('form')!);
}

function emitPacket(id: number, port: number): void {
  act(() => FakeEventSource.instances[0].onmessage!({
    data: JSON.stringify({
      type: 'packet',
      packet: {
        id: `pkt-${id}`, timestamp: '12:00:00.000', relativeTimeMs: id,
        layer: 4, protocol: 'TCP', src: '10.0.0.1', dst: '10.0.0.2',
        length: 64, summary: `frame ${id}`, hexDump: '00 01 02 03',
        headerHexDump: 'aa bb',
        fields: [{ path: 'tcp.dst_port', type: 'uint', value: port, region: 'header', offset: 0, len: 2 }],
      },
    }),
  } as MessageEvent));
}

function emitConnection(id: number, port: number): void {
  act(() => FakeEventSource.instances[0].onmessage!({
    data: JSON.stringify({
      type: 'connection_update',
      connection: {
        id: `conn-${id}`, protocol: 'HTTPS', appLayerProtocol: 'HTTPS', transportProtocol: 'TCP',
        osiStack: 'L4:Tcp -> L3:IP', localAddr: '10.0.0.1', localPort: 40000 + id,
        remoteAddr: `93.184.0.${id}`, remotePort: port, processName: `Browser ${id}`, pid: id,
        rxSpeed: 0, txSpeed: 0, rxBytesTotal: 0, txBytesTotal: 0,
        latencyMs: 0, packetLoss: 0, status: 'ESTABLISHED', encryption: 'TLS', sparkline: [],
      },
    }),
  } as MessageEvent));
}

function controlBodies(): Array<Record<string, unknown>> {
  return (global.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls
    .filter((call) => call[0] === '/api/control')
    .map((call) => JSON.parse((call[1] as RequestInit).body as string));
}

describe('command bar: display filter and BPF capture filter', () => {
  let originalEventSource: typeof EventSource;
  let originalFetch: typeof fetch;

  beforeEach(() => {
    FakeEventSource.instances = [];
    originalEventSource = global.EventSource;
    global.EventSource = FakeEventSource as unknown as typeof EventSource;
    originalFetch = global.fetch;
    global.fetch = vi.fn().mockResolvedValue({ json: async () => ({ ok: true }) }) as unknown as typeof fetch;
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

  it('filters buffered packet rows locally and shows the active expression in both views', () => {
    render(<TerminalApp />);
    emitPacket(1, 443);
    emitPacket(2, 80);

    runCommand('display tcp.dst_port == 443');
    runCommand('pcap');
    expect(screen.getByText(/Display filter \(tcp\.dst_port == 443\): 1 of 2 buffered packets match/)).toBeInTheDocument();
    expect(screen.getByText(/PACKET CAPTURE FEED/)).toHaveTextContent('1 FRAMES');
    expect(screen.getByText('frame 1')).toBeInTheDocument();
    expect(screen.queryByText('frame 2')).not.toBeInTheDocument();

    runCommand('conn');
    expect(screen.getByText(/Display filter \(tcp\.dst_port == 443\): 0 of 0 buffered connections match/)).toBeInTheDocument();
    expect(controlBodies()).toHaveLength(0);
  });

  it('clears the display filter and restores buffered rows without a control request', () => {
    render(<TerminalApp />);
    emitPacket(1, 443);
    emitPacket(2, 80);
    runCommand('display tcp.dst_port == 443');
    runCommand('pcap');
    expect(screen.getByText(/PACKET CAPTURE FEED/)).toHaveTextContent('1 FRAMES');

    runCommand('display clear');
    expect(screen.queryByText(/Display filter \(/)).not.toBeInTheDocument();
    expect(screen.getByText(/PACKET CAPTURE FEED/)).toHaveTextContent('2 FRAMES');
    expect(screen.getByText('frame 1')).toBeInTheDocument();
    expect(screen.getByText('frame 2')).toBeInTheDocument();
    expect(controlBodies()).toHaveLength(0);
  });

  it('applies one display expression to connections and packets', () => {
    render(<TerminalApp />);
    emitConnection(1, 443);
    emitConnection(2, 80);
    emitPacket(1, 443);
    emitPacket(2, 80);

    runCommand('display connection.remote_port == 443');
    runCommand('conn');
    expect(screen.getByText(/Display filter \(connection\.remote_port == 443\): 1 of 2 buffered connections match/)).toBeInTheDocument();
    expect(screen.getByText('Browser 1')).toBeInTheDocument();
    expect(screen.queryByText('Browser 2')).not.toBeInTheDocument();
    runCommand('pcap');
    expect(screen.getByText(/Display filter \(connection\.remote_port == 443\): 0 of 2 buffered packets match/)).toBeInTheDocument();
    runCommand('display clear');
    runCommand('conn');
    expect(screen.getByText('Browser 1')).toBeInTheDocument();
    expect(screen.getByText('Browser 2')).toBeInTheDocument();
    expect(controlBodies()).toHaveLength(0);
  });

  it('shows token and character position for invalid display syntax while retaining the valid filter', () => {
    render(<TerminalApp />);
    emitPacket(1, 443);
    emitPacket(2, 80);
    runCommand('display tcp.dst_port == 443');
    runCommand('pcap');

    runCommand('display tcp.dst_port == nope');
    const error = screen.getByRole('alert');
    expect(error).toHaveTextContent(/display filter/i);
    expect(error).toHaveTextContent('nope');
    expect(error).toHaveTextContent(/character 17/i);
    expect(screen.getByText(/Display filter \(tcp\.dst_port == 443\): 1 of 2 buffered packets match/)).toBeInTheDocument();
    expect(screen.getByText(/PACKET CAPTURE FEED/)).toHaveTextContent('1 FRAMES');
    expect(controlBodies()).toHaveLength(0);

    runCommand('display clear');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByText(/PACKET CAPTURE FEED/)).toHaveTextContent('2 FRAMES');
  });

  it('keeps filter commands as BPF capture controls with original case', () => {
    render(<TerminalApp />);
    runCommand('filter host Example.com');
    runCommand('filter clear');
    expect(controlBodies()).toEqual([
      { type: 'set_capture_filter', filter: 'host Example.com' },
      { type: 'set_capture_filter', filter: '' },
    ]);
  });
});
