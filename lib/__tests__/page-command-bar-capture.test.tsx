// @vitest-environment jsdom
//
// Coverage for JAM-146 (JAM-125 Task 12): the `capture` and `buffer`
// command-bar verbs, driven through the real CommandLineBar input rather
// than by calling handleExecuteCommand directly — the command bar is the
// only way a user reaches these, and the routing/case-handling split
// between `cmdStr` and the lowercased `parts` lives in that path.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import TerminalApp from '@/app/page';

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) {
    FakeEventSource.instances.push(this);
  }
  close(): void {}
}

/** Types `cmd` into the command bar and submits it. */
function runCommand(cmd: string): void {
  const input = screen.getByPlaceholderText(/Type CLI command/i);
  fireEvent.change(input, { target: { value: cmd } });
  fireEvent.submit(input.closest('form')!);
}

/** The JSON body of the Nth `/api/control` POST the component made. */
function controlBodies(): Array<Record<string, unknown>> {
  return (global.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls
    .filter((call) => call[0] === '/api/control')
    .map((call) => JSON.parse((call[1] as RequestInit).body as string));
}

/**
 * A packet wire event with every field `mapPacketEvent` requires — it calls
 * `requireField` on each, so an incomplete payload is rejected by the SSE
 * handler's own try/catch and never reaches state.
 */
function packetEvent(id: number): MessageEvent {
  return {
    data: JSON.stringify({
      type: 'packet',
      packet: {
        id: `pkt-${id}`,
        timestamp: '12:00:00.000',
        relativeTimeMs: id,
        layer: 4,
        protocol: 'TCP',
        src: '10.0.0.1',
        dst: '10.0.0.2',
        length: 64,
        summary: `frame ${id}`,
        hexDump: '00 01 02 03',
        headerHexDump: 'aa bb',
        fields: [],
      },
    }),
  } as MessageEvent;
}

describe('command bar: capture / buffer verbs', () => {
  let originalEventSource: typeof EventSource;
  let originalFetch: typeof fetch;

  beforeEach(() => {
    FakeEventSource.instances = [];
    originalEventSource = global.EventSource;
    global.EventSource = FakeEventSource as unknown as typeof EventSource;
    originalFetch = global.fetch;
    global.fetch = vi.fn().mockResolvedValue({ json: async () => ({ ok: true }) }) as unknown as typeof fetch;

    window.matchMedia = vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }));
  });

  afterEach(() => {
    cleanup();
    global.EventSource = originalEventSource;
    global.fetch = originalFetch;
  });

  it('sends start_capture_file with the path case preserved and ring/autostop parsed', () => {
    render(<TerminalApp />);

    runCommand('capture /Users/Me/Captures/Run1.pcapng ring size 104857600 autostop duration 3600');

    expect(controlBodies()).toContainEqual({
      type: 'start_capture_file',
      // The single most regression-prone thing here: the path must NOT be
      // lowercased by the command router's own `cmdStr.toLowerCase()`.
      path: '/Users/Me/Captures/Run1.pcapng',
      ring: { mode: 'size', threshold: 104857600 },
      autostop: { mode: 'duration', threshold: 3600 },
    });
  });

  it('sends start_capture_file with no ring/autostop for a bare `capture <path>`', () => {
    render(<TerminalApp />);

    runCommand('capture /tmp/Plain.pcapng');

    const body = controlBodies().find((b) => b.type === 'start_capture_file');
    expect(body).toBeDefined();
    expect(body!.path).toBe('/tmp/Plain.pcapng');
    expect(body!.ring).toBeUndefined();
    expect(body!.autostop).toBeUndefined();
  });

  it('normalizes the `totalSize` autostop mode back to the wire contract spelling', () => {
    render(<TerminalApp />);

    // Typed lowercase by a user; the wire contract spells it camelCase.
    runCommand('capture /tmp/Run.pcapng autostop totalsize 1048576');

    const body = controlBodies().find((b) => b.type === 'start_capture_file');
    expect(body!.autostop).toEqual({ mode: 'totalSize', threshold: 1048576 });
  });

  it('refuses a malformed ring option rather than starting a capture without it', () => {
    render(<TerminalApp />);

    // `ring` is present but its mode is not one of size/duration/count —
    // silently starting an un-rotated capture would be the worse failure.
    runCommand('capture /tmp/Run.pcapng ring bogus 100');

    expect(controlBodies().filter((b) => b.type === 'start_capture_file')).toHaveLength(0);
  });

  it('refuses a ring option with a zero or negative threshold', () => {
    render(<TerminalApp />);

    runCommand('capture /tmp/Run.pcapng ring size 0');

    expect(controlBodies().filter((b) => b.type === 'start_capture_file')).toHaveLength(0);
  });

  it('sends stop_capture_file for `capture stop`', () => {
    render(<TerminalApp />);

    runCommand('capture stop');

    expect(controlBodies()).toContainEqual({ type: 'stop_capture_file' });
    // `stop` must not be mistaken for a path by the `capture <path>` branch.
    expect(controlBodies().filter((b) => b.type === 'start_capture_file')).toHaveLength(0);
  });

  it('buffer packets <n> changes how many packets the view keeps, with no agent round-trip', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    const emitPacket = (id: number) => source.onmessage!(packetEvent(id));

    // Default cap is 100: 120 frames in, 100 retained.
    act(() => {
      for (let i = 0; i < 120; i++) emitPacket(i);
    });
    runCommand('pcap');
    expect(screen.getByText(/PACKET CAPTURE FEED/)).toHaveTextContent('100 FRAMES');

    // Raise it; the buffer is now allowed to grow past 100.
    runCommand('buffer packets 500');
    act(() => {
      for (let i = 120; i < 300; i++) emitPacket(i);
    });
    expect(screen.getByText(/PACKET CAPTURE FEED/)).toHaveTextContent('280 FRAMES');

    // No `buffer` command ever reaches the agent — it is purely client-side.
    expect(controlBodies()).toHaveLength(0);
  });

  it('lowering a buffer limit re-caps what is already held, without waiting for the next event', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    act(() => {
      for (let i = 0; i < 50; i++) source.onmessage!(packetEvent(i));
    });
    runCommand('pcap');
    expect(screen.getByText(/PACKET CAPTURE FEED/)).toHaveTextContent('50 FRAMES');

    runCommand('buffer packets 10');
    // No further packet events — the truncation must have happened on the
    // command itself, not lazily on the next arrival.
    expect(screen.getByText(/PACKET CAPTURE FEED/)).toHaveTextContent('10 FRAMES');
  });

  it('ignores a buffer command with a non-positive or unparseable count', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    act(() => {
      for (let i = 0; i < 20; i++) source.onmessage!(packetEvent(i));
    });
    runCommand('pcap');

    runCommand('buffer packets 0');
    expect(screen.getByText(/PACKET CAPTURE FEED/)).toHaveTextContent('20 FRAMES');

    runCommand('buffer packets abc');
    expect(screen.getByText(/PACKET CAPTURE FEED/)).toHaveTextContent('20 FRAMES');
  });

  it('omits the observed total when the counter cannot support it (replay mode)', () => {
    // In replay mode capture_stats' `received` comes from libpcap's own
    // pcap::Stat, which has no live handle to report on and is therefore 0
    // — so the packet view must NOT claim "showing last 25 of 0 observed".
    // It still states the retention cap, which is always true.
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    act(() => {
      for (let i = 0; i < 25; i++) source.onmessage!(packetEvent(i));
      source.onmessage!({
        data: JSON.stringify({
          type: 'capture_stats',
          stats: {
            received: 0,
            dropped: 0,
            ifDropped: 0,
            relayLaggedEvents: 0,
            unparseableFrames: 0,
            totalConnectionsObserved: 0,
            capacityEvictions: 0,
            idleEvictions: 0,
          },
        }),
      } as MessageEvent);
    });

    runCommand('pcap');
    expect(screen.queryByText(/of 0 observed/)).not.toBeInTheDocument();
    expect(screen.getByText(/showing last 25/)).toBeInTheDocument();
    expect(screen.getByText(/this tab keeps 100/)).toBeInTheDocument();
  });

  it('renders an honest "showing N of M observed" horizon once capture_stats arrives', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    act(() => {
      source.onmessage!(packetEvent(1));
      source.onmessage!({
        data: JSON.stringify({
          type: 'capture_stats',
          stats: {
            received: 400000,
            dropped: 0,
            ifDropped: 0,
            relayLaggedEvents: 0,
            unparseableFrames: 0,
            totalConnectionsObserved: 5000,
            capacityEvictions: 12,
            idleEvictions: 300,
          },
        }),
      } as MessageEvent);
    });

    runCommand('pcap');
    expect(screen.getByText(/showing last 1 of 400000 observed/)).toBeInTheDocument();

    runCommand('conn');
    expect(screen.getByText(/showing 0 of 5000 observed/)).toBeInTheDocument();
    // Capacity eviction is surfaced distinctly from ordinary idle turnover.
    expect(screen.getByText(/12 connection\(s\) evicted for capacity/)).toBeInTheDocument();
  });
});
