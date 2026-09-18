// @vitest-environment jsdom
//
// Regression coverage for issue #64: SystemStats used to be a fabricated
// placeholder rendered as if live, with no wire event ever populating it.
// This exercises app/page.tsx's actual onmessage handler against a
// realistic system_stats wire event end to end, confirming it parses
// without error and the real hostname reaches the rendered header.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
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

describe('TerminalApp system_stats stream handling', () => {
  let originalEventSource: typeof EventSource;

  beforeEach(() => {
    FakeEventSource.instances = [];
    originalEventSource = global.EventSource;
    global.EventSource = FakeEventSource as unknown as typeof EventSource;

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
  });

  it('shows a placeholder, not a fabricated hostname, before any system_stats event arrives', () => {
    render(<TerminalApp />);
    expect(screen.queryByText('osi-gw-01')).not.toBeInTheDocument();
  });

  it('renders the real hostname once a system_stats event arrives', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];
    expect(source).toBeDefined();
    expect(source.onmessage).not.toBeNull();

    act(() => {
      source.onmessage!({
        data: JSON.stringify({
          type: 'system_stats',
          stats: {
            hostname: 'osi-gw-01',
            interfaceName: 'en0',
            ipAddress: '192.168.1.104',
            rxTotalMbps: 4.68,
            txTotalMbps: 3.7,
            rxPpsTotal: 480,
            txPpsTotal: 220,
            totalPacketsCaptured: 184200,
          },
        }),
      } as MessageEvent);
    });

    expect(screen.getByText('osi-gw-01')).toBeInTheDocument();
    expect(errorSpy).not.toHaveBeenCalledWith(
      'capture-agent: failed to process stream event',
      expect.anything(),
      expect.anything()
    );
    errorSpy.mockRestore();
  });
});
