// @vitest-environment jsdom
//
// Regression coverage for issue #69: interface listing and switching. This
// exercises app/page.tsx's actual onmessage handler against realistic
// interface_list/interface_changed/interface_error wire events end to end,
// confirming they parse without error, the list reaches the header picker,
// a rejected switch surfaces a dismissible banner, and a successful switch
// clears any earlier rejection automatically (unlike capture_config_error,
// since interface_changed only ever fires on success).
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

describe('TerminalApp interface stream handling', () => {
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

  it('populates the interface picker once an interface_list event arrives', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    act(() => {
      source.onmessage!({
        data: JSON.stringify({
          type: 'interface_list',
          interfaces: [
            { name: 'en0', addresses: ['192.168.1.104'] },
            { name: 'lo0', addresses: ['127.0.0.1'] },
          ],
        }),
      } as MessageEvent);
    });

    expect(screen.getByText('en0 (192.168.1.104)')).toBeInTheDocument();
    expect(screen.getByText('lo0 (127.0.0.1)')).toBeInTheDocument();
    expect(errorSpy).not.toHaveBeenCalledWith(
      'capture-agent: failed to process stream event',
      expect.anything(),
      expect.anything()
    );
    errorSpy.mockRestore();
  });

  it('shows a dismissible error banner when interface_error arrives, and dismissing it clears it', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    act(() => {
      source.onmessage!({
        data: JSON.stringify({ type: 'interface_error', message: 'no such interface: en9' }),
      } as MessageEvent);
    });

    expect(screen.getByText(/interface switch rejected/i)).toHaveTextContent('no such interface: en9');

    fireEvent.click(screen.getByLabelText(/dismiss interface error/i));
    expect(screen.queryByText(/interface switch rejected/i)).not.toBeInTheDocument();
  });

  it('clears the error banner automatically once interface_changed arrives, since that only ever fires on success', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    act(() => {
      source.onmessage!({
        data: JSON.stringify({ type: 'interface_error', message: 'no such interface: en9' }),
      } as MessageEvent);
    });
    expect(screen.getByText(/interface switch rejected/i)).toBeInTheDocument();

    act(() => {
      source.onmessage!({
        data: JSON.stringify({
          type: 'interface_changed',
          interface: { name: 'lo0', ipAddress: '127.0.0.1' },
        }),
      } as MessageEvent);
    });
    expect(screen.queryByText(/interface switch rejected/i)).not.toBeInTheDocument();
  });
});
