// @vitest-environment jsdom
//
// Regression coverage for issue #68: capture filter/snap length control
// messages and their agent-side acks/errors. This exercises app/page.tsx's
// actual onmessage handler against realistic capture_config/
// capture_config_error wire events end to end, confirming they parse
// without error, the active filter reaches the rendered header, and a
// rejected change surfaces a dismissible banner rather than being silent.
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

describe('TerminalApp capture_config stream handling', () => {
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

  it('shows no active filter/a "—" snap length before any capture_config event arrives', () => {
    render(<TerminalApp />);
    expect(screen.getByText(/filter:/i)).toHaveTextContent('filter: none');
    expect(screen.getByText(/snaplen:/i)).toHaveTextContent('snaplen: —');
  });

  it('renders the active filter and snap length once a capture_config event arrives', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    act(() => {
      source.onmessage!({
        data: JSON.stringify({ type: 'capture_config', config: { filter: 'tcp port 443', snaplen: 96 } }),
      } as MessageEvent);
    });

    expect(screen.getByText(/filter:/i)).toHaveTextContent('filter: tcp port 443');
    expect(screen.getByText(/snaplen:/i)).toHaveTextContent('snaplen: 96B');
    expect(errorSpy).not.toHaveBeenCalledWith(
      'capture-agent: failed to process stream event',
      expect.anything(),
      expect.anything()
    );
    errorSpy.mockRestore();
  });

  it('shows a dismissible error banner when capture_config_error arrives, and dismissing it clears it', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    act(() => {
      source.onmessage!({
        data: JSON.stringify({ type: 'capture_config_error', message: 'invalid capture filter: syntax error' }),
      } as MessageEvent);
    });

    expect(screen.getByText(/capture config rejected/i)).toHaveTextContent('invalid capture filter: syntax error');

    fireEvent.click(screen.getByLabelText(/dismiss capture config error/i));
    expect(screen.queryByText(/capture config rejected/i)).not.toBeInTheDocument();
  });

  it('does not auto-clear the error banner on the next unrelated capture_config tick', () => {
    // The periodic capture_config tick re-sends the same, still-unchanged
    // (still-rejected) config every second regardless of the error — that
    // must not be mistaken for the operator having fixed it.
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    act(() => {
      source.onmessage!({
        data: JSON.stringify({ type: 'capture_config_error', message: 'invalid capture filter: syntax error' }),
      } as MessageEvent);
    });
    expect(screen.getByText(/capture config rejected/i)).toBeInTheDocument();

    act(() => {
      source.onmessage!({
        data: JSON.stringify({ type: 'capture_config', config: { filter: null, snaplen: 65535 } }),
      } as MessageEvent);
    });
    expect(screen.getByText(/capture config rejected/i)).toBeInTheDocument();
  });
});
