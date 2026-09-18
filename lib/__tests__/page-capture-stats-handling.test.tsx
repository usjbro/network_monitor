// @vitest-environment jsdom
//
// Regression coverage for issue #61: capture-side drops (kernel/driver, or
// a lagging relay client) were invisible to the browser entirely — no
// wire event carried them. This exercises app/page.tsx's actual onmessage
// handler against a realistic capture_stats wire event end to end,
// confirming it both parses without error (mirrors the traceroute_hop
// nested-envelope regression in #46 — see page-traceroute-hop-handling.test.tsx)
// and actually surfaces the degraded-capture banner.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { act, cleanup, render } from '@testing-library/react';
import TerminalApp from '@/app/page';

// The banner's text is split across several JSX expressions/conditionals
// (see app/page.tsx), so it isn't one text node — `screen.getByText` can't
// match it directly. Finds the banner element by its stable lead-in phrase
// and returns its full text, or null if no such element is rendered.
function bannerText(): string | null {
  const match = Array.from(document.querySelectorAll('div')).find((el) =>
    el.textContent?.toLowerCase().includes('capture degraded')
  );
  return match ? match.textContent : null;
}

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) {
    FakeEventSource.instances.push(this);
  }
  close(): void {}
}

describe('TerminalApp capture_stats stream handling', () => {
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

  it('shows no degraded-capture banner before any capture_stats event arrives', () => {
    render(<TerminalApp />);
    expect(bannerText()).toBeNull();
  });

  it('shows no degraded-capture banner for a healthy zero-drop capture_stats event', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];
    act(() => {
      source.onmessage!({
        data: JSON.stringify({
          type: 'capture_stats',
          stats: { received: 5000, dropped: 0, ifDropped: 0, relayLaggedEvents: 0, unparseableFrames: 0 },
        }),
      } as MessageEvent);
    });
    expect(bannerText()).toBeNull();
  });

  it('shows the degraded-capture banner once capture_stats reports nonzero drops', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];
    expect(source).toBeDefined();
    expect(source.onmessage).not.toBeNull();

    act(() => {
      source.onmessage!({
        data: JSON.stringify({
          type: 'capture_stats',
          stats: { received: 5000, dropped: 12, ifDropped: 0, relayLaggedEvents: 0, unparseableFrames: 0 },
        }),
      } as MessageEvent);
    });

    expect(bannerText()).toMatch(/capture degraded/i);
    expect(bannerText()).toMatch(/12 frame\(s\) dropped/i);
    expect(errorSpy).not.toHaveBeenCalledWith(
      'capture-agent: failed to process stream event',
      expect.anything(),
      expect.anything()
    );
    errorSpy.mockRestore();
  });

  it('includes the relay-lag count in the banner when relayLaggedEvents is nonzero', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];
    act(() => {
      source.onmessage!({
        data: JSON.stringify({
          type: 'capture_stats',
          stats: { received: 5000, dropped: 0, ifDropped: 0, relayLaggedEvents: 9, unparseableFrames: 0 },
        }),
      } as MessageEvent);
    });
    expect(bannerText()).toMatch(/capture degraded/i);
    expect(bannerText()).toMatch(/9 event\(s\) dropped for a lagging client/i);
  });

  it('shows the degraded-capture banner and mentions unparseable frames when unparseableFrames is nonzero', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];
    act(() => {
      source.onmessage!({
        data: JSON.stringify({
          type: 'capture_stats',
          stats: { received: 5000, dropped: 0, ifDropped: 0, relayLaggedEvents: 0, unparseableFrames: 6 },
        }),
      } as MessageEvent);
    });
    expect(bannerText()).toMatch(/capture degraded/i);
    expect(bannerText()).toMatch(/6 frame\(s\) could not be parsed/i);
  });
});
