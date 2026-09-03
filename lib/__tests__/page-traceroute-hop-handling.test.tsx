// @vitest-environment jsdom
//
// Regression coverage for issue #46: app/page.tsx's SSE handler passed the
// raw traceroute_hop event straight to mapTracerouteHopEvent instead of
// unwrapping its nested `hop` field (capture-agent/src/wire.rs's
// `TracerouteHop { hop: Box<TracerouteHopJson> }`), so every hop event
// threw inside the handler's try/catch and was silently dropped. This test
// exercises app/page.tsx's actual onmessage handler against a realistic
// nested wire event, closing the gap the issue itself flagged: the unit
// test for mapTracerouteHopEvent alone can't catch an unwrap bug at the
// call site.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render } from '@testing-library/react';
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

describe('TerminalApp traceroute_hop stream handling', () => {
  let originalEventSource: typeof EventSource;

  beforeEach(() => {
    FakeEventSource.instances = [];
    originalEventSource = global.EventSource;
    global.EventSource = FakeEventSource as unknown as typeof EventSource;

    // jsdom doesn't implement matchMedia; InstallModal (rendered as part of
    // TerminalApp's tree) reads it on mount to detect standalone PWA mode.
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

  it('does not throw/log an error when fed a realistic nested traceroute_hop wire event', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];
    expect(source).toBeDefined();
    expect(source.onmessage).not.toBeNull();

    source.onmessage!({
      data: JSON.stringify({
        type: 'traceroute_hop',
        hop: { targetIp: '93.184.216.34', hopNumber: 4, hopIp: '12.122.1.1', rttMs: 18.4 },
      }),
    } as MessageEvent);

    expect(errorSpy).not.toHaveBeenCalledWith(
      'capture-agent: failed to process stream event',
      expect.anything(),
      expect.anything()
    );
    errorSpy.mockRestore();
  });
});
