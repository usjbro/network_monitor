// @vitest-environment jsdom
//
// Regression coverage for epic #55/JAM-133's UI honesty requirement: "the
// UI must say 'replaying <file>' rather than implying live capture." This
// exercises app/page.tsx's actual onmessage handler against realistic
// connection_status/agent_status wire events end to end, mirroring
// page-capture-stats-handling.test.tsx's own FakeEventSource pattern.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { act, cleanup, render } from '@testing-library/react';
import TerminalApp from '@/app/page';

// The banner's text is split across several JSX expressions/conditionals
// (see app/page.tsx), so it isn't one text node — `screen.getByText` can't
// match it directly. Finds the first element whose text includes `phrase`
// and returns its full text, or null if no such element is rendered.
function bannerTextContaining(phrase: string): string | null {
  const match = Array.from(document.querySelectorAll('div')).find((el) => el.textContent?.toLowerCase().includes(phrase.toLowerCase()));
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

function send(source: FakeEventSource, data: unknown): void {
  act(() => {
    source.onmessage!({ data: JSON.stringify(data) } as MessageEvent);
  });
}

describe('TerminalApp agent mode banner', () => {
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

  it('shows the disconnected banner when connection_status reports disconnected, regardless of last-known mode', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    send(source, { type: 'connection_status', connected: true });
    send(source, {
      type: 'agent_status',
      status: { interface: 'lo', capturing: true, mode: 'live', directionAttributionUnavailable: false },
    });
    send(source, { type: 'connection_status', connected: false });

    expect(bannerTextContaining('capture agent not connected')).not.toBeNull();
    expect(bannerTextContaining('replaying')).toBeNull();
  });

  it('shows the replaying banner with the source file once agent_status reports replay mode', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    send(source, { type: 'connection_status', connected: true });
    send(source, {
      type: 'agent_status',
      status: {
        interface: 'unknown (replayed pcapng, no if_name recorded)',
        capturing: true,
        mode: 'replay',
        replaySource: '/tmp/incident.pcapng',
        directionAttributionUnavailable: false,
      },
    });

    const banner = bannerTextContaining('replaying');
    expect(banner).not.toBeNull();
    expect(banner).toContain('/tmp/incident.pcapng');
    expect(bannerTextContaining('capture agent not connected')).toBeNull();
  });

  it('appends the direction-attribution caveat only when directionAttributionUnavailable is true', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    send(source, { type: 'connection_status', connected: true });
    send(source, {
      type: 'agent_status',
      status: {
        interface: 'unknown (replayed pcapng, no if_name recorded)',
        capturing: true,
        mode: 'replay',
        replaySource: '/tmp/incident.pcapng',
        directionAttributionUnavailable: true,
      },
    });

    const banner = bannerTextContaining('replaying');
    expect(banner).toContain('direction (rx/tx) could not be determined');
  });

  it('does not append the direction-attribution caveat when it is false', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    send(source, { type: 'connection_status', connected: true });
    send(source, {
      type: 'agent_status',
      status: {
        interface: 'unknown (replayed pcapng, no if_name recorded)',
        capturing: true,
        mode: 'replay',
        replaySource: '/tmp/incident.pcapng',
        directionAttributionUnavailable: false,
      },
    });

    const banner = bannerTextContaining('replaying');
    expect(banner).not.toContain('direction (rx/tx) could not be determined');
  });

  it('shows no mode banner at all once connected in live mode', () => {
    render(<TerminalApp />);
    const source = FakeEventSource.instances[0];

    send(source, { type: 'connection_status', connected: true });
    send(source, {
      type: 'agent_status',
      status: { interface: 'en0', capturing: true, mode: 'live', directionAttributionUnavailable: false },
    });

    expect(bannerTextContaining('capture agent not connected')).toBeNull();
    expect(bannerTextContaining('replaying')).toBeNull();
  });

  it('shows the disconnected banner before any agent_status has ever arrived, same as before this task', () => {
    render(<TerminalApp />);
    expect(bannerTextContaining('capture agent not connected')).not.toBeNull();
  });
});
