// @vitest-environment jsdom
//
// KAN-131: app/page.tsx's onmessage handler for the bounded rollups. The
// Hosts tab must never show a partial or unreadable list as a complete one,
// and one table's bad event must not touch the other's.
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

const TOO_OLD = 'The running capture agent is older than this page. Restart the agent.';
const UNREADABLE = "This table's data could not be read.";
const WAITING = 'Waiting for the first update.';

const none = { rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0 };
const bounds = (overrides: Record<string, unknown> = {}) => ({
  cap: 50_000, topN: 200, tracked: 1, evictions: 0, unkeyed: 0, sinceMs: 0, horizonMs: null,
  totals: none, evicted: none, ...overrides,
});
const traffic = {
  historyComplete: true, rxBytesTotal: 100, txBytesTotal: 50, rxPacketsTotal: 2, txPacketsTotal: 1,
  rxSpeed: 10, txSpeed: 5, flowCount: 1, firstSeenMs: 0, lastSeenMs: 1000, processName: 'Safari', pid: 1234,
};
const endpointRollup = (hosts: string[], overrides: Record<string, unknown> = {}) => ({
  type: 'endpoint_rollup',
  endpoints: hosts.map((host) => ({ host, ...traffic })),
  bounds: bounds({ tracked: hosts.length, ...overrides }),
});
const conversationRollup = (remotes: string[], overrides: Record<string, unknown> = {}) => ({
  type: 'conversation_rollup',
  conversations: remotes.map((remoteAddr) => ({ localAddr: '192.168.1.10', remoteAddr, durationMs: 1000, ...traffic })),
  bounds: bounds({ tracked: remotes.length, ...overrides }),
});
const enrichmentEvent = (remoteAddr: string, remoteHostname: string) => ({
  type: 'connection_enrichment', connectionId: `Tcp-${remoteAddr}`, remoteAddr, remoteHostname,
  enrichment: { org: 'Example Org', source: 'rdap', fetchedAt: '2026-09-28T00:00:00.000Z' },
});

// Both tables, each with the event that the old agent sent for it.
const TABLES = [
  {
    table: 'endpoints', rollup: endpointRollup, rowsKey: 'endpoints', old: 'endpoint_update',
    other: 'conversations', otherRollup: conversationRollup,
  },
  {
    table: 'conversations', rollup: conversationRollup, rowsKey: 'conversations', old: 'conversation_update',
    other: 'endpoints', otherRollup: endpointRollup,
  },
];

let originalEventSource: typeof EventSource;
let errorSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  FakeEventSource.instances = [];
  originalEventSource = global.EventSource;
  global.EventSource = FakeEventSource as unknown as typeof EventSource;
  errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: false, media: query, onchange: null, addListener: vi.fn(), removeListener: vi.fn(),
    addEventListener: vi.fn(), removeEventListener: vi.fn(), dispatchEvent: vi.fn(),
  }));
});

afterEach(() => {
  cleanup();
  errorSpy.mockRestore();
  global.EventSource = originalEventSource;
});

// Parsed back from JSON, as the stream delivers it.
function send(event: unknown): void {
  act(() => {
    FakeEventSource.instances[0].onmessage!({ data: JSON.stringify(event) } as MessageEvent);
  });
}

function openHosts(): void {
  render(<TerminalApp />);
  fireEvent.click(screen.getByText(/^F7: HOSTS/));
}

const show = (table: string) => fireEvent.click(screen.getByRole('button', { name: table }));
const bodyRows = () => Array.from(screen.getByRole('table').querySelectorAll('tbody tr')).map((tr) => tr.textContent ?? '');
const tabText = () => screen.getByText(/^F7: HOSTS/).textContent;

describe.each(TABLES)('$table', ({ table, rollup, rowsKey, old, other, otherRollup }) => {
  it('waits for the first update', () => {
    openHosts();
    show(table);
    expect(bodyRows()).toEqual([WAITING]);
  });

  it('says so when nothing is tracked', () => {
    openHosts();
    show(table);
    send(rollup([]));
    expect(bodyRows()).toEqual([`No ${table} observed yet.`]);
  });

  it('does not claim nothing was observed while keys are tracked', () => {
    openHosts();
    show(table);
    send(rollup(['10.0.0.1']));
    fireEvent.change(screen.getByPlaceholderText(/search received rows/i), { target: { value: 'no such row' } });
    expect(screen.queryByText(`No ${table} observed yet.`)).not.toBeInTheDocument();
  });

  it('renders a first event received mid-capture whole', () => {
    openHosts();
    show(table);
    send(rollup(['10.0.0.1', '10.0.0.2'], { tracked: 50_000, evictions: 812, sinceMs: 1200, horizonMs: 41_200 }));
    expect(bodyRows()).toHaveLength(2);
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.2')).toBeInTheDocument();
  });

  it('replaces the rows on every event', () => {
    openHosts();
    show(table);
    send(rollup(['10.0.0.1']));
    send(rollup(['10.0.0.2']));
    expect(bodyRows()).toHaveLength(1);
    expect(screen.getByText('10.0.0.2')).toBeInTheDocument();
  });

  it('an old agent shows its notice and no rows, clears, and recovers', () => {
    openHosts();
    show(table);
    const oldEvent = { type: old, [rowsKey]: rollup(['10.9.9.9'])[rowsKey as never] };
    send(oldEvent);
    expect(bodyRows()).toEqual([TOO_OLD]);

    send(rollup(['10.0.0.1']));
    expect(screen.queryByText(TOO_OLD)).not.toBeInTheDocument();
    expect(bodyRows()).toHaveLength(1);

    send(oldEvent);
    expect(bodyRows()).toEqual([TOO_OLD]);
  });

  it.each([
    ['no bounds', (e: Record<string, unknown>) => ({ ...e, bounds: undefined })],
    ['bad bounds', (e: Record<string, unknown>) => ({ ...e, bounds: bounds({ cap: 0 }) })],
    ['no rows', (e: Record<string, unknown>) => ({ ...e, [rowsKey]: undefined })],
    ['a bad row', (e: Record<string, unknown>) => ({ ...e, [rowsKey]: [null] })],
  ])('an event with %s clears this table only, and recovers', (_label, spoil) => {
    openHosts();
    send(otherRollup(['10.1.1.1']));
    show(table);
    send(rollup(['10.0.0.1']));
    send(spoil(rollup(['10.0.0.1'])));
    expect(bodyRows()).toEqual([UNREADABLE]);
    show(other);
    expect(screen.getByText('10.1.1.1')).toBeInTheDocument();
    expect(screen.queryByText(UNREADABLE)).not.toBeInTheDocument();

    show(table);
    send(rollup(['10.0.0.2']));
    expect(screen.queryByText(UNREADABLE)).not.toBeInTheDocument();
    expect(bodyRows()).toHaveLength(1);
    expect(screen.getByText('10.0.0.2')).toBeInTheDocument();
  });

  it('an old agent event leaves the other table alone', () => {
    openHosts();
    send(otherRollup(['10.1.1.1']));
    send({ type: old, [rowsKey]: [] });
    show(other);
    expect(bodyRows()).toHaveLength(1);
    expect(screen.getByText('10.1.1.1')).toBeInTheDocument();
  });

  it('an unreadable table can turn out to be an old agent, and back', () => {
    openHosts();
    show(table);
    send(rollup(['10.0.0.1'], { tracked: -1 }));
    expect(bodyRows()).toEqual([UNREADABLE]);
    send({ type: old, [rowsKey]: [] });
    expect(bodyRows()).toEqual([TOO_OLD]);
    send(rollup(['10.0.0.1'], { tracked: -1 }));
    expect(bodyRows()).toEqual([UNREADABLE]);
  });

  it('enrichment applies to rows on screen and survives leaving and re-entering', () => {
    openHosts();
    show(table);
    send(rollup(['10.0.0.1', '10.0.0.2']));
    send(enrichmentEvent('10.0.0.1', 'ptr.example.net'));
    expect(screen.getByText('ptr.example.net')).toBeInTheDocument();

    send(rollup(['10.0.0.2']));
    expect(screen.queryByText('ptr.example.net')).not.toBeInTheDocument();
    send(rollup(['10.0.0.1']));
    expect(screen.getByText('ptr.example.net')).toBeInTheDocument();
  });

  it('a later result replaces what is on screen', () => {
    openHosts();
    show(table);
    send(rollup(['10.0.0.1']));
    send(enrichmentEvent('10.0.0.1', 'first.example.net'));
    send(enrichmentEvent('10.0.0.1', 'second.example.net'));
    expect(screen.getByText('second.example.net')).toBeInTheDocument();
    expect(screen.queryByText('first.example.net')).not.toBeInTheDocument();
  });

  it('enrichment for a row that arrives after its result', () => {
    openHosts();
    show(table);
    send(enrichmentEvent('10.0.0.1', 'ptr.example.net'));
    send(rollup(['10.0.0.1']));
    expect(screen.getByText('ptr.example.net')).toBeInTheDocument();
  });

  it('enrichment survives an unreadable event, and does not bring its rows back', () => {
    openHosts();
    show(table);
    send(rollup(['10.0.0.1']));
    send(enrichmentEvent('10.0.0.1', 'ptr.example.net'));
    send({ ...rollup(['10.0.0.1']), bounds: null });
    send(enrichmentEvent('10.0.0.1', 'ptr.example.net'));
    expect(bodyRows()).toEqual([UNREADABLE]);
    send(rollup(['10.0.0.1']));
    expect(screen.getByText('ptr.example.net')).toBeInTheDocument();
  });

  it('keeps the enrichment of rows that only this table shows, past the idle limit', () => {
    openHosts();
    show(table);
    send(rollup(['10.0.0.1']));
    send(otherRollup(['10.1.1.1']));
    send(enrichmentEvent('10.0.0.1', 'ptr.example.net'));
    send(otherRollup(['10.1.1.2']));
    act(() => {
      for (let i = 0; i < 1_001; i++) {
        FakeEventSource.instances[0].onmessage!({
          data: JSON.stringify(enrichmentEvent(`10.2.${i >> 8}.${i & 255}`, 'idle.example.net')),
        } as MessageEvent);
      }
    });
    send(rollup(['10.0.0.1']));
    expect(screen.getByText('ptr.example.net')).toBeInTheDocument();
  });

  it('the hosts of a cleared table fall under the idle limit', () => {
    openHosts();
    show(table);
    send(rollup(['10.0.0.1']));
    send(enrichmentEvent('10.0.0.1', 'ptr.example.net'));
    send({ ...rollup(['10.0.0.1']), bounds: null });
    act(() => {
      for (let i = 0; i < 1_000; i++) {
        FakeEventSource.instances[0].onmessage!({
          data: JSON.stringify(enrichmentEvent(`10.2.${i >> 8}.${i & 255}`, 'idle.example.net')),
        } as MessageEvent);
      }
    });
    send(rollup(['10.0.0.1']));
    expect(screen.queryByText('ptr.example.net')).not.toBeInTheDocument();
  });

  it('does not keep an observed name the next event lacks', () => {
    openHosts();
    show(table);
    const named = rollup(['10.0.0.1']);
    (named[rowsKey as never] as Record<string, unknown>[])[0].observedName = 'observed.example';
    send(named);
    send(rollup(['10.0.0.1']));
    expect(screen.queryByText('observed.example')).not.toBeInTheDocument();
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
  });

  it('accepts counters re-encoded as floats', () => {
    openHosts();
    show(table);
    const text = JSON.stringify(rollup(['10.0.0.1'], { evictions: 7 }))
      .replace('"evictions":7', '"evictions":1.8446744073709552e19')
      .replace('"cap":50000', '"cap":50000.0');
    act(() => {
      FakeEventSource.instances[0].onmessage!({ data: text } as MessageEvent);
    });
    expect(bodyRows()).toHaveLength(1);
    expect(errorSpy).not.toHaveBeenCalled();
  });
});

describe('the Hosts tab label', () => {
  it('shows tracked hosts, not rows received, and a dash unless ready', () => {
    render(<TerminalApp />);
    expect(tabText()).toBe('F7: HOSTS (–)');
    send(endpointRollup(['10.0.0.1'], { tracked: 50_000 }));
    expect(tabText()).toBe('F7: HOSTS (50,000)');
    send(endpointRollup([]));
    expect(tabText()).toBe('F7: HOSTS (0)');
    send({ ...endpointRollup([]), bounds: {} });
    expect(tabText()).toBe('F7: HOSTS (–)');
    send(endpointRollup(['10.0.0.1']));
    expect(tabText()).toBe('F7: HOSTS (1)');
    send({ type: 'endpoint_update', endpoints: [] });
    expect(tabText()).toBe('F7: HOSTS (–)');
  });

  it('ignores the conversations table', () => {
    render(<TerminalApp />);
    send(endpointRollup(['10.0.0.1']));
    send(conversationRollup(['10.0.0.1', '10.0.0.2']));
    send({ type: 'conversation_rollup' });
    expect(tabText()).toBe('F7: HOSTS (1)');
  });
});
