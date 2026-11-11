// @vitest-environment jsdom
// JAM-18 Task 4 (KAN-111): the Packets view constrained to an IO graph
// interval [fromMs, toMs) and that series' filter, with a header computed
// from the agent's counts and the packets actually buffered (spec D7).
import { afterEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import type { PacketFrame } from '@/lib/types';
import type { DrillInfo } from '@/lib/io-graph';
import type { CompiledDisplayFilter } from '@/lib/display-filter';

afterEach(cleanup);

const T0 = 1_794_120_000_000;
const packet = (id: string, ms: number, protocol = 'DNS'): PacketFrame => ({
  id, timestamp: String(ms), relativeTimeMs: 0, layer: 7, protocol,
  src: '10.0.0.1', dst: '10.0.0.2', length: 60, summary: `${protocol} ${id}`,
  hexDump: '', headerHexDump: '', fields: [],
});
const isDns: CompiledDisplayFilter = (r) => r.kind === 'packet' && r.packet.protocol === 'DNS';
const info: DrillInfo = {
  seriesId: 'dns', interval: 1000, fromMs: T0, toMs: T0 + 1000,
  onTime: 5, late: 0, unplacedLate: 0, lossy: false, state: 'value', notObservedMs: 0,
};
const packets = [
  packet('before', T0 - 1),          // outside: just before
  packet('a', T0),                   // inside (start is inclusive)
  packet('b', T0 + 999),             // inside
  packet('tcp', T0 + 500, 'TCP'),    // inside but not matching the series filter
  packet('after', T0 + 1000),        // outside (end is exclusive)
];

function view(extra: Partial<React.ComponentProps<typeof PacketStreamView>> = {}) {
  const onClearDrill = vi.fn();
  const utils = render(
    <PacketStreamView packets={packets} theme={THEMES.matrix} onClearPackets={() => {}} bufferLimit={100}
      displayFilter={isDns} displayFilterExpression="dns"
      timeRange={{ fromMs: T0, toMs: T0 + 1000 }}
      drillHeader={{ info, filter: 'dns', timeZone: 'UTC' }} onClearDrill={onClearDrill} {...extra} />,
  );
  return { ...utils, onClearDrill };
}

const rowIds = () => Array.from(document.querySelectorAll('[data-packet-row]')).map((el) => /(DNS|TCP) ([a-z]+)/.exec(el.textContent ?? '')?.[2]);

describe('PacketStreamView drill-down', () => {
  it('lists only buffered packets in [fromMs, toMs) that match the series filter', () => {
    view();
    expect(rowIds()).toEqual(['a', 'b']);
  });

  it('states k of N from the buffer, never clamped, with the external-analyzer path', () => {
    view();
    const header = screen.getByTestId('drill-header');
    expect(header).toHaveTextContent('2 of 5 packets in 06:40:00.000–06:40:01.000 matching `dns` are available here.');
    expect(header).toHaveTextContent('100-packet buffer');
    expect(header).toHaveTextContent('external analyzer');
    expect(header.textContent).not.toMatch(/replay/i);
  });

  it('k above the agent count says the count is incomplete instead of shrinking k', () => {
    view({ drillHeader: { info: { ...info, onTime: 1 }, filter: 'dns', timeZone: 'UTC' } });
    expect(screen.getByTestId('drill-header')).toHaveTextContent("2 packets in 06:40:00.000–06:40:01.000 matching `dns` are available here; the agent's count for this interval is incomplete (late frames).");
  });

  it('k follows the buffer: a packet aging out lowers it', () => {
    const { rerender, onClearDrill } = view();
    rerender(
      <PacketStreamView packets={packets.filter((p) => p.id !== 'a')} theme={THEMES.matrix} onClearPackets={() => {}} bufferLimit={100}
        displayFilter={isDns} displayFilterExpression="dns" timeRange={{ fromMs: T0, toMs: T0 + 1000 }}
        drillHeader={{ info, filter: 'dns', timeZone: 'UTC' }} onClearDrill={onClearDrill} />,
    );
    expect(screen.getByTestId('drill-header')).toHaveTextContent('1 of 5 packets');
  });

  it('can be cleared', () => {
    const { onClearDrill } = view();
    fireEvent.click(screen.getByTestId('drill-clear'));
    expect(onClearDrill).toHaveBeenCalled();
  });

  it('without a time range, nothing changes (existing call sites)', () => {
    render(<PacketStreamView packets={packets} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.queryByTestId('drill-header')).toBeNull();
    expect(rowIds()).toHaveLength(5);
  });
});
