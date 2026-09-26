// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import type { Finding, PacketFrame } from '@/lib/types';

afterEach(cleanup);

const flagged: PacketFrame = {
  id: 'pkt-flagged', timestamp: '1000', relativeTimeMs: 1, layer: 4,
  protocol: 'TCP', src: '192.168.1.10:51000', dst: '93.184.216.34:443',
  length: 60, summary: 'flagged packet', hexDump: '', headerHexDump: '', fields: [],
};
const clean: PacketFrame = { ...flagged, id: 'pkt-clean', summary: 'clean packet' };

const findings: Finding[] = [
  { id: 'finding-1', timestamp: '1000', severity: 'warning', code: 'retransmission', summary: 'retransmitted segment', frameId: 'pkt-flagged' },
];

describe('PacketStreamView finding row markers', () => {
  it('shows a marker on a packet row whose id has a matching finding', () => {
    render(<PacketStreamView packets={[flagged, clean]} theme={THEMES.matrix} onClearPackets={() => {}} findings={findings} />);
    const flaggedRow = screen.getByText('flagged packet').closest('div[data-packet-row]')!;
    const cleanRow = screen.getByText('clean packet').closest('div[data-packet-row]')!;
    expect(flaggedRow.querySelector('[data-testid="finding-marker"]')).not.toBeNull();
    expect(cleanRow.querySelector('[data-testid="finding-marker"]')).toBeNull();
  });

  it('shows no markers at all when findings is omitted', () => {
    render(<PacketStreamView packets={[flagged, clean]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.queryAllByTestId('finding-marker')).toHaveLength(0);
  });
});
