// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import type { PacketFrame } from '@/lib/types';

afterEach(cleanup);

describe('PacketStreamView MAC vendor labels', () => {
  it('shows an offline vendor beside known Ethernet addresses and unknown for unassigned prefixes', () => {
    const packet: PacketFrame = {
      id: 'vendor-packet', timestamp: '1000', relativeTimeMs: 1, layer: 4,
      protocol: 'TCP', src: '192.168.1.10:50000', dst: '192.168.1.1:443',
      length: 60, summary: 'TCP packet', hexDump: '', headerHexDump: '',
      fields: [
        { path: 'eth', label: 'Ethernet II', type: 'group', region: 'header', offset: 0, len: 14 },
        { path: 'eth.src', label: 'Source MAC', type: 'addr', group: 'eth', value: '00:00:0c:12:34:56', region: 'header', offset: 6, len: 6 },
        { path: 'eth.dst', label: 'Destination MAC', type: 'addr', group: 'eth', value: '00:08:33:12:34:56', region: 'header', offset: 0, len: 6 },
      ],
    };
    render(<PacketStreamView packets={[packet]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByText(/Cisco Systems, Inc/)).toBeInTheDocument();
    expect(screen.getByText(/Unknown vendor/)).toBeInTheDocument();
  });
});
