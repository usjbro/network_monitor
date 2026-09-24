// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import type { PacketFrame, WireField } from '@/lib/types';

afterEach(cleanup);

const ethFields: WireField[] = [
  { path: 'eth', label: 'Ethernet II', type: 'group', region: 'header', offset: 0, len: 14 },
  { path: 'eth.src', label: 'Source MAC', type: 'addr', group: 'eth', value: '00:01:02:03:04:05', region: 'header', offset: 6, len: 6 },
];

const basePacket: PacketFrame = {
  id: 'pkt-1', timestamp: '1000', relativeTimeMs: 1, layer: 4,
  protocol: 'TCP', src: '192.168.1.10:51000', dst: '93.184.216.34:443',
  length: 60, summary: 'TCP packet', hexDump: '00 01',
  headerHexDump: '06 07 08 09 0a 0b 00 01 02 03 04 05 81 00 00 64',
  fields: ethFields,
};

describe('PacketStreamView VLAN field rendering', () => {
  it('shows the VLAN ID as a nested field on tagged frames', () => {
    const tagged: PacketFrame = { ...basePacket, fields: [
      ...ethFields,
      { path: 'eth.vlan', label: '802.1Q VLAN Tag', type: 'group', group: 'eth', region: 'header', offset: 12, len: 4 },
      { path: 'eth.vlan.id', label: 'VLAN ID', type: 'uint', group: 'eth.vlan', value: 100, region: 'header', offset: 14, len: 2 },
    ] };
    render(<PacketStreamView packets={[tagged]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByText('VLAN ID')).toBeInTheDocument();
    expect(screen.getByText('100')).toBeInTheDocument();
  });

  it('shows no VLAN field on an untagged frame', () => {
    render(<PacketStreamView packets={[basePacket]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.queryByText('VLAN ID')).not.toBeInTheDocument();
  });
});
