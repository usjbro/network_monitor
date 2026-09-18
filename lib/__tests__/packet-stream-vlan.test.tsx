// @vitest-environment jsdom
//
// Regression coverage for issue #62: Layer2Json.vlanTag was hard-coded
// None on the wire while LayerDetailView told the user 802.1Q tagging was
// handled. Now the agent parses it and PacketStreamView must show it when
// present, and say nothing extra when the frame was untagged.
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import { PacketFrame } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const basePacket: PacketFrame = {
  id: 'pkt-1',
  timestamp: '1000',
  relativeTimeMs: 1,
  layer: 4,
  protocol: 'TCP',
  src: '192.168.1.10:51000',
  dst: '93.184.216.34:443',
  length: 60,
  summary: 'TCP 192.168.1.10 -> 93.184.216.34',
  hexDump: '00 01',
  headerBreakdown: {
    layer2: {
      srcMac: '00:01:02:03:04:05',
      dstMac: '06:07:08:09:0a:0b',
      ethType: 'IPv4',
    },
  },
};

describe('PacketStreamView VLAN tag rendering', () => {
  // The first packet in the list is selected by default (no click needed).
  it('shows the 802.1Q VLAN tag when the selected packet carries one', () => {
    const tagged: PacketFrame = {
      ...basePacket,
      headerBreakdown: { layer2: { ...basePacket.headerBreakdown.layer2!, vlanTag: '100' } },
    };
    render(<PacketStreamView packets={[tagged]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByText(/802\.1Q VLAN: 100/)).toBeInTheDocument();
  });

  it('shows no VLAN line for an untagged frame', () => {
    render(<PacketStreamView packets={[basePacket]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.queryByText(/802\.1Q VLAN/)).not.toBeInTheDocument();
  });
});
