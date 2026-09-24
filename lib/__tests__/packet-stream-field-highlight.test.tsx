// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import type { PacketFrame } from '@/lib/types';

afterEach(cleanup);

const packet: PacketFrame = {
  id: 'pkt-1', timestamp: '1000', relativeTimeMs: 1, layer: 4,
  protocol: 'TCP', src: '192.168.1.10:51000', dst: '93.184.216.34:443',
  length: 60, summary: 'TCP packet', hexDump: '16 03 01 00 a5',
  headerHexDump: '06 07 08 09 0a 0b 00 01 02 03 04 05 08 00',
  fields: [
    { path: 'eth', label: 'Ethernet II', type: 'group', region: 'header', offset: 0, len: 14 },
    { path: 'eth.dst', label: 'Destination MAC', type: 'addr', group: 'eth', value: '06:07:08:09:0a:0b', region: 'header', offset: 0, len: 6 },
    { path: 'eth.src', label: 'Source MAC', type: 'addr', group: 'eth', value: '00:01:02:03:04:05', region: 'header', offset: 6, len: 6 },
    { path: 'tls', label: 'TLS', type: 'group', region: 'payload', offset: 0, len: 5 },
    { path: 'tls.handshake.sni', label: 'Server Name', type: 'str', group: 'tls', value: 'example.com', region: 'payload', offset: 0, len: 5 },
  ],
};

function highlightedBytes(pane: HTMLElement): string[] {
  return Array.from(pane.querySelectorAll('span.bg-emerald-500\\/40')).map((el) => el.textContent?.trim() ?? '');
}

describe('PacketStreamView field and byte highlighting', () => {
  it('clicking a header field highlights only its six header bytes', () => {
    render(<PacketStreamView packets={[packet]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    fireEvent.click(screen.getByText('Source MAC'));
    expect(highlightedBytes(screen.getByTestId('header-hex-dump'))).toEqual(['00', '01', '02', '03', '04', '05']);
    expect(highlightedBytes(screen.getByTestId('payload-hex-dump'))).toEqual([]);
  });

  it('clicking a payload field highlights only payload bytes', () => {
    render(<PacketStreamView packets={[packet]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    fireEvent.click(screen.getByText('Server Name'));
    expect(highlightedBytes(screen.getByTestId('payload-hex-dump'))).toEqual(['16', '03', '01', '00', 'a5']);
    expect(highlightedBytes(screen.getByTestId('header-hex-dump'))).toEqual([]);
  });

  it('hovering a byte highlights all containing fields in that pane, including shared bit fields', () => {
    const flagsPacket: PacketFrame = { ...packet,
      fields: [
        ...packet.fields,
        { path: 'tcp', label: 'TCP', type: 'group', region: 'header', offset: 8, len: 6 },
        { path: 'tcp.flags', label: 'Flags', type: 'group', group: 'tcp', region: 'header', offset: 13, len: 1 },
        { path: 'tcp.flags.syn', label: 'SYN', type: 'bool', group: 'tcp.flags', value: true, region: 'header', offset: 13, len: 1 },
        { path: 'tcp.flags.ack', label: 'ACK', type: 'bool', group: 'tcp.flags', value: false, region: 'header', offset: 13, len: 1 },
      ],
    };
    render(<PacketStreamView packets={[flagsPacket]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    const byte = screen.getByTestId('header-hex-dump').querySelector('[data-byte-index="13"]')!;
    fireEvent.mouseEnter(byte);
    for (const path of ['eth', 'tcp', 'tcp.flags', 'tcp.flags.syn', 'tcp.flags.ack']) {
      expect(document.querySelector(`[data-field-path="${path}"]`)).toHaveAttribute('data-highlighted', 'true');
    }
    expect(document.querySelector('[data-field-path="tls"]')).not.toHaveAttribute('data-highlighted', 'true');
    fireEvent.mouseLeave(byte);
    expect(document.querySelector('[data-field-path="tcp.flags.syn"]')).not.toHaveAttribute('data-highlighted', 'true');
  });

  it('clamps a field range to the visible 64-byte payload dump', () => {
    const longPacket: PacketFrame = { ...packet,
      hexDump: Array.from({ length: 64 }, (_, i) => i.toString(16).padStart(2, '0')).join(' '),
      fields: [
        { path: 'tls', label: 'TLS', type: 'group', region: 'payload', offset: 0, len: 80 },
        { path: 'tls.trailing', label: 'Trailing Field', type: 'str', group: 'tls', value: 'long', region: 'payload', offset: 60, len: 20 },
      ],
    };
    render(<PacketStreamView packets={[longPacket]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    fireEvent.click(screen.getByText('Trailing Field'));
    expect(highlightedBytes(screen.getByTestId('payload-hex-dump'))).toEqual(['3c', '3d', '3e', '3f']);
  });

  it('clears a selected field when switching to another packet with the same field path', () => {
    const nextPacket: PacketFrame = { ...packet, id: 'pkt-2', summary: 'next packet',
      headerHexDump: 'ff ee dd cc bb aa 11 22 33 44 55 66 08 00' };
    render(<PacketStreamView packets={[packet, nextPacket]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    fireEvent.click(screen.getByText('Source MAC'));
    expect(highlightedBytes(screen.getByTestId('header-hex-dump'))).toHaveLength(6);
    fireEvent.click(screen.getByText('next packet'));
    expect(highlightedBytes(screen.getByTestId('header-hex-dump'))).toEqual([]);
  });
});
