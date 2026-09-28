// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import type { PacketFrame } from '@/lib/types';

afterEach(() => cleanup());

const packet = (id: string, layer: PacketFrame['layer'], protocol: string, summary: string): PacketFrame => ({
  id,
  timestamp: '12:00:00',
  relativeTimeMs: 0,
  layer,
  protocol,
  src: '10.0.0.1',
  dst: '10.0.0.2',
  length: 60,
  summary,
  hexDump: '',
  headerHexDump: '',
  fields: [],
});

describe('PacketStreamView OSI layer filters', () => {
  it('filters mixed packet events at L3, L4, and L7 and omits unsupported layers', () => {
    const packets = [
      packet('icmp', 3, 'ICMP', 'ICMP echo request'),
      packet('tcp', 4, 'TCP', 'TCP connection packet'),
      packet('http', 7, 'TCP', 'HTTP GET /'),
    ];
    render(<PacketStreamView packets={packets} theme={THEMES.matrix} onClearPackets={() => {}} />);

    for (const layer of [1, 2, 5, 6]) {
      expect(screen.queryByRole('button', { name: `L${layer}` })).not.toBeInTheDocument();
    }

    fireEvent.click(screen.getByRole('button', { name: 'L3' }));
    expect(screen.getByText('ICMP echo request')).toBeInTheDocument();
    expect(screen.queryByText('TCP connection packet')).not.toBeInTheDocument();
    expect(screen.queryByText('HTTP GET /')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'L4' }));
    expect(screen.getByText('TCP connection packet')).toBeInTheDocument();
    expect(screen.queryByText('ICMP echo request')).not.toBeInTheDocument();
    expect(screen.queryByText('HTTP GET /')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'L7' }));
    expect(screen.getByText('HTTP GET /')).toBeInTheDocument();
    expect(screen.queryByText('ICMP echo request')).not.toBeInTheDocument();
    expect(screen.queryByText('TCP connection packet')).not.toBeInTheDocument();
  });
});
