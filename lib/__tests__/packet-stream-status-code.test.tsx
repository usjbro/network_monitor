// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import type { PacketFrame } from '@/lib/types';

afterEach(cleanup);

const basePacket: PacketFrame = {
  id: 'pkt-1', timestamp: '1000', relativeTimeMs: 1, layer: 4,
  protocol: 'TCP', src: '93.184.216.34:443', dst: '192.168.1.10:51000',
  length: 60, summary: 'TCP response', hexDump: '48 54 54 50', headerHexDump: 'aa bb',
  fields: [
    { path: 'http', label: 'HTTP', type: 'group', region: 'payload', offset: 0, len: 4 },
    { path: 'http.request.method', label: 'Request Method', type: 'str', group: 'http', value: 'GET', region: 'payload', offset: 0, len: 3 },
  ],
};

describe('PacketStreamView HTTP field rendering', () => {
  it('shows a response status code as a field value', () => {
    const response: PacketFrame = { ...basePacket, fields: [
      basePacket.fields[0],
      { path: 'http.response.code', label: 'Status Code', type: 'uint', group: 'http', value: 404, region: 'payload', offset: 0, len: 4 },
    ] };
    render(<PacketStreamView packets={[response]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByText('Status Code')).toBeInTheDocument();
    expect(screen.getByText('404')).toBeInTheDocument();
  });

  it('shows the request method without a response status field', () => {
    render(<PacketStreamView packets={[basePacket]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByText('Request Method')).toBeInTheDocument();
    expect(screen.queryByText('Status Code')).not.toBeInTheDocument();
  });
});
