// @vitest-environment jsdom
//
// Regression coverage for issue #65: Layer7Json.status_or_code was declared
// on the wire and never populated by anything, so the packet detail pane
// could never show it. Now HTTP responses populate it and this view must
// render it when present, nothing extra when absent.
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
  src: '93.184.216.34:443',
  dst: '192.168.1.10:51000',
  length: 60,
  summary: 'TCP 93.184.216.34 -> 192.168.1.10',
  hexDump: '00 01',
  headerBreakdown: {
    layer7: {
      app: 'HTTP',
      methodOrType: 'GET',
      pathOrQuery: '/index.html',
      payloadBytes: 10,
    },
  },
};

describe('PacketStreamView status_or_code rendering', () => {
  it('shows the HTTP status when the selected packet is a response', () => {
    const response: PacketFrame = {
      ...basePacket,
      headerBreakdown: {
        layer7: { app: 'HTTP', methodOrType: 'RESPONSE', pathOrQuery: '', statusOrCode: '404', payloadBytes: 10 },
      },
    };
    render(<PacketStreamView packets={[response]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByText(/Status: 404/)).toBeInTheDocument();
  });

  it('shows no Status line for an HTTP request (no status_or_code)', () => {
    render(<PacketStreamView packets={[basePacket]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.queryByText(/Status:/)).not.toBeInTheDocument();
  });
});
