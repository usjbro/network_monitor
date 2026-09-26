// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { ConnectionsView } from '@/components/ConnectionsView';
import { THEMES } from '@/lib/osi-engine';
import { NetworkConnection } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const baseConn: NetworkConnection = {
  id: 'udp-192.168.1.10:53000-8.8.8.8:53',
  protocol: 'DNS',
  appLayerProtocol: 'DNS',
  transportProtocol: 'UDP',
  osiStack: 'L4:UDP -> L3:IP',
  localAddr: '192.168.1.10',
  localPort: 53000,
  remoteAddr: '8.8.8.8',
  remotePort: 53,
  processName: 'mDNSResponder',
  pid: 99,
  rxSpeed: 0,
  txSpeed: 0,
  rxBytesTotal: 0,
  txBytesTotal: 0,
  packetLoss: 0,
  status: 'ESTABLISHED',
  encryption: '',
  sparkline: [],
};

// JAM-156: an unmeasured latency must never render as a real "0 ms".
describe('ConnectionsView latency cell', () => {
  it('shows a dash, not "0 ms", when latency was not measured', () => {
    render(<ConnectionsView connections={[baseConn]} theme={THEMES.matrix} />);
    expect(screen.queryByText(/\b0 ms\b/)).not.toBeInTheDocument();
    expect(screen.getByTitle('Latency not measured for this flow')).toHaveTextContent('—');
  });

  it('shows the measured value when present', () => {
    render(<ConnectionsView connections={[{ ...baseConn, latencyMs: 12.5 }]} theme={THEMES.matrix} />);
    expect(screen.getByText('12.5 ms')).toBeInTheDocument();
  });
});
