// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, fireEvent } from '@testing-library/react';
import { ConnectionsView } from '@/components/ConnectionsView';
import { THEMES } from '@/lib/osi-engine';
import { NetworkConnection } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const baseConn: NetworkConnection = {
  id: 'tcp-192.168.1.10:51000-93.184.216.34:443',
  protocol: 'HTTPS/TLS',
  appLayerProtocol: 'HTTPS/TLS',
  transportProtocol: 'TCP',
  osiStack: 'L4:TCP -> L3:IP',
  localAddr: '192.168.1.10',
  localPort: 51000,
  remoteAddr: '93.184.216.34',
  remotePort: 443,
  processName: 'Safari',
  pid: 1234,
  rxSpeed: 1024,
  txSpeed: 512,
  rxBytesTotal: 4096,
  txBytesTotal: 2048,
  latencyMs: 20,
  packetLoss: 0,
  status: 'ESTABLISHED',
  encryption: 'TLS',
  sparkline: [1, 2, 3],
};

describe('ConnectionsView JA3 display', () => {
  it('shows the JA3 hash and label when present on the selected connection', () => {
    const conn = { ...baseConn, ja3Fingerprint: 'deadbeef', ja3Label: 'matches Chrome 12x' };
    render(<ConnectionsView connections={[conn]} theme={THEMES.matrix} />);
    fireEvent.click(screen.getByText(conn.processName));
    expect(screen.getByText(/deadbeef/)).toBeInTheDocument();
    expect(screen.getByText('matches Chrome 12x')).toBeInTheDocument();
  });

  it('shows a plain "no handshake observed" state when JA3 is absent', () => {
    const conn = { ...baseConn, ja3Fingerprint: undefined, ja3Label: undefined };
    render(<ConnectionsView connections={[conn]} theme={THEMES.matrix} />);
    fireEvent.click(screen.getByText(conn.processName));
    expect(screen.getByText(/no TLS handshake observed/i)).toBeInTheDocument();
  });
});
