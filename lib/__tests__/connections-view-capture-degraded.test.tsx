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
  packetLoss: 1.5,
  status: 'ESTABLISHED',
  encryption: 'TLS',
  sparkline: [1, 2, 3],
};

// Issue #61: the per-connection loss % is retransmit-derived and only
// trustworthy when the agent isn't also dropping frames at the capture
// layer — this must be visibly qualified, not presented with the same
// confidence as a healthy capture.
describe('ConnectionsView capture-degraded caveat', () => {
  it('shows no caveat marker when the capture is healthy', () => {
    render(<ConnectionsView connections={[baseConn]} theme={THEMES.matrix} captureDegraded={false} />);
    expect(screen.getByText(/1\.50% loss/)).toBeInTheDocument();
    expect(screen.queryByTitle(/may under-report/i)).not.toBeInTheDocument();
  });

  it('shows a caveat marker on the loss figure when the capture is degraded', () => {
    render(<ConnectionsView connections={[baseConn]} theme={THEMES.matrix} captureDegraded={true} />);
    expect(screen.getByText(/1\.50% loss/)).toBeInTheDocument();
    expect(screen.getByTitle(/may under-report/i)).toBeInTheDocument();
  });

  it('shows no caveat marker when captureDegraded is omitted (default)', () => {
    render(<ConnectionsView connections={[baseConn]} theme={THEMES.matrix} />);
    expect(screen.queryByTitle(/may under-report/i)).not.toBeInTheDocument();
  });
});
