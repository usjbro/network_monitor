// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ConnectionsView } from '../../components/ConnectionsView';
import { THEMES } from '../osi-engine';
import { NetworkConnection } from '../types';

const baseConn: NetworkConnection = {
  id: 'tcp-192.168.1.10:51000-93.184.216.34:443',
  protocol: 'HTTPS/TLS',
  appLayerProtocol: 'HTTPS/TLS',
  transportProtocol: 'TCP',
  osiStack: 'L4:TCP -> L3:IPv4',
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
  sparkline: [],
};

describe('ConnectionsView traceroute', () => {
  it('calls onTraceRoute with the selected connection id and remoteAddr when clicked', () => {
    const onTraceRoute = vi.fn();
    render(<ConnectionsView connections={[baseConn]} theme={THEMES.matrix} onTraceRoute={onTraceRoute} />);
    fireEvent.click(screen.getByText(baseConn.processName));
    fireEvent.click(screen.getByRole('button', { name: /trace route/i }));
    expect(onTraceRoute).toHaveBeenCalledWith(baseConn.id, baseConn.remoteAddr);
  });

  it('disables the button while a trace is in flight for the selected connection', () => {
    render(
      <ConnectionsView
        connections={[baseConn]}
        theme={THEMES.matrix}
        onTraceRoute={vi.fn()}
        traceroute={{ [baseConn.id]: [] }}
        traceInFlight={{ [baseConn.id]: true }}
      />
    );
    fireEvent.click(screen.getByText(baseConn.processName));
    expect(screen.getByRole('button', { name: /trace route/i })).toBeDisabled();
  });

  it('renders hop rows progressively, showing "* * *" for no-response hops', () => {
    const hops = [
      { targetIp: baseConn.remoteAddr, hopNumber: 1, hopIp: '10.0.0.1', rttMs: 1.2 },
      { targetIp: baseConn.remoteAddr, hopNumber: 2 }, // no response
    ];
    render(
      <ConnectionsView
        connections={[baseConn]}
        theme={THEMES.matrix}
        onTraceRoute={vi.fn()}
        traceroute={{ [baseConn.id]: hops }}
      />
    );
    fireEvent.click(screen.getByText(baseConn.processName));
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
    expect(screen.getByText('* * *')).toBeInTheDocument();
  });

  it('shows "location unavailable" for a hop with no location', () => {
    const hops = [{ targetIp: baseConn.remoteAddr, hopNumber: 1, hopIp: '10.0.0.1', rttMs: 1.2 }];
    render(
      <ConnectionsView
        connections={[baseConn]}
        theme={THEMES.matrix}
        onTraceRoute={vi.fn()}
        traceroute={{ [baseConn.id]: hops }}
      />
    );
    fireEvent.click(screen.getByText(baseConn.processName));
    expect(screen.getByText(/location unavailable/i)).toBeInTheDocument();
  });
});
