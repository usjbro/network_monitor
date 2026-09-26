// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { ConnectionsView } from '@/components/ConnectionsView';
import { THEMES } from '@/lib/osi-engine';
import type { Finding, NetworkConnection } from '@/lib/types';

afterEach(cleanup);

const flagged: NetworkConnection = {
  id: 'Tcp-flagged', protocol: 'TCP', appLayerProtocol: 'HTTPS/TLS', transportProtocol: 'TCP',
  osiStack: 'L4:Tcp -> L3:IP', localAddr: '192.168.1.10', localPort: 51000,
  remoteAddr: '93.184.216.34', remotePort: 443, processName: 'Safari', pid: 1,
  rxSpeed: 0, txSpeed: 0, rxBytesTotal: 0, txBytesTotal: 0, latencyMs: 0, packetLoss: 0,
  status: 'ESTABLISHED', encryption: 'TLS', sparkline: [],
};
const clean: NetworkConnection = { ...flagged, id: 'Tcp-clean', remotePort: 444 };

const findings: Finding[] = [
  { id: 'finding-1', timestamp: '1000', severity: 'note', code: 'connection-reset', summary: 'connection reset', flowId: 'Tcp-flagged' },
];

describe('ConnectionsView finding row markers', () => {
  it('shows a marker on a connection row whose id has a matching finding', () => {
    render(<ConnectionsView connections={[flagged, clean]} theme={THEMES.matrix} findings={findings} />);
    const rows = screen.getAllByRole('row').filter((r) => r.hasAttribute('data-connection-row'));
    const flaggedRow = rows.find((r) => r.getAttribute('data-connection-row') === 'Tcp-flagged')!;
    const cleanRow = rows.find((r) => r.getAttribute('data-connection-row') === 'Tcp-clean')!;
    expect(flaggedRow.querySelector('[data-testid="finding-marker"]')).not.toBeNull();
    expect(cleanRow.querySelector('[data-testid="finding-marker"]')).toBeNull();
  });

  it('shows no markers at all when findings is omitted', () => {
    render(<ConnectionsView connections={[flagged, clean]} theme={THEMES.matrix} />);
    expect(screen.queryAllByTestId('finding-marker')).toHaveLength(0);
  });
});
