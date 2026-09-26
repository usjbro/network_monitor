// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { ConnectionsView } from '@/components/ConnectionsView';
import { THEMES } from '@/lib/osi-engine';

afterEach(() => {
  cleanup();
});

// JAM-157: the agent never tags a flow's transport as QUIC (its
// TransportProtocol enum is TCP/UDP/ICMP/Other), so a QUIC filter button
// could only ever show an empty list. No filter without a real producer.
describe('ConnectionsView protocol filter buttons', () => {
  it('offers only filters something actually produces', () => {
    render(<ConnectionsView connections={[]} theme={THEMES.matrix} />);
    for (const proto of ['ALL', 'TCP', 'UDP', 'HTTPS', 'DNS']) {
      expect(screen.getByRole('button', { name: proto })).toBeInTheDocument();
    }
    expect(screen.queryByRole('button', { name: 'QUIC' })).not.toBeInTheDocument();
  });
});
