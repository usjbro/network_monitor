// @vitest-environment jsdom
//
// Regression coverage for issue #64: the KPI cards on the dashboard used to
// render fabricated placeholder SystemStats values (e.g. a fake
// totalPacketsCaptured) with the same visual confidence as a real
// measurement. Now stats is null until the first system_stats tick, and
// every card must show "—" rather than formatting a placeholder or zero as
// if it were live.
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { DashboardView } from '@/components/DashboardView';
import { mergeLayerStats } from '@/lib/agent-mapping';
import { THEMES } from '@/lib/osi-engine';
import { SystemStats } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const layers = mergeLayerStats({} as never);

const baseProps = {
  layers,
  theme: THEMES.matrix,
  onSelectLayer: () => {},
  historyRx: [],
  historyTx: [],
};

const liveStats: SystemStats = {
  hostname: 'osi-gw-01',
  interfaceName: 'en0',
  ipAddress: '192.168.1.104',
  rxTotalMbps: 4.68,
  txTotalMbps: 3.7,
  rxPpsTotal: 480,
  txPpsTotal: 220,
  totalPacketsCaptured: 184200,
};

describe('DashboardView system_stats rendering', () => {
  it('shows "—" placeholders in the KPI cards before any system_stats event arrives', () => {
    render(<DashboardView {...baseProps} stats={null} />);
    expect(screen.getAllByText('—').length).toBeGreaterThan(0);
    expect(screen.queryByText('184,200')).not.toBeInTheDocument();
  });

  it('renders the real interface name and packet count once system_stats has arrived', () => {
    render(<DashboardView {...baseProps} stats={liveStats} />);
    expect(screen.getByText(/en0/)).toBeInTheDocument();
    expect(screen.getByText(/184,200/)).toBeInTheDocument();
  });
});
