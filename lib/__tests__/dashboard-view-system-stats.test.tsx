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
  it('shows a waiting message until bandwidth samples arrive', () => {
    render(<DashboardView {...baseProps} stats={null} />);
    expect(screen.getByText(/waiting for bandwidth data/i)).toBeInTheDocument();
  });

  it('renders idle samples at zero height, with positive samples proportional to the peak', () => {
    const { container } = render(
      <DashboardView {...baseProps} stats={liveStats} historyRx={[0, 10]} historyTx={[0, 5]} />
    );
    const rxBars = container.getElementsByClassName('bg-emerald-500/80');
    const txBars = container.getElementsByClassName('bg-sky-500/80');
    expect(rxBars).toHaveLength(2);
    expect(txBars).toHaveLength(2);
    expect(rxBars[0]).toHaveStyle({ height: '0%' });
    expect(txBars[0]).toHaveStyle({ height: '0%' });
    expect(rxBars[1]).toHaveStyle({ height: '100%' });
    expect(txBars[1]).toHaveStyle({ height: '50%' });
  });

  it('labels measured histogram rates in decimal Mbps', () => {
    render(<DashboardView {...baseProps} stats={liveStats} historyRx={[10]} historyTx={[2.5]} />);
    expect(screen.getByText('RX: 10 Mbps')).toBeInTheDocument();
    expect(screen.getByText('TX: 2.5 Mbps')).toBeInTheDocument();
    expect(screen.queryByText(/waiting for bandwidth data/i)).not.toBeInTheDocument();
  });

  it('keeps measured rate tooltips readable with at most two decimal places', () => {
    render(<DashboardView {...baseProps} stats={liveStats} historyRx={[8.632047904191618]} historyTx={[0.125]} />);
    expect(screen.getByText('RX: 8.63 Mbps')).toBeInTheDocument();
    expect(screen.getByText('TX: 0.13 Mbps')).toBeInTheDocument();
  });

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
