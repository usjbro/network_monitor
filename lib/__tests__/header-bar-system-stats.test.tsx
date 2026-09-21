// @vitest-environment jsdom
//
// Regression coverage for issue #64: SystemStats used to be seeded with
// fabricated placeholder values (a fake hostname, interface speed, etc.)
// and rendered as if live. Now it is `null` until the agent's first real
// system_stats tick, and every field must render an explicit "—" while
// null rather than a zero/placeholder formatted as a measurement.
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { HeaderBar } from '@/components/HeaderBar';
import { THEMES } from '@/lib/osi-engine';
import { CaptureConfig, SystemStats } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const noop = () => {};

const baseProps = {
  theme: THEMES.matrix,
  onSelectTheme: noop,
  isPaused: false,
  onTogglePause: noop,
  onReset: noop,
  crtEnabled: false,
  onToggleCrt: noop,
  onOpenInstall: noop,
  captureConfig: null as CaptureConfig | null,
  captureFileStatus: null,
  availableInterfaces: [],
  onListInterfaces: noop,
  onSelectInterface: noop,
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

describe('HeaderBar system_stats rendering', () => {
  it('shows "—" placeholders before any system_stats event has arrived', () => {
    render(<HeaderBar {...baseProps} stats={null} />);
    expect(screen.queryByText('osi-gw-01')).not.toBeInTheDocument();
    // At least the hostname and interface slots render the placeholder —
    // getAllByText tolerates the RX/TX badges also rendering the same glyph.
    expect(screen.getAllByText('—').length).toBeGreaterThan(0);
  });

  it('renders real hostname/interface once system_stats has arrived', () => {
    render(<HeaderBar {...baseProps} stats={liveStats} />);
    expect(screen.getByText('osi-gw-01')).toBeInTheDocument();
    expect(screen.getByText('en0')).toBeInTheDocument();
  });

  it('never renders a fabricated interface speed or duplex mode', () => {
    render(<HeaderBar {...baseProps} stats={liveStats} />);
    // The old placeholder shape rendered "[10G]" next to the interface name
    // and a duplex-mode string — issue #64 removed both since neither is
    // measurable from this agent.
    expect(screen.queryByText(/\[\d+[GM]\]/)).not.toBeInTheDocument();
    expect(screen.queryByText(/full duplex/i)).not.toBeInTheDocument();
  });
});
