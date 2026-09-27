// @vitest-environment jsdom
//
// Coverage for ProtocolMatrixView: default encapsulation ordering, the
// direction toggle, layer-row click dispatch, and the rendered speed text.
import { afterEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ProtocolMatrixView } from '@/components/ProtocolMatrixView';
import { STATIC_LAYER_INFO, THEMES, formatSpeed } from '@/lib/osi-engine';
import { OSILayerInfo, OSILayerNumber, ProtocolNode } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const theme = THEMES.matrix;

function layerFixture(num: OSILayerNumber, rxSpeed: number, txSpeed: number): OSILayerInfo {
  return {
    ...STATIC_LAYER_INFO[num],
    rxSpeed,
    txSpeed,
    rxPacketsPerSec: 0,
    txPacketsPerSec: 0,
    totalBytes: 0,
    errorRate: 0,
    activeSockets: 0,
    sparkline: [],
    details: {
      primaryMetric: '',
      primaryValue: '',
      secondaryMetric: '',
      secondaryValue: '',
      tertiaryMetric: '',
      tertiaryValue: '',
      healthStatus: 'OPTIMAL',
      keyMetrics: {},
    },
  };
}

const layers: OSILayerInfo[] = [
  layerFixture(1, 100, 50),
  layerFixture(4, 2000, 1000),
  layerFixture(7, 500, 250),
];

describe('ProtocolMatrixView', () => {
  it('renders in encapsulation order (7 -> 4 -> 1) by default', () => {
    render(<ProtocolMatrixView layers={layers} theme={theme} onSelectLayer={() => {}} />);
    const labels = screen.getAllByText(/^Layer \d: /).map((el) => el.textContent);
    expect(labels).toEqual(['Layer 7: Application', 'Layer 4: Transport', 'Layer 1: Physical']);
  });

  it('reverses to decapsulation order (1 -> 4 -> 7) when toggled', () => {
    render(<ProtocolMatrixView layers={layers} theme={theme} onSelectLayer={() => {}} />);
    fireEvent.click(screen.getByText('DECAPSULATION (RX)'));
    const labels = screen.getAllByText(/^Layer \d: /).map((el) => el.textContent);
    expect(labels).toEqual(['Layer 1: Physical', 'Layer 4: Transport', 'Layer 7: Application']);
  });

  it('calls onSelectLayer with the clicked layer number', () => {
    const onSelectLayer = vi.fn();
    render(<ProtocolMatrixView layers={layers} theme={theme} onSelectLayer={onSelectLayer} />);
    fireEvent.click(screen.getByText('Layer 4: Transport'));
    expect(onSelectLayer).toHaveBeenCalledWith(4);
  });

  it('renders the combined rx+tx speed for each layer', () => {
    render(<ProtocolMatrixView layers={layers} theme={theme} onSelectLayer={() => {}} />);
    expect(screen.getByText(formatSpeed(2000 + 1000))).toBeInTheDocument();
  });

  // JAM-13: measured protocol hierarchy replaces the static per-layer
  // protocol badges (STATIC_LAYER_INFO's `protocols` list), which were
  // presented as if measured even though they were always the same
  // hard-coded illustration regardless of real traffic.
  // Every resulting share below (50%, 30%, 20%, 60%, 40%) is deliberately
  // distinct so assertions can look up one exact percentage text with no
  // ambiguity between the app-level and transport-level rollups.
  const hierarchy: ProtocolNode = {
    name: 'Capture',
    bytes: 1000,
    packets: 10,
    children: [
      {
        name: 'Ethernet',
        bytes: 1000,
        packets: 10,
        children: [
          {
            name: 'IP',
            bytes: 1000,
            packets: 10,
            children: [
              {
                name: 'TCP',
                bytes: 600,
                packets: 6,
                children: [
                  { name: 'HTTP', bytes: 500, packets: 5, children: [] },
                  { name: 'Unknown', bytes: 100, packets: 1, children: [] },
                ],
              },
              {
                name: 'UDP',
                bytes: 400,
                packets: 4,
                children: [
                  { name: 'DNS', bytes: 300, packets: 3, children: [] },
                  { name: 'Unknown', bytes: 100, packets: 1, children: [] },
                ],
              },
            ],
          },
        ],
      },
    ],
  };

  it('shows measured application-layer protocol shares, not the static illustration', () => {
    render(<ProtocolMatrixView layers={layers} theme={theme} onSelectLayer={() => {}} hierarchy={hierarchy} />);
    expect(screen.getByText('HTTP')).toBeInTheDocument();
    expect(screen.getByText('50.0%')).toBeInTheDocument();
    expect(screen.getByText('DNS')).toBeInTheDocument();
    expect(screen.getByText('30.0%')).toBeInTheDocument();
  });

  it('shows the Unknown/undecoded bucket rather than hiding it, merged across transports', () => {
    render(<ProtocolMatrixView layers={layers} theme={theme} onSelectLayer={() => {}} hierarchy={hierarchy} />);
    // 100 (TCP) + 100 (UDP) = 200 of 1000 total = one merged 20% entry, not two.
    expect(screen.getAllByText('Unknown')).toHaveLength(1);
    expect(screen.getByText('20.0%')).toBeInTheDocument();
  });

  it('shows measured transport-protocol shares on the Transport layer card', () => {
    render(<ProtocolMatrixView layers={layers} theme={theme} onSelectLayer={() => {}} hierarchy={hierarchy} />);
    expect(screen.getByText('TCP')).toBeInTheDocument();
    expect(screen.getByText('60.0%')).toBeInTheDocument();
    expect(screen.getByText('UDP')).toBeInTheDocument();
    expect(screen.getByText('40.0%')).toBeInTheDocument();
  });

  it('does not render the static protocol-badge list for layer 1 as if it were measured', () => {
    render(<ProtocolMatrixView layers={layers} theme={theme} onSelectLayer={() => {}} hierarchy={hierarchy} />);
    // Layer 1's static illustration is ['Ethernet PHY'] — with no
    // independent way to measure layer 1, that must not appear at all now
    // that this component only shows real numbers.
    expect(screen.queryByText('Ethernet PHY')).not.toBeInTheDocument();
  });

  it('shows a clear no-data state instead of fabricating percentages when hierarchy is absent', () => {
    render(<ProtocolMatrixView layers={layers} theme={theme} onSelectLayer={() => {}} />);
    expect(screen.getAllByText(/not yet measured/i).length).toBeGreaterThan(0);
    expect(screen.queryByText('60.0%')).not.toBeInTheDocument();
  });
});
