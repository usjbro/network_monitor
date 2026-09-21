// @vitest-environment jsdom
//
// Coverage for ProtocolMatrixView: default encapsulation ordering, the
// direction toggle, layer-row click dispatch, and the rendered speed text.
import { afterEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ProtocolMatrixView } from '@/components/ProtocolMatrixView';
import { STATIC_LAYER_INFO, THEMES, formatSpeed } from '@/lib/osi-engine';
import { OSILayerInfo, OSILayerNumber } from '@/lib/types';

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
});
