// @vitest-environment jsdom
//
// Coverage for LayerDetailView: per-layer description lookup (proving the
// LAYER_DESCRIPTIONS table is wired, not defaulting), the out-of-range
// fallback, the back button, and the layer quick-selector.
import { afterEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { LayerDetailView } from '@/components/LayerDetailView';
import { STATIC_LAYER_INFO, THEMES } from '@/lib/osi-engine';
import { OSILayerInfo, OSILayerNumber } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const theme = THEMES.matrix;

function layerFixture(num: OSILayerNumber): OSILayerInfo {
  return {
    ...STATIC_LAYER_INFO[num],
    rxSpeed: 0,
    txSpeed: 0,
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

describe('LayerDetailView', () => {
  it('renders the layer-4 description, not a default', () => {
    render(<LayerDetailView layer={layerFixture(4)} theme={theme} onBack={() => {}} onSelectLayer={() => {}} />);
    expect(screen.getByText('Transport Layer (Layer 4)')).toBeInTheDocument();
    expect(screen.getByText(/TCP flow control/)).toBeInTheDocument();
  });

  it('renders the layer-7 description, distinct from layer 4', () => {
    render(<LayerDetailView layer={layerFixture(7)} theme={theme} onBack={() => {}} onSelectLayer={() => {}} />);
    expect(screen.getByText('Application Layer (Layer 7)')).toBeInTheDocument();
  });

  it('falls back to the layer-7 description for an out-of-range layer number', () => {
    const layer = { ...layerFixture(4), layer: 9 as unknown as OSILayerNumber };
    render(<LayerDetailView layer={layer} theme={theme} onBack={() => {}} onSelectLayer={() => {}} />);
    expect(screen.getByText('Application Layer (Layer 7)')).toBeInTheDocument();
  });

  it('calls onBack when "BACK TO STACK" is clicked', () => {
    const onBack = vi.fn();
    render(<LayerDetailView layer={layerFixture(4)} theme={theme} onBack={onBack} onSelectLayer={() => {}} />);
    fireEvent.click(screen.getByText('BACK TO STACK'));
    expect(onBack).toHaveBeenCalled();
  });

  it('calls onSelectLayer when a quick-selector button is clicked', () => {
    const onSelectLayer = vi.fn();
    render(<LayerDetailView layer={layerFixture(4)} theme={theme} onBack={() => {}} onSelectLayer={onSelectLayer} />);
    fireEvent.click(screen.getByText('L3'));
    expect(onSelectLayer).toHaveBeenCalledWith(3);
  });
});
