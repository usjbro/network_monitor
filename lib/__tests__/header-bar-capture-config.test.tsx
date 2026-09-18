// @vitest-environment jsdom
//
// Regression coverage for issue #68: the active capture filter/snap length
// must always be visible in the header, not just apparent from the
// command bar you happened to type it into — an operator must never be
// unsure whether they're seeing everything.
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { HeaderBar } from '@/components/HeaderBar';
import { THEMES } from '@/lib/osi-engine';
import { CaptureConfig } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const noop = () => {};

const baseProps = {
  stats: null,
  theme: THEMES.matrix,
  onSelectTheme: noop,
  isPaused: false,
  onTogglePause: noop,
  onReset: noop,
  crtEnabled: false,
  onToggleCrt: noop,
  onOpenInstall: noop,
};

describe('HeaderBar capture_config rendering', () => {
  it('shows "—" for snap length and "none" for filter before any capture_config event has arrived', () => {
    render(<HeaderBar {...baseProps} captureConfig={null} />);
    expect(screen.getByText(/snaplen:/i)).toHaveTextContent('snaplen: —');
    expect(screen.getByText(/filter:/i)).toHaveTextContent('filter: none');
  });

  it('shows "none" for an active-but-empty filter (the default, healthy state)', () => {
    const config: CaptureConfig = { filter: null, snaplen: 65535 };
    render(<HeaderBar {...baseProps} captureConfig={config} />);
    expect(screen.getByText(/filter:/i)).toHaveTextContent('filter: none');
    expect(screen.getByText(/snaplen:/i)).toHaveTextContent('snaplen: 65535B');
  });

  it('renders the active filter expression once applied', () => {
    const config: CaptureConfig = { filter: 'tcp port 443', snaplen: 65535 };
    render(<HeaderBar {...baseProps} captureConfig={config} />);
    expect(screen.getByText(/filter:/i)).toHaveTextContent('filter: tcp port 443');
  });

  it('renders a narrowed snap length', () => {
    const config: CaptureConfig = { filter: null, snaplen: 96 };
    render(<HeaderBar {...baseProps} captureConfig={config} />);
    expect(screen.getByText(/snaplen:/i)).toHaveTextContent('snaplen: 96B');
  });
});
