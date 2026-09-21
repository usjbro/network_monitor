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
import { CaptureConfig, CaptureFileStatus } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const noop = () => {};

const baseProps = {
  stats: null,
  captureFileStatus: null,
  theme: THEMES.matrix,
  onSelectTheme: noop,
  isPaused: false,
  onTogglePause: noop,
  onReset: noop,
  crtEnabled: false,
  onToggleCrt: noop,
  onOpenInstall: noop,
  availableInterfaces: [],
  onListInterfaces: noop,
  onSelectInterface: noop,
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

describe('HeaderBar capture_file_status rendering (epic #55/JAM-132/GitHub #70)', () => {
  it('shows no recording indicator before any capture_file_status tick arrives', () => {
    render(<HeaderBar {...baseProps} captureConfig={null} />);
    expect(screen.queryByText(/recording/i)).toBeNull();
  });

  it('shows no recording indicator while writing is false, even with a known last-active path', () => {
    const status: CaptureFileStatus = { writing: false, path: '/tmp/capture-0001.pcapng', bytesWritten: 4096, backpressureDrops: 0 };
    render(<HeaderBar {...baseProps} captureConfig={null} captureFileStatus={status} />);
    expect(screen.queryByText(/recording/i)).toBeNull();
  });

  it('shows the recording indicator with the active file\'s basename while writing', () => {
    const status: CaptureFileStatus = {
      writing: true,
      path: '/Users/me/captures/incident-0002.pcapng',
      bytesWritten: 1048576,
      ringFile: 2,
      backpressureDrops: 0,
    };
    render(<HeaderBar {...baseProps} captureConfig={null} captureFileStatus={status} />);
    expect(screen.getByText(/recording/i)).toHaveTextContent('recording incident-0002.pcapng');
  });
});
