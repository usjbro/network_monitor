// @vitest-environment jsdom
//
// Regression coverage for issue #69: interface selection must be visible
// and usable from the header — the browser must never silently fall back
// to selecting the wrong interface just because the list hasn't loaded
// yet, and requesting the list must be an explicit, on-demand action, not
// automatic.
import { afterEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { HeaderBar } from '@/components/HeaderBar';
import { THEMES } from '@/lib/osi-engine';
import { NetworkInterface, SystemStats } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const noop = () => {};

const baseProps = {
  captureConfig: null,
  theme: THEMES.matrix,
  onSelectTheme: noop,
  isPaused: false,
  onTogglePause: noop,
  onReset: noop,
  crtEnabled: false,
  onToggleCrt: noop,
  onOpenInstall: noop,
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

describe('HeaderBar interface picker', () => {
  it('disables the picker before any system_stats event has arrived', () => {
    render(<HeaderBar {...baseProps} stats={null} availableInterfaces={[]} onListInterfaces={noop} onSelectInterface={noop} />);
    expect(screen.getByTitle(/capture interface/i)).toBeDisabled();
  });

  it('shows the current interface as a selectable option even before the list has loaded', () => {
    render(<HeaderBar {...baseProps} stats={liveStats} availableInterfaces={[]} onListInterfaces={noop} onSelectInterface={noop} />);
    const select = screen.getByTitle(/capture interface/i) as HTMLSelectElement;
    expect(select.value).toBe('en0');
    expect(screen.getByText('en0')).toBeInTheDocument();
  });

  it('requests the interface list on focus, not automatically', () => {
    const onListInterfaces = vi.fn();
    render(<HeaderBar {...baseProps} stats={liveStats} availableInterfaces={[]} onListInterfaces={onListInterfaces} onSelectInterface={noop} />);
    expect(onListInterfaces).not.toHaveBeenCalled();

    fireEvent.focus(screen.getByTitle(/capture interface/i));
    expect(onListInterfaces).toHaveBeenCalledTimes(1);
  });

  it('renders every interface from the list, with its first address, once loaded', () => {
    const interfaces: NetworkInterface[] = [
      { name: 'en0', addresses: ['192.168.1.104'] },
      { name: 'lo0', addresses: ['127.0.0.1', '::1'] },
    ];
    render(<HeaderBar {...baseProps} stats={liveStats} availableInterfaces={interfaces} onListInterfaces={noop} onSelectInterface={noop} />);
    expect(screen.getByText('en0 (192.168.1.104)')).toBeInTheDocument();
    expect(screen.getByText('lo0 (127.0.0.1)')).toBeInTheDocument();
  });

  it('calls onSelectInterface with the newly chosen interface name', () => {
    const onSelectInterface = vi.fn();
    const interfaces: NetworkInterface[] = [
      { name: 'en0', addresses: ['192.168.1.104'] },
      { name: 'lo0', addresses: ['127.0.0.1'] },
    ];
    render(<HeaderBar {...baseProps} stats={liveStats} availableInterfaces={interfaces} onListInterfaces={noop} onSelectInterface={onSelectInterface} />);
    fireEvent.change(screen.getByTitle(/capture interface/i), { target: { value: 'lo0' } });
    expect(onSelectInterface).toHaveBeenCalledWith('lo0');
  });
});
