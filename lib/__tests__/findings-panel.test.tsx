// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { FindingsPanel } from '@/components/FindingsPanel';
import { THEMES } from '@/lib/osi-engine';
import type { Finding } from '@/lib/types';

const findings: Finding[] = [
  { id: 'finding-1', timestamp: '1000', severity: 'warning', code: 'retransmission', summary: 'retransmitted segment', frameId: 'pkt-1' },
  { id: 'finding-2', timestamp: '2000', severity: 'note', code: 'connection-reset', summary: 'connection reset', flowId: 'Tcp-flow-1' },
  { id: 'finding-3', timestamp: '3000', severity: 'warning', code: 'malformed-frame', summary: '58-byte frame did not decode as Ethernet framing' },
];

describe('FindingsPanel', () => {
  it('renders one row per finding, grouped under a heading per code', () => {
    render(<FindingsPanel findings={findings} theme={THEMES.matrix} onNavigate={() => {}} />);
    expect(screen.getByText(/RETRANSMISSION/)).toBeInTheDocument();
    expect(screen.getByText(/CONNECTION-RESET/)).toBeInTheDocument();
    expect(screen.getByText(/MALFORMED-FRAME/)).toBeInTheDocument();
    expect(screen.getByText('retransmitted segment')).toBeInTheDocument();
    expect(screen.getByText('connection reset')).toBeInTheDocument();
    expect(screen.getByText('58-byte frame did not decode as Ethernet framing')).toBeInTheDocument();
  });

  it('a retransmission row is clickable and navigates to its frame', () => {
    const onNavigate = vi.fn();
    render(<FindingsPanel findings={findings} theme={THEMES.matrix} onNavigate={onNavigate} />);
    fireEvent.click(screen.getByRole('button', { name: /retransmitted segment/ }));
    expect(onNavigate).toHaveBeenCalledWith({ kind: 'frame', id: 'pkt-1' });
  });

  it('a connection-reset row is clickable and navigates to its flow', () => {
    const onNavigate = vi.fn();
    render(<FindingsPanel findings={findings} theme={THEMES.matrix} onNavigate={onNavigate} />);
    fireEvent.click(screen.getByRole('button', { name: /connection reset/ }));
    expect(onNavigate).toHaveBeenCalledWith({ kind: 'flow', id: 'Tcp-flow-1' });
  });

  it('a malformed-frame row has no clickable affordance, since nothing was ever produced to navigate to', () => {
    render(<FindingsPanel findings={findings} theme={THEMES.matrix} onNavigate={() => {}} />);
    const row = screen.getByText('58-byte frame did not decode as Ethernet framing');
    expect(row.closest('[role="button"]')).toBeNull();
    expect(row.closest('button')).toBeNull();
  });

  it('renders an empty state with no findings', () => {
    render(<FindingsPanel findings={[]} theme={THEMES.matrix} onNavigate={() => {}} />);
    expect(screen.getByText(/no findings/i)).toBeInTheDocument();
  });
});
