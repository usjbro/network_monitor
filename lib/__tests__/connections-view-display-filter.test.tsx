// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ConnectionsView } from '@/components/ConnectionsView';
import { THEMES } from '@/lib/osi-engine';
import type { NetworkConnection } from '@/lib/types';
import type { CompiledDisplayFilter } from '@/lib/display-filter';
import * as exportModule from '@/lib/export';

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const connection = (id: string, processName: string): NetworkConnection => ({
  id, protocol: 'HTTPS', appLayerProtocol: 'HTTPS', transportProtocol: 'TCP',
  osiStack: `stack for ${id}`, localAddr: '10.0.0.1', localPort: 50000,
  remoteAddr: '10.0.0.2', remotePort: 443, processName, pid: 123,
  rxSpeed: 0, txSpeed: 0, rxBytesTotal: 10, txBytesTotal: 20,
  latencyMs: 1, packetLoss: 0, status: 'ESTABLISHED', encryption: 'TLS', sparkline: [],
});
const hidden = connection('conn-hidden', 'HiddenProcess');
const match = connection('conn-match', 'MatchProcess');
const displayFilter: CompiledDisplayFilter = (record) => record.kind === 'connection' && record.connection.id === 'conn-match';

describe('ConnectionsView shared display filter', () => {
  it('creates the CSV filename timestamp when export is clicked', () => {
    const download = vi.spyOn(exportModule, 'downloadBlob').mockImplementation(() => {});
    const now = vi.spyOn(Date, 'now').mockReturnValue(123456789);
    render(<ConnectionsView connections={[match]} theme={THEMES.matrix} />);

    fireEvent.click(screen.getByRole('button', { name: /export csv/i }));

    expect(download).toHaveBeenCalledWith(expect.any(String), 'connections-123456789.csv', 'text/csv');
    now.mockRestore();
  });

  it('scopes rows and CSV export while reporting matches against the full retained buffer', () => {
    const download = vi.spyOn(exportModule, 'downloadBlob').mockImplementation(() => {});
    const connections = [hidden, match];
    render(<ConnectionsView connections={connections} theme={THEMES.matrix}
      displayFilter={displayFilter} displayFilterExpression="tcp.port == 443" />);

    expect(screen.getByText('MatchProcess')).toBeInTheDocument();
    expect(screen.queryByText('HiddenProcess')).not.toBeInTheDocument();
    expect(screen.getByText(/1 of 2 buffered connections match/i)).toBeInTheDocument();
    expect(screen.getByText(/hidden connections remain buffered/i)).toBeInTheDocument();
    expect(connections).toEqual([hidden, match]);

    fireEvent.click(screen.getByRole('button', { name: /export csv/i }));
    expect(download.mock.calls[0][0]).toContain('MatchProcess');
    expect(download.mock.calls[0][0]).not.toContain('HiddenProcess');
  });

  it('falls back from a hidden selection and clears details when no connections match', () => {
    const { rerender } = render(<ConnectionsView connections={[hidden, match]} theme={THEMES.matrix} />);
    expect(screen.getByText('stack for conn-hidden')).toBeInTheDocument();
    rerender(<ConnectionsView connections={[hidden, match]} theme={THEMES.matrix} displayFilter={displayFilter} />);
    expect(screen.getByText('stack for conn-match')).toBeInTheDocument();
    expect(screen.queryByText('stack for conn-hidden')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('MatchProcess'));
    expect(screen.getByText('stack for conn-match')).toBeInTheDocument();
    rerender(<ConnectionsView connections={[hidden, match]} theme={THEMES.matrix} displayFilter={() => false} />);
    expect(screen.queryByText('stack for conn-match')).not.toBeInTheDocument();
  });

  it('counts shared matches before the local keyword refinement', () => {
    render(<ConnectionsView connections={[hidden, match]} theme={THEMES.matrix} displayFilter={displayFilter} />);
    fireEvent.change(screen.getByPlaceholderText(/filter sockets by ip/i), { target: { value: 'absent' } });
    expect(screen.getByText(/1 of 2 buffered connections match/i)).toBeInTheDocument();
    expect(screen.getByText(/no active sockets matching/i)).toBeInTheDocument();
  });
});
