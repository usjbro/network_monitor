// lib/__tests__/endpoints-view.test.tsx
// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { EndpointsView } from '../../components/EndpointsView';
import { THEMES } from '../osi-engine';
import { Conversation, Endpoint } from '../types';

// See connections-view-ownership.test.tsx's identical comment: this file
// imports afterEach explicitly (vitest.config.ts doesn't enable globals),
// so @testing-library/react's own auto-cleanup never registers — without
// this, renders from earlier tests accumulate in document.body.
afterEach(() => cleanup());

const theme = THEMES.sophisticated;

function endpoint(overrides: Partial<Endpoint> = {}): Endpoint {
  return {
    host: '93.184.216.34',
    rxBytesTotal: 100,
    txBytesTotal: 50,
    rxPacketsTotal: 2,
    txPacketsTotal: 1,
    rxSpeed: 10,
    txSpeed: 5,
    flowCount: 1,
    firstSeenMs: 0,
    lastSeenMs: 1000,
    processName: 'Safari',
    pid: 1234,
    ...overrides,
  };
}

function conversation(overrides: Partial<Conversation> = {}): Conversation {
  return {
    localAddr: '192.168.1.10',
    remoteAddr: '93.184.216.34',
    rxBytesTotal: 100,
    txBytesTotal: 50,
    rxPacketsTotal: 2,
    txPacketsTotal: 1,
    rxSpeed: 10,
    txSpeed: 5,
    flowCount: 1,
    firstSeenMs: 0,
    lastSeenMs: 1000,
    durationMs: 1000,
    processName: 'Safari',
    pid: 1234,
    ...overrides,
  };
}

describe('EndpointsView', () => {
  it('renders one row per host, matching a 50-flows-collapsed-into-one rollup', () => {
    render(
      <EndpointsView
        endpoints={[endpoint({ host: '93.184.216.34', flowCount: 50, rxBytesTotal: 5000, txBytesTotal: 3000 })]}
        conversations={[]}
        theme={theme}
      />,
    );
    expect(screen.getByText('93.184.216.34')).toBeInTheDocument();
    expect(screen.getByRole('table').querySelectorAll('tbody tr')).toHaveLength(1);
  });

  it('defaults to sorting by bytes descending', () => {
    render(
      <EndpointsView
        endpoints={[
          endpoint({ host: 'small.example', rxBytesTotal: 10, txBytesTotal: 0 }),
          endpoint({ host: 'big.example', rxBytesTotal: 9000, txBytesTotal: 1000 }),
          endpoint({ host: 'mid.example', rxBytesTotal: 500, txBytesTotal: 0 }),
        ]}
        conversations={[]}
        theme={theme}
      />,
    );
    const rows = screen.getAllByRole('row').slice(1); // drop header row
    const hostsInOrder = rows.map((row) => within(row).getAllByRole('cell')[0].textContent);
    expect(hostsInOrder).toEqual(['big.example', 'mid.example', 'small.example']);
  });

  it('toggles sort direction when the same column header is clicked twice', () => {
    render(
      <EndpointsView
        endpoints={[
          endpoint({ host: 'a.example', rxBytesTotal: 10, txBytesTotal: 0 }),
          endpoint({ host: 'b.example', rxBytesTotal: 9000, txBytesTotal: 0 }),
        ]}
        conversations={[]}
        theme={theme}
      />,
    );
    // Already descending by default; click once for ascending.
    fireEvent.click(screen.getByText(/bytes \(rx\/tx\)/i));
    let rows = screen.getAllByRole('row').slice(1);
    expect(within(rows[0]).getAllByRole('cell')[0].textContent).toBe('a.example');

    fireEvent.click(screen.getByText(/bytes \(rx\/tx\)/i));
    rows = screen.getAllByRole('row').slice(1);
    expect(within(rows[0]).getAllByRole('cell')[0].textContent).toBe('b.example');
  });

  it('sorts by an arbitrary column, e.g. flow count', () => {
    render(
      <EndpointsView
        endpoints={[
          endpoint({ host: 'a.example', flowCount: 1 }),
          endpoint({ host: 'b.example', flowCount: 9 }),
          endpoint({ host: 'c.example', flowCount: 5 }),
        ]}
        conversations={[]}
        theme={theme}
      />,
    );
    fireEvent.click(screen.getByText(/flows/i));
    const rows = screen.getAllByRole('row').slice(1);
    const hostsInOrder = rows.map((row) => within(row).getAllByRole('cell')[0].textContent);
    expect(hostsInOrder).toEqual(['b.example', 'c.example', 'a.example']);
  });

  it('sorts by process name when the Process (PID) header is clicked', () => {
    render(
      <EndpointsView
        endpoints={[
          endpoint({ host: 'a.example', processName: 'Chrome', rxBytesTotal: 300 }),
          endpoint({ host: 'b.example', processName: 'Firefox', rxBytesTotal: 200 }),
          endpoint({ host: 'c.example', processName: 'Safari', rxBytesTotal: 100 }),
        ]}
        conversations={[]}
        theme={theme}
      />,
    );
    fireEvent.click(screen.getByText(/process \(pid\)/i));
    const rows = screen.getAllByRole('row').slice(1);
    expect(rows.map((row) => within(row).getAllByRole('cell')[0].textContent)).toEqual([
      'c.example', 'b.example', 'a.example',
    ]);
  });

  it('sorts by combined RX and TX rate when the Rate header is clicked', () => {
    render(
      <EndpointsView
        endpoints={[
          endpoint({ host: 'a.example', rxBytesTotal: 900, rxSpeed: 1, txSpeed: 0 }),
          endpoint({ host: 'b.example', rxBytesTotal: 500, rxSpeed: 4, txSpeed: 5 }),
          endpoint({ host: 'c.example', rxBytesTotal: 100, rxSpeed: 3, txSpeed: 1 }),
        ]}
        conversations={[]}
        theme={theme}
      />,
    );
    fireEvent.click(screen.getByText(/rate \(rx\/tx\)/i));
    const rows = screen.getAllByRole('row').slice(1);
    expect(rows.map((row) => within(row).getAllByRole('cell')[0].textContent)).toEqual([
      'b.example', 'c.example', 'a.example',
    ]);
  });

  it('switches to the Conversations table and shows local<->remote pairs with duration', () => {
    render(
      <EndpointsView
        endpoints={[endpoint()]}
        conversations={[conversation({ localAddr: '192.168.1.10', remoteAddr: '93.184.216.34', durationMs: 4200 })]}
        theme={theme}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: /conversations/i }));
    expect(screen.getByText('192.168.1.10')).toBeInTheDocument();
    expect(screen.getByText('93.184.216.34')).toBeInTheDocument();
    expect(screen.getByText('4,200 ms')).toBeInTheDocument();
  });

  it('filters rows by the search box', () => {
    render(
      <EndpointsView
        endpoints={[endpoint({ host: 'match.example' }), endpoint({ host: 'other.example' })]}
        conversations={[]}
        theme={theme}
      />,
    );
    fireEvent.change(screen.getByPlaceholderText(/filter by host or process/i), { target: { value: 'match' } });
    expect(screen.getByText('match.example')).toBeInTheDocument();
    expect(screen.queryByText('other.example')).not.toBeInTheDocument();
  });

  it('shows and filters endpoint rows by the PTR hostname from ownership enrichment', () => {
    render(
      <EndpointsView
        endpoints={[endpoint({ host: '93.184.216.34', remoteHostname: 'edge.example.net' })]}
        conversations={[]}
        theme={theme}
      />,
    );

    expect(screen.getByText('edge.example.net')).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText(/filter by host or process/i), {
      target: { value: 'edge.example.net' },
    });
    expect(screen.getByText('93.184.216.34')).toBeInTheDocument();
  });

  describe('Ownership section', () => {
    it('shows "Enrichment disabled" until a row is selected and enrichment is off', () => {
      render(<EndpointsView endpoints={[endpoint()]} conversations={[]} theme={theme} enrichmentMode="off" />);
      fireEvent.click(screen.getByText('93.184.216.34'));
      expect(screen.getByText(/enrichment disabled/i)).toBeInTheDocument();
    });

    it('shows a "not yet looked up" button and calls onRequestLookup with the host', () => {
      const onRequestLookup = vi.fn();
      render(
        <EndpointsView
          endpoints={[endpoint()]}
          conversations={[]}
          theme={theme}
          enrichmentMode="on-demand"
          onRequestLookup={onRequestLookup}
        />,
      );
      fireEvent.click(screen.getByText('93.184.216.34'));
      fireEvent.click(screen.getByText(/not yet looked up/i));
      expect(onRequestLookup).toHaveBeenCalledWith('93.184.216.34');
    });

    it('shows org/ASN once enrichment data is attached to the row', () => {
      render(
        <EndpointsView
          endpoints={[endpoint({ enrichment: { org: 'EXAMPLE-ORG', asn: 'AS15133', source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' } })]}
          conversations={[]}
          theme={theme}
          enrichmentMode="on-demand"
        />,
      );
      fireEvent.click(screen.getByText('93.184.216.34'));
      expect(screen.getByText(/EXAMPLE-ORG/)).toBeInTheDocument();
      expect(screen.getByText(/AS15133/)).toBeInTheDocument();
    });
  });
});
