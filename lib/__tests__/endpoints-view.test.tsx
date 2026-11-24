// lib/__tests__/endpoints-view.test.tsx
// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { EndpointsView } from '../../components/EndpointsView';
import { THEMES, formatBytes } from '../osi-engine';
import { Conversation, Endpoint, RollupBounds, RollupState } from '../types';
import { rankRows } from '../rollup-rank';

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
    historyComplete: true,
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
    historyComplete: true,
    ...overrides,
  };
}

function ready<T>(rows: T[], bounds: Partial<RollupBounds> = {}): RollupState<T> {
  const none = { rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0 };
  return {
    status: 'ready',
    rows,
    bounds: {
      cap: 50_000, topN: 200, tracked: rows.length, evictions: 0, unkeyed: 0,
      sinceMs: 0, horizonMs: null, totals: none, evicted: none, ...bounds,
    },
  };
}

describe('EndpointsView', () => {
  it('renders one row per host, matching a 50-flows-collapsed-into-one rollup', () => {
    render(
      <EndpointsView
        endpoints={ready([endpoint({ host: '93.184.216.34', flowCount: 50, rxBytesTotal: 5000, txBytesTotal: 3000 })])}
        conversations={ready([])}
        theme={theme}
      />,
    );
    expect(screen.getByText('93.184.216.34')).toBeInTheDocument();
    expect(screen.getByRole('table').querySelectorAll('tbody tr')).toHaveLength(1);
  });

  it('defaults to sorting by bytes descending', () => {
    render(
      <EndpointsView
        endpoints={ready([
          endpoint({ host: 'small.example', rxBytesTotal: 10, txBytesTotal: 0 }),
          endpoint({ host: 'big.example', rxBytesTotal: 9000, txBytesTotal: 1000 }),
          endpoint({ host: 'mid.example', rxBytesTotal: 500, txBytesTotal: 0 }),
        ])}
        conversations={ready([])}
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
        endpoints={ready([
          endpoint({ host: 'a.example', rxBytesTotal: 10, txBytesTotal: 0 }),
          endpoint({ host: 'b.example', rxBytesTotal: 9000, txBytesTotal: 0 }),
        ])}
        conversations={ready([])}
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
        endpoints={ready([
          endpoint({ host: 'a.example', flowCount: 1 }),
          endpoint({ host: 'b.example', flowCount: 9 }),
          endpoint({ host: 'c.example', flowCount: 5 }),
        ])}
        conversations={ready([])}
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
        endpoints={ready([
          endpoint({ host: 'a.example', processName: 'Chrome', rxBytesTotal: 300 }),
          endpoint({ host: 'b.example', processName: 'Firefox', rxBytesTotal: 200 }),
          endpoint({ host: 'c.example', processName: 'Safari', rxBytesTotal: 100 }),
        ])}
        conversations={ready([])}
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
        endpoints={ready([
          endpoint({ host: 'a.example', rxBytesTotal: 900, rxSpeed: 1, txSpeed: 0 }),
          endpoint({ host: 'b.example', rxBytesTotal: 500, rxSpeed: 4, txSpeed: 5 }),
          endpoint({ host: 'c.example', rxBytesTotal: 100, rxSpeed: 3, txSpeed: 1 }),
        ])}
        conversations={ready([])}
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
        endpoints={ready([endpoint()])}
        conversations={ready([conversation({ localAddr: '192.168.1.10', remoteAddr: '93.184.216.34', durationMs: 4200 })])}
        theme={theme}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: /conversations/i }));
    expect(screen.getByText('192.168.1.10')).toBeInTheDocument();
    expect(screen.getByText('93.184.216.34')).toBeInTheDocument();
    expect(screen.getByText('4,200 ms')).toBeInTheDocument();
  });

  describe('observed DNS names', () => {
    const renderOne = (e: Partial<Endpoint>) =>
      render(<EndpointsView endpoints={ready([endpoint(e)])} conversations={ready([])} theme={theme} />);

    it('shows_the_observed_name_under_the_host', () => {
      renderOne({ observedName: 'example.com' });
      const el = screen.getByText('example.com');
      expect(el).toHaveAttribute('title', 'Learned from observed DNS');
      const host = screen.getByText('93.184.216.34');
      // The name follows the host inside the same cell, as a later sibling line.
      expect(host.closest('td')).toBe(el.closest('td'));
      expect(host.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    });

    it('shows_a_visible_DNS_tag_beside_an_observed_name', () => {
      renderOne({ observedName: 'example.com' });
      const tag = screen.getByText('DNS');
      // jsdom can't see Tailwind's CSS, so check the classes themselves, on the
      // tag and on the row around it, for anything that hides it until hover.
      for (const el of [tag, tag.parentElement!]) {
        expect(el.className).not.toMatch(/(^|\s)(hidden|invisible|sr-only|opacity-0)(\s|$)/);
        expect(el.className).not.toMatch(/(^|\s)(group-)?hover:/);
      }
      expect(tag).toHaveAttribute('title', 'Learned from observed DNS');
      expect(tag.closest('td')).toBe(screen.getByText('example.com').closest('td'));
    });

    it('shows_no_DNS_tag_for_a_ptr_name_alone', () => {
      renderOne({ remoteHostname: 'edge.example.net' });
      expect(screen.queryByText('DNS')).not.toBeInTheDocument();
    });

    it('the_DNS_tag_does_not_enter_the_search_text', () => {
      renderOne({ observedName: 'example.com' });
      fireEvent.change(screen.getByPlaceholderText(/search received rows/i), { target: { value: 'dns' } });
      expect(screen.queryByText('example.com')).not.toBeInTheDocument();
    });

    it('shows_the_ptr_name_too_when_it_differs', () => {
      renderOne({ observedName: 'example.com', remoteHostname: 'edge.example.net' });
      expect(screen.getByText('example.com')).toBeInTheDocument();
      expect(screen.getByText('edge.example.net')).toBeInTheDocument();
    });

    it('shows_one_line_when_observed_and_ptr_names_match', () => {
      renderOne({ observedName: 'example.com', remoteHostname: 'example.com' });
      expect(screen.getAllByText('example.com')).toHaveLength(1);
    });

    it('search_matches_the_observed_name', () => {
      render(
        <EndpointsView
          endpoints={ready([endpoint({ host: '10.0.0.1', observedName: 'wanted.example' }), endpoint({ host: '10.0.0.2' })])}
          conversations={ready([])}
          theme={theme}
        />,
      );
      fireEvent.change(screen.getByPlaceholderText(/search received rows/i), { target: { value: 'wanted' } });
      expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
      expect(screen.queryByText('10.0.0.2')).not.toBeInTheDocument();
    });

    it('wraps_a_long_name_instead_of_widening_the_table', () => {
      const long = `${'a'.repeat(60)}.${'b'.repeat(60)}.${'c'.repeat(60)}.example.com`;
      renderOne({ observedName: long });
      const span = screen.getByText(long);
      expect(span).toHaveClass('break-all');
      expect(span).not.toHaveClass('truncate');
      expect(span.closest('td')).toHaveClass('max-w-xs');
    });

    it('wraps_a_long_ptr_name_too', () => {
      const ptr = `${'p'.repeat(60)}.${'q'.repeat(60)}.${'r'.repeat(60)}.example.net`;
      renderOne({ remoteHostname: ptr });
      expect(screen.getByText(ptr)).toHaveClass('break-all');
    });

    it('renders_markup_in_a_name_as_text', () => {
      const evil = '<img src=x onerror=alert(1)>';
      const { container } = renderOne({ observedName: evil });
      expect(screen.getByText(evil)).toBeInTheDocument();
      expect(container.querySelector('img')).toBeNull();
    });
  });

  it('filters rows by the search box', () => {
    render(
      <EndpointsView
        endpoints={ready([endpoint({ host: 'match.example' }), endpoint({ host: 'other.example' })])}
        conversations={ready([])}
        theme={theme}
      />,
    );
    fireEvent.change(screen.getByPlaceholderText(/search received rows/i), { target: { value: 'match' } });
    expect(screen.getByText('match.example')).toBeInTheDocument();
    expect(screen.queryByText('other.example')).not.toBeInTheDocument();
  });

  it('shows and filters endpoint rows by the PTR hostname from ownership enrichment', () => {
    render(
      <EndpointsView
        endpoints={ready([endpoint({ host: '93.184.216.34', remoteHostname: 'edge.example.net' })])}
        conversations={ready([])}
        theme={theme}
      />,
    );

    expect(screen.getByText('edge.example.net')).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText(/search received rows/i), {
      target: { value: 'edge.example.net' },
    });
    expect(screen.getByText('93.184.216.34')).toBeInTheDocument();
  });

  describe('Ownership section', () => {
    it('shows "Enrichment disabled" until a row is selected and enrichment is off', () => {
      render(<EndpointsView endpoints={ready([endpoint()])} conversations={ready([])} theme={theme} enrichmentMode="off" />);
      fireEvent.click(screen.getByText('93.184.216.34'));
      expect(screen.getByText(/enrichment disabled/i)).toBeInTheDocument();
    });

    it('shows a "not yet looked up" button and calls onRequestLookup with the host', () => {
      const onRequestLookup = vi.fn();
      render(
        <EndpointsView
          endpoints={ready([endpoint()])}
          conversations={ready([])}
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
          endpoints={ready([endpoint({ enrichment: { org: 'EXAMPLE-ORG', asn: 'AS15133', source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' } })])}
          conversations={ready([])}
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

// KAN-131 Task 6: a bounded, partial list says exactly what it leaves out.
describe('EndpointsView partial lists', () => {
  const hostsOf = () =>
    screen.getAllByRole('row').slice(1).map((row) => within(row).getAllByRole('cell')[0].textContent);
  const search = (value: string) =>
    fireEvent.change(screen.getByPlaceholderText(/search received rows/i), { target: { value } });
  const rankBy = (value: string) =>
    fireEvent.change(screen.getByLabelText(/rank by/i), { target: { value } });

  // Rows whose four rankings all differ and have no ties (396 shares no
  // factor with 7, 13 or 31).
  const many = (n = 396) =>
    Array.from({ length: n }, (_, i) =>
      endpoint({
        host: `host-${i}.example`,
        rxBytesTotal: i + 1, txBytesTotal: 0,
        rxPacketsTotal: ((i * 7) % n) + 1, txPacketsTotal: 0,
        rxSpeed: ((i * 13) % n) + 1, txSpeed: 0,
        lastSeenMs: ((i * 31) % n) + 1,
      }),
    );
  const manyConv = (n = 396) =>
    many(n).map((e) => conversation({ ...e, localAddr: '10.0.0.1', remoteAddr: e.host }));

  describe('counts line and notices', () => {
    it('says what is shown, received and tracked, with the agent-relative start', () => {
      render(<EndpointsView endpoints={ready(many(), { tracked: 50_000, sinceMs: 1200 })} conversations={ready([])} theme={theme} />);
      expect(screen.getByText('Showing 200 of 396 received; 50,000 hosts tracked since 1,200 ms.')).toBeInTheDocument();
      expect(screen.getAllByRole('row').length - 1).toBe(200);
    });

    it('omits the since clause while sinceMs is null', () => {
      render(<EndpointsView endpoints={ready(many(), { tracked: 50_000, sinceMs: null })} conversations={ready([])} theme={theme} />);
      expect(screen.getByText('Showing 200 of 396 received; 50,000 hosts tracked.')).toBeInTheDocument();
    });

    it('says conversations throughout for the conversations table', () => {
      render(
        <EndpointsView
          endpoints={ready([])}
          conversations={ready(manyConv(), { tracked: 50_000, sinceMs: 1200, evictions: 3, cap: 50_000, horizonMs: 5000, evicted: { rxBytes: 1, txBytes: 2, rxPackets: 0, txPackets: 0 } })}
          theme={theme}
        />,
      );
      fireEvent.click(screen.getByRole('button', { name: /conversations/i }));
      expect(screen.getByText('Showing 200 of 396 received; 50,000 conversations tracked since 1,200 ms.')).toBeInTheDocument();
      expect(screen.getByText(`3 evictions (cap 50,000): least recently active conversations were dropped; their totals (${formatBytes(3)}) are not in any row.`)).toBeInTheDocument();
      expect(screen.getByText('Conversations last active at or before 5,000 ms may be missing.')).toBeInTheDocument();
    });

    it('shows the eviction notice only when evictions > 0', () => {
      const evicted = { rxBytes: 1_000_000, txBytes: 500_000, rxPackets: 0, txPackets: 0 };
      const { rerender } = render(
        <EndpointsView endpoints={ready(many(5), { evictions: 812, evicted })} conversations={ready([])} theme={theme} />,
      );
      expect(
        screen.getByText(`812 evictions (cap 50,000): least recently active hosts were dropped; their totals (${formatBytes(1_500_000)}) are not in any row.`),
      ).toBeInTheDocument();
      rerender(<EndpointsView endpoints={ready(many(5), { evictions: 0, evicted })} conversations={ready([])} theme={theme} />);
      expect(screen.queryByText(/evictions \(cap/)).not.toBeInTheDocument();
    });

    it('shows the horizon notice only when horizonMs is not null', () => {
      const { rerender } = render(
        <EndpointsView endpoints={ready(many(5), { horizonMs: 41_200 })} conversations={ready([])} theme={theme} />,
      );
      expect(screen.getByText('Hosts last active at or before 41,200 ms may be missing.')).toBeInTheDocument();
      rerender(<EndpointsView endpoints={ready(many(5), { horizonMs: null })} conversations={ready([])} theme={theme} />);
      expect(screen.queryByText(/may be missing/)).not.toBeInTheDocument();
      rerender(<EndpointsView endpoints={ready(many(5), { horizonMs: 0 })} conversations={ready([])} theme={theme} />);
      expect(screen.getByText('Hosts last active at or before 0 ms may be missing.')).toBeInTheDocument();
    });

    it('shows the unkeyed notice only when unkeyed > 0', () => {
      const { rerender } = render(
        <EndpointsView endpoints={ready(many(5), { unkeyed: 1234 })} conversations={ready([])} theme={theme} />,
      );
      expect(screen.getByText('1,234 packets had an unreadable address and are not counted.')).toBeInTheDocument();
      rerender(<EndpointsView endpoints={ready(many(5), { unkeyed: 0 })} conversations={ready([])} theme={theme} />);
      expect(screen.queryByText(/unreadable address/)).not.toBeInTheDocument();
    });

    it('does not show a notice for the other table', () => {
      render(
        <EndpointsView endpoints={ready(many(5))} conversations={ready(manyConv(5), { unkeyed: 9, evictions: 2, horizonMs: 3 })} theme={theme} />,
      );
      expect(screen.queryByText(/unreadable address/)).not.toBeInTheDocument();
      expect(screen.queryByText(/evictions \(cap/)).not.toBeInTheDocument();
      expect(screen.queryByText(/may be missing/)).not.toBeInTheDocument();
    });
  });

  describe('search', () => {
    it('uses the placeholder "Search received rows…"', () => {
      render(<EndpointsView endpoints={ready(many(3))} conversations={ready([])} theme={theme} />);
      expect(screen.getByPlaceholderText('Search received rows…')).toBeInTheDocument();
    });

    it('finds a row ranked 300th, which is not displayed without a search', () => {
      render(<EndpointsView endpoints={ready(many(), { tracked: 50_000 })} conversations={ready([])} theme={theme} />);
      expect(screen.queryByText('host-96.example')).not.toBeInTheDocument();
      search('host-96.');
      expect(hostsOf()).toEqual(['host-96.example']);
      expect(screen.getByText('1 matches in 396 received; 50,000 hosts tracked since 0 ms.')).toBeInTheDocument();
    });

    it('shows every match, not just topN, with a matches line', () => {
      render(<EndpointsView endpoints={ready(many(), { tracked: 50_000, sinceMs: 1200 })} conversations={ready([])} theme={theme} />);
      search('host-');
      expect(hostsOf()).toHaveLength(396);
      expect(screen.getByText('396 matches in 396 received; 50,000 hosts tracked since 1,200 ms.')).toBeInTheDocument();
    });

    it('says how many matched', () => {
      render(
        <EndpointsView
          endpoints={ready([...many(393), endpoint({ host: 'zz-a' }), endpoint({ host: 'zz-b' }), endpoint({ host: 'zz-c' })], { tracked: 50_000, sinceMs: 1200 })}
          conversations={ready([])}
          theme={theme}
        />,
      );
      search('zz-');
      expect(screen.getByText('3 matches in 396 received; 50,000 hosts tracked since 1,200 ms.')).toBeInTheDocument();
    });

    it('an empty result says how many more are tracked but not sent', () => {
      render(<EndpointsView endpoints={ready(many(), { tracked: 50_000 })} conversations={ready([])} theme={theme} />);
      search('nothing-matches');
      expect(screen.getByText('No match among the 396 rows received; 49,604 more are tracked but not sent.')).toBeInTheDocument();
    });

    it('an empty result says only the received count when nothing is unsent', () => {
      render(<EndpointsView endpoints={ready(many(10))} conversations={ready([])} theme={theme} />);
      search('nothing-matches');
      expect(screen.getByText('No match among the 10 rows received.')).toBeInTheDocument();
      expect(screen.queryByText(/not sent/)).not.toBeInTheDocument();
    });

    it('an empty result is absent while there is a match', () => {
      render(<EndpointsView endpoints={ready(many(10))} conversations={ready([])} theme={theme} />);
      search('host-1');
      expect(screen.queryByText(/No match among/)).not.toBeInTheDocument();
    });

    it('the conversations table counts its own received rows', () => {
      render(<EndpointsView endpoints={ready(many(5))} conversations={ready(manyConv(300), { tracked: 1000 })} theme={theme} />);
      fireEvent.click(screen.getByRole('button', { name: /conversations/i }));
      search('nothing-matches');
      expect(screen.getByText('No match among the 300 rows received; 700 more are tracked but not sent.')).toBeInTheDocument();
    });
  });

  describe('rank by and top N', () => {
    it('shows 200 of 396 received by default, the first 200 by bytes', () => {
      const rows = many();
      render(<EndpointsView endpoints={ready(rows)} conversations={ready([])} theme={theme} />);
      expect(hostsOf()).toEqual(rankRows(rows, 'bytes').slice(0, 200).map((r) => r.host));
      expect(screen.getByLabelText(/rank by/i)).toHaveValue('bytes');
    });

    it('honours a smaller topN from the bounds', () => {
      render(<EndpointsView endpoints={ready(many(50), { topN: 7 })} conversations={ready([])} theme={theme} />);
      expect(hostsOf()).toHaveLength(7);
      expect(screen.getByText(/^Showing 7 of 50 received;/)).toBeInTheDocument();
    });

    for (const ranking of ['bytes', 'packets', 'rate', 'recent'] as const) {
      it(`Rank by ${ranking} shows rankRows(...).slice(0, topN) in that order`, () => {
        const rows = many();
        render(<EndpointsView endpoints={ready(rows)} conversations={ready([])} theme={theme} />);
        rankBy(ranking);
        expect(hostsOf()).toEqual(rankRows(rows, ranking).slice(0, 200).map((r) => r.host));
        // The sort is the ranking's own column, descending, so there is no note.
        expect(screen.queryByText(/sorted within/)).not.toBeInTheDocument();
      });
    }

    it('Rank by is kept per table and defaults to bytes in each', () => {
      render(<EndpointsView endpoints={ready(many())} conversations={ready(manyConv())} theme={theme} />);
      rankBy('packets');
      fireEvent.click(screen.getByRole('button', { name: /conversations/i }));
      expect(screen.getByLabelText(/rank by/i)).toHaveValue('bytes');
      rankBy('rate');
      fireEvent.click(screen.getByRole('button', { name: /endpoints/i }));
      expect(screen.getByLabelText(/rank by/i)).toHaveValue('packets');
      fireEvent.click(screen.getByRole('button', { name: /conversations/i }));
      expect(screen.getByLabelText(/rank by/i)).toHaveValue('rate');
    });

    it('clicking a column never changes Rank by or which rows are chosen', () => {
      const rows = many();
      render(<EndpointsView endpoints={ready(rows)} conversations={ready([])} theme={theme} />);
      const chosen = rankRows(rows, 'bytes').slice(0, 200);
      fireEvent.click(screen.getByText('Packets'));
      expect(screen.getByLabelText(/rank by/i)).toHaveValue('bytes');
      const packetsOrder = [...chosen].sort((a, b) => b.rxPacketsTotal - a.rxPacketsTotal).map((r) => r.host);
      expect(hostsOf()).toEqual(packetsOrder);
    });
  });

  describe('sort note', () => {
    const noteTop = 'sorted within the top 200 by bytes';
    it('is absent for the default sort', () => {
      render(<EndpointsView endpoints={ready(many())} conversations={ready([])} theme={theme} />);
      expect(screen.queryByText(noteTop)).not.toBeInTheDocument();
    });
    it('appears for Packets descending under Rank by bytes', () => {
      render(<EndpointsView endpoints={ready(many())} conversations={ready([])} theme={theme} />);
      fireEvent.click(screen.getByText('Packets'));
      expect(screen.getByText(noteTop)).toBeInTheDocument();
    });
    it('appears when the Rank by column is sorted ascending, and goes when descending again', () => {
      render(<EndpointsView endpoints={ready(many())} conversations={ready([])} theme={theme} />);
      fireEvent.click(screen.getByText(/bytes \(rx\/tx\)/i));
      expect(screen.getByText(noteTop)).toBeInTheDocument();
      fireEvent.click(screen.getByText(/bytes \(rx\/tx\)/i));
      expect(screen.queryByText(noteTop)).not.toBeInTheDocument();
    });
    it('names the current ranking', () => {
      render(<EndpointsView endpoints={ready(many())} conversations={ready([])} theme={theme} />);
      rankBy('packets');
      fireEvent.click(screen.getByText(/bytes \(rx\/tx\)/i));
      expect(screen.getByText('sorted within the top 200 by packets')).toBeInTheDocument();
    });
    it('is "sorted within matching received rows" with a search, and not the top note', () => {
      render(<EndpointsView endpoints={ready(many())} conversations={ready([])} theme={theme} />);
      search('host-');
      expect(screen.getByText('sorted within matching received rows')).toBeInTheDocument();
      expect(screen.queryByText(noteTop)).not.toBeInTheDocument();
    });
    it('the matching-rows note is absent without a search', () => {
      render(<EndpointsView endpoints={ready(many())} conversations={ready([])} theme={theme} />);
      fireEvent.click(screen.getByText('Packets'));
      expect(screen.queryByText('sorted within matching received rows')).not.toBeInTheDocument();
    });
  });

  describe('stable column sort', () => {
    it('keeps rank order among rows that tie in the sorted column', () => {
      const rows = [1, 2, 3, 4, 5, 6].map((i) => endpoint({ host: `t${i}`, rxBytesTotal: (7 - i) * 10, flowCount: 4 }));
      render(<EndpointsView endpoints={ready(rows)} conversations={ready([])} theme={theme} />);
      fireEvent.click(screen.getByText('Flows'));
      expect(hostsOf()).toEqual(['t1', 't2', 't3', 't4', 't5', 't6']);
      fireEvent.click(screen.getByText('Flows'));
      expect(hostsOf()).toEqual(['t1', 't2', 't3', 't4', 't5', 't6']);
    });
  });

  describe('history not complete', () => {
    const cells = (i: number) => within(screen.getAllByRole('row')[1]).getAllByRole('cell')[i];

    it('marks bytes, packets, flows and duration with a tooltip, but not rate or last seen', () => {
      render(
        <EndpointsView endpoints={ready([])} conversations={ready([conversation({ historyComplete: false })])} theme={theme} />,
      );
      fireEvent.click(screen.getByRole('button', { name: /conversations/i }));
      for (const i of [2, 3, 5, 8]) expect(cells(i).textContent).toMatch(/^≥/);
      for (const i of [4, 7]) expect(cells(i).textContent).not.toContain('≥');
      expect(cells(6).textContent).toContain('may be earlier');
      expect(cells(7).textContent).not.toContain('may be earlier');
      const mark = within(cells(2)).getByText('≥');
      expect(mark).toHaveAttribute('title', 'Earlier history may have been evicted. The rate can be low in the second this row returned.');
    });

    it('endpoints have no duration column and three marks', () => {
      render(<EndpointsView endpoints={ready([endpoint({ historyComplete: false })])} conversations={ready([])} theme={theme} />);
      expect(screen.getAllByText('≥')).toHaveLength(3);
      for (const i of [2, 3, 5]) expect(cells(i).textContent).toMatch(/^≥/);
      expect(cells(4).textContent).not.toContain('≥');
    });

    it('shows nothing when history is complete', () => {
      render(<EndpointsView endpoints={ready([endpoint({ historyComplete: true })])} conversations={ready([])} theme={theme} />);
      expect(screen.queryByText('≥')).not.toBeInTheDocument();
      expect(screen.queryByText(/may be earlier/)).not.toBeInTheDocument();
    });

    it('marks only the incomplete row', () => {
      render(
        <EndpointsView
          endpoints={ready([endpoint({ host: 'a', historyComplete: true }), endpoint({ host: 'b', historyComplete: false, rxBytesTotal: 1 })])}
          conversations={ready([])}
          theme={theme}
        />,
      );
      expect(screen.getAllByText('≥')).toHaveLength(3);
      expect(screen.getAllByText(/may be earlier/)).toHaveLength(1);
    });
  });

  describe('selection', () => {
    it('keeps the panel for a selected row that a search filters out', () => {
      render(<EndpointsView endpoints={ready(many(5))} conversations={ready([])} theme={theme} />);
      fireEvent.click(screen.getByText('host-3.example'));
      search('host-1');
      expect(screen.queryByText('host-3.example')).not.toBeInTheDocument();
      expect(screen.getByText('OWNERSHIP FOR host-3.example')).toBeInTheDocument();
      expect(screen.queryByText(/No longer among the received rows/)).not.toBeInTheDocument();
    });

    it('keeps the panel when Rank by hides the selected row', () => {
      const rows = many(10);
      render(<EndpointsView endpoints={ready(rows, { topN: 3 })} conversations={ready([])} theme={theme} />);
      const top = rankRows(rows, 'bytes')[0].host;
      fireEvent.click(screen.getByText(top));
      rankBy('packets'); // top 3 by packets do not include the top host by bytes
      expect(rankRows(rows, 'packets').slice(0, 3).map((r) => r.host)).not.toContain(top);
      expect(screen.queryByText(top)).not.toBeInTheDocument();
      expect(screen.getByText(`OWNERSHIP FOR ${top}`)).toBeInTheDocument();
      expect(screen.queryByText(/No longer among the received rows/)).not.toBeInTheDocument();
    });

    it('says the row is no longer among the received rows once it is not received', () => {
      const { rerender } = render(<EndpointsView endpoints={ready(many(5))} conversations={ready([])} theme={theme} />);
      fireEvent.click(screen.getByText('host-3.example'));
      rerender(<EndpointsView endpoints={ready(many(3))} conversations={ready([])} theme={theme} />);
      expect(screen.getByText('No longer among the received rows')).toBeInTheDocument();
      expect(screen.queryByText(/OWNERSHIP FOR host-3/)).not.toBeInTheDocument();
    });

    it('names the row that is no longer received, as text', () => {
      const name = '<img src=x>';
      const { rerender } = render(<EndpointsView endpoints={ready([endpoint({ host: name })])} conversations={ready([])} theme={theme} />);
      fireEvent.click(screen.getByText(name));
      rerender(<EndpointsView endpoints={ready(many(3))} conversations={ready([])} theme={theme} />);
      const panel = screen.getByText('No longer among the received rows').parentElement!;
      expect(panel).toHaveTextContent(name);
      expect(panel.querySelector('img')).toBeNull();
    });

    it('after a reset with a row selected and a search active, leaves no old notice or panel', () => {
      const evicted = { rxBytes: 9, txBytes: 9, rxPackets: 0, txPackets: 0 };
      const before = ready(many(5), {
        tracked: 50_000, sinceMs: 1200, evictions: 812, horizonMs: 41_200, unkeyed: 7, evicted,
      });
      const { rerender } = render(<EndpointsView endpoints={before} conversations={ready([])} theme={theme} />);
      fireEvent.click(screen.getByText('host-3.example'));
      search('host-');
      expect(screen.getByText(/812 evictions/)).toBeInTheDocument();
      rerender(
        <EndpointsView
          endpoints={ready([endpoint({ host: 'fresh.example' })], { tracked: 1, sinceMs: 77 })}
          conversations={ready([])}
          theme={theme}
        />,
      );
      expect(screen.queryByText(/evictions/)).not.toBeInTheDocument();
      expect(screen.queryByText(/may be missing/)).not.toBeInTheDocument();
      expect(screen.queryByText(/unreadable address/)).not.toBeInTheDocument();
      expect(screen.queryByText(/1,200 ms/)).not.toBeInTheDocument();
      expect(screen.queryByText(/OWNERSHIP FOR host-3/)).not.toBeInTheDocument();
      expect(screen.getByText('No longer among the received rows')).toBeInTheDocument();
      expect(screen.getByText('No match among the 1 rows received.')).toBeInTheDocument();
      expect(screen.getByText('0 matches in 1 received; 1 hosts tracked since 77 ms.')).toBeInTheDocument();
    });
  });

  it('formats row times and packet counts as en-US, like the notices, whatever the browser locale', () => {
    const original = Number.prototype.toLocaleString;
    const spy = vi.spyOn(Number.prototype, 'toLocaleString').mockImplementation(function (this: number, locale, options) {
      return original.call(this, locale ?? 'de-DE', options);
    });
    try {
      const times = { rxPacketsTotal: 1234, txPacketsTotal: 5678, firstSeenMs: 11111, lastSeenMs: 22222 };
      render(
        <EndpointsView
          endpoints={ready([endpoint({ host: 'h.example', ...times })])}
          conversations={ready([conversation({ ...times, durationMs: 33333 })])}
          theme={theme}
        />,
      );
      for (const shown of ['1,234 / 5,678', '11,111 ms', '22,222 ms']) expect(screen.getByText(shown)).toBeInTheDocument();
      fireEvent.click(screen.getByText('conversations'));
      for (const shown of ['1,234 / 5,678', '11,111 ms', '22,222 ms', '33,333 ms']) expect(screen.getByText(shown)).toBeInTheDocument();
    } finally {
      spy.mockRestore();
    }
  });

  it('renders markup in a host or conversation name as text', () => {
    const evil = '<img src=x onerror=alert(1)>';
    const { container } = render(
      <EndpointsView endpoints={ready([endpoint({ host: evil })])} conversations={ready([conversation({ remoteAddr: evil })])} theme={theme} />,
    );
    expect(screen.getByText(evil)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /conversations/i }));
    expect(screen.getByText(evil)).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
  });
});
