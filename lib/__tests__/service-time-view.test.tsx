// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { ServiceTimeView } from '@/components/ServiceTimeView';
import { THEMES } from '@/lib/osi-engine';
import type { ServiceTimeSummary } from '@/lib/types';

afterEach(cleanup);

const summaries: ServiceTimeSummary[] = [
  { protocol: 'DNS', answered: 42, unanswered: 2, untracked: 0, minUs: 310, maxUs: 2_400_000, sampleCount: 42, medianUs: 11_200, p95Us: 95_000 },
  { protocol: 'HTTP', answered: 0, unanswered: 0, untracked: 0, sampleCount: 0 },
];

describe('ServiceTimeView', () => {
  it('says nothing has been measured before the first update, rather than showing zeros', () => {
    render(<ServiceTimeView summaries={null} theme={THEMES.matrix} />);
    expect(screen.getByText(/not measured yet/i)).toBeInTheDocument();
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('shows counts and min/median/p95/max per protocol in readable units', () => {
    render(<ServiceTimeView summaries={summaries} theme={THEMES.matrix} />);
    const dns = screen.getByRole('row', { name: /DNS/ });
    for (const text of ['42', '2', '310 µs', '11.2 ms', '95.0 ms', '2.40 s']) {
      expect(within(dns).getByText(text)).toBeInTheDocument();
    }
  });

  it('shows a dash, not zero, for timing a protocol has no responses for', () => {
    render(<ServiceTimeView summaries={summaries} theme={THEMES.matrix} />);
    const http = screen.getByRole('row', { name: /HTTP/ });
    expect(within(http).getAllByText('—')).toHaveLength(4);
  });

  it('states which window the percentiles cover', () => {
    render(<ServiceTimeView summaries={summaries} theme={THEMES.matrix} />);
    expect(screen.getByText(/median and p95 over the most recent 42 DNS/i)).toBeInTheDocument();
  });
});
