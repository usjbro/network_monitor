// @vitest-environment jsdom
// JAM-18 Task 3: IoGraphView rendering, keyboard control and the
// compare-and-swap series editor.
import { afterEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { IoGraphView, formatSi, type SetIoSeriesMessage } from '@/components/IoGraphView';
import { THEMES } from '@/lib/osi-engine';
import { createHistory, ingestBuckets, ingestStatus } from '@/lib/io-graph';
import type { IoSeriesStatus } from '@/lib/types';

afterEach(cleanup);

const T0 = 1_794_120_000_000;

const status: IoSeriesStatus = {
  revision: 3,
  epoch: 'aaaabbbb',
  replayWaiting: false,
  series: [
    { id: 'all', filter: '', ok: true },
    { id: 'dns', filter: 'dns', ok: true },
  ],
};

function filledHistory() {
  const h = createHistory();
  ingestStatus(h, status);
  for (let s = 0; s < 60; s++) {
    const start = T0 + s * 1000;
    ingestBuckets(h, {
      revision: 3, epoch: 'aaaabbbb', bucketMs: 100, coveredFromMs: start, coveredToMs: start + 1000,
      notObserved: [], loss: { kernelDropped: 0, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 },
      series: [
        { id: 'all', late: 0, lateBuckets: [], buckets: Array.from({ length: 10 }, (_, i) => [start + i * 100, 10, 1000] as [number, number, number]) },
        { id: 'dns', late: 0, lateBuckets: [], buckets: [[start, 1, 90]] },
      ],
    });
  }
  return h;
}

function view(props: Partial<React.ComponentProps<typeof IoGraphView>> = {}) {
  const onSend = props.onSend ?? vi.fn(async () => true);
  const h = props.history ?? filledHistory();
  const utils = render(
    <IoGraphView history={h} version={h.version} status={status} connected theme={THEMES.matrix} onSend={onSend} now={() => T0} timeZone="UTC" {...props} />,
  );
  return { ...utils, onSend, history: h };
}

describe('IoGraphView', () => {
  it('shows an honest empty state with no series', () => {
    view({ history: createHistory(), status: { ...status, series: [] } });
    expect(screen.getByTestId('io-empty')).toHaveTextContent('No IO graph series configured');
    expect(screen.getByTestId('io-horizon')).toHaveTextContent('No IO graph data yet');
  });

  it('draws one path per series with labelled axes and the horizon', () => {
    const { container } = view();
    expect(screen.getByTestId('io-path-all').getAttribute('d')).toMatch(/^M[\d.]+,[\d.]+(L[\d.]+,[\d.]+)+$/);
    expect(screen.getByTestId('io-path-dns').getAttribute('d')).not.toBe('');
    const labels = Array.from(container.querySelectorAll('text')).map((t) => t.textContent);
    expect(labels).toContain('pkt/s');
    expect(labels).toContain('100'); // all: 100 pkt/s at the 1 s interval
    expect(labels.some((l) => /^\d\d:\d\d:\d\d$/.test(l ?? ''))).toBe(true);
    expect(screen.getByTestId('io-horizon')).toHaveTextContent('History since 06:40:00');
  });

  it('switches a series to bits/s with a second axis', () => {
    const { container } = view();
    fireEvent.change(screen.getByLabelText('series 1 measure'), { target: { value: 'bits' } });
    const labels = Array.from(container.querySelectorAll('text')).map((t) => t.textContent);
    expect(labels).toContain('bit/s');
    expect(labels).toContain('80.0k'); // 10 kB/s * 8
  });

  it('disables intervals that would exceed 2000 points, and the keyboard pans, zooms and returns to live', () => {
    view();
    const graph = screen.getByTestId('io-graph');
    const option100 = screen.getByRole('option', { name: '100 ms' }) as HTMLOptionElement;
    expect(option100.disabled).toBe(false); // 60 s window = 600 points
    for (let i = 0; i < 12; i++) fireEvent.keyDown(graph, { key: '-' });
    expect((screen.getByRole('option', { name: /100 ms/ }) as HTMLOptionElement).disabled).toBe(true);
    expect(screen.getByTestId('io-follow')).toHaveTextContent('live');
    fireEvent.keyDown(graph, { key: 'ArrowLeft' });
    expect(screen.getByTestId('io-follow')).toHaveTextContent('paused');
    fireEvent.keyDown(graph, { key: 'End' });
    expect(screen.getByTestId('io-follow')).toHaveTextContent('live');
  });

  it('zooming while live keeps following the newest data', () => {
    view();
    const graph = screen.getByTestId('io-graph');
    const before = screen.getByTestId('io-path-all').getAttribute('d')!.split('L').length;
    fireEvent.keyDown(graph, { key: '+' });
    expect(screen.getByTestId('io-follow')).toHaveTextContent('live');
    fireEvent.keyDown(graph, { key: '-' });
    fireEvent.keyDown(graph, { key: '-' });
    // Still live, and the wider window still ends at the newest data (all
    // 60 s of it are inside the window, none pushed past the live edge).
    expect(screen.getByTestId('io-follow')).toHaveTextContent('live');
    expect(screen.getByTestId('io-path-all').getAttribute('d')!.split('L').length).toBeGreaterThanOrEqual(before);
  });

  it('applies edits by compare-and-swap against the latest status, and shows a conflict', async () => {
    const { onSend, rerender, history } = view();
    fireEvent.change(screen.getByLabelText('series 2 filter'), { target: { value: 'dns or udp' } });
    await act(async () => {
      fireEvent.click(screen.getByTestId('io-apply'));
    });
    expect(onSend).toHaveBeenCalledTimes(1);
    const sent = (onSend as ReturnType<typeof vi.fn>).mock.calls[0][0] as SetIoSeriesMessage;
    expect(sent).toMatchObject({ type: 'set_io_series', baseEpoch: 'aaaabbbb', baseRevision: 3 });
    expect(sent.requestId).toMatch(/^[0-9a-f]{16}$/);
    expect(sent.series).toEqual([{ id: 'all', filter: '' }, { id: 'dns', filter: 'dns or udp' }]);
    expect(screen.getByTestId('io-apply')).toHaveTextContent('applying');
    // Another tab won; the agent refuses ours and returns its current set.
    const refused: IoSeriesStatus = { ...status, revision: 4, requestId: sent.requestId, rejected: 'conflict', series: [{ id: 'other', filter: 'tcp', ok: true }] };
    rerender(<IoGraphView history={history} version={history.version} status={refused} connected theme={THEMES.matrix} onSend={onSend} now={() => T0} timeZone="UTC" />);
    expect(screen.getByTestId('io-message')).toHaveTextContent('Series changed in another tab');
    expect((screen.getByLabelText('series 1 id') as HTMLInputElement).value).toBe('other');
    expect(screen.queryByLabelText('series 2 id')).toBeNull();
  });

  it('shows a series compile error with its position, and the replay-waiting banner', () => {
    view({
      status: {
        ...status,
        replayWaiting: true,
        series: [{ id: 'big', filter: 'frame.len > 1000 and ==', ok: false, error: { message: 'Unexpected token', token: '==', position: 21 } }],
      },
    });
    expect(screen.getByTestId('io-error-big')).toHaveTextContent('Unexpected token at position 21: == (not counted)');
    expect(screen.getByTestId('io-replay-waiting')).toBeInTheDocument();
  });

  it('reports a relay refusal of the request itself', async () => {
    const onSend = vi.fn(async () => false);
    view({ onSend });
    await act(async () => {
      fireEvent.click(screen.getByTestId('io-apply'));
    });
    expect(screen.getByTestId('io-message')).toHaveTextContent('The relay refused the request');
    expect(screen.getByTestId('io-apply')).toHaveTextContent('apply');
  });

  it('formats SI values', () => {
    expect([formatSi(0), formatSi(12.5), formatSi(999), formatSi(1500), formatSi(2_400_000), formatSi(3e9)]).toEqual(['0', '12.5', '999', '1.5k', '2.4M', '3.0G']);
  });
});
