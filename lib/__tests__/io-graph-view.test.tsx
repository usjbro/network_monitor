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

// PR #306 review fixes.
describe('IoGraphView: compare-and-swap (review C1)', () => {
  function rerenderWith(utils: ReturnType<typeof view>, next: IoSeriesStatus, connected = true) {
    utils.rerender(<IoGraphView history={utils.history} version={utils.history.version} status={next} connected={connected} theme={THEMES.matrix} onSend={utils.onSend} now={() => T0} timeZone="UTC" />);
  }
  const sentMessages = (onSend: unknown) => (onSend as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0] as SetIoSeriesMessage);

  it('a draft sends the revision it was built from, so a change made meanwhile in another tab is refused, not overwritten', async () => {
    const utils = view();
    fireEvent.change(screen.getByLabelText('series 2 filter'), { target: { value: 'dns or udp' } });
    // Tab B applies [all, web] meanwhile: revision 4.
    const fromB: IoSeriesStatus = { ...status, revision: 4, requestId: 'bbbbbbbbbbbbbbbb', series: [{ id: 'all', filter: '', ok: true }, { id: 'web', filter: 'tcp.port == 443', ok: true }] };
    rerenderWith(utils, fromB);
    // The draft is kept (no lost work), and says it is stale.
    expect((screen.getByLabelText('series 2 filter') as HTMLInputElement).value).toBe('dns or udp');
    expect(screen.getByTestId('io-message')).toHaveTextContent('since you started editing');
    await act(async () => {
      fireEvent.click(screen.getByTestId('io-apply'));
    });
    expect(sentMessages(utils.onSend)[0]).toMatchObject({ baseEpoch: 'aaaabbbb', baseRevision: 3 });
    // The agent refuses it and returns B's set, which the editor then shows.
    rerenderWith(utils, { ...fromB, requestId: sentMessages(utils.onSend)[0].requestId, rejected: 'conflict' });
    expect(screen.getByTestId('io-message')).toHaveTextContent('Series changed in another tab');
    expect((screen.getByLabelText('series 2 id') as HTMLInputElement).value).toBe('web');
  });

  it("an answered request stays answered when another tab's change arrives afterwards", async () => {
    const utils = view();
    fireEvent.change(screen.getByLabelText('series 2 filter'), { target: { value: 'udp' } });
    await act(async () => {
      fireEvent.click(screen.getByTestId('io-apply'));
    });
    const ours = sentMessages(utils.onSend)[0];
    const accepted: IoSeriesStatus = { ...status, revision: 4, requestId: ours.requestId, series: [{ id: 'all', filter: '', ok: true }, { id: 'dns', filter: 'udp', ok: true }] };
    rerenderWith(utils, accepted);
    expect(screen.getByTestId('io-apply')).toHaveTextContent(/^apply$/);
    // Tab B then changes the set; this tab is not stuck "applying", and shows B's set.
    rerenderWith(utils, { ...status, revision: 5, requestId: 'bbbbbbbbbbbbbbbb', series: [{ id: 'web', filter: 'tcp', ok: true }] });
    expect(screen.getByTestId('io-apply')).toHaveTextContent(/^apply$/);
    expect((screen.getByLabelText('series 1 id') as HTMLInputElement).value).toBe('web');
    // A fresh edit starts from revision 5, the set it shows.
    fireEvent.change(screen.getByLabelText('series 1 filter'), { target: { value: 'tcp or udp' } });
    await act(async () => {
      fireEvent.click(screen.getByTestId('io-apply'));
    });
    expect(sentMessages(utils.onSend)[1]).toMatchObject({ baseRevision: 5, series: [{ id: 'web', filter: 'tcp or udp' }] });
  });

  it('a reconnect bootstrap before the answer ends the pending request instead of leaving it stuck', async () => {
    const utils = view();
    await act(async () => {
      fireEvent.click(screen.getByTestId('io-apply'));
    });
    expect(screen.getByTestId('io-apply')).toHaveTextContent('applying');
    rerenderWith(utils, { ...status }); // same revision, no requestId: the relay re-sent the current state
    expect(screen.getByTestId('io-apply')).toHaveTextContent(/^apply$/);
    expect(screen.getByTestId('io-message')).toHaveTextContent('before the agent answered');
  });

  it('a dropped connection before the answer also ends it', async () => {
    const utils = view();
    await act(async () => {
      fireEvent.click(screen.getByTestId('io-apply'));
    });
    rerenderWith(utils, status, false);
    expect(screen.getByTestId('io-message')).toHaveTextContent('connection dropped');
  });

  it("another tab's refused request does not end ours", async () => {
    const utils = view();
    await act(async () => {
      fireEvent.click(screen.getByTestId('io-apply'));
    });
    rerenderWith(utils, { ...status, requestId: 'bbbbbbbbbbbbbbbb', rejected: 'invalid_id' });
    expect(screen.getByTestId('io-apply')).toHaveTextContent('applying');
  });

  it('the measure follows a row when its id is edited (minor 11)', () => {
    view();
    fireEvent.change(screen.getByLabelText('series 2 measure'), { target: { value: 'bits' } });
    fireEvent.change(screen.getByLabelText('series 2 id'), { target: { value: 'dns2' } });
    expect((screen.getByLabelText('series 2 measure') as HTMLSelectElement).value).toBe('bits');
  });
});

describe('IoGraphView: pointer, wheel and readout', () => {
  function stubRect(el: Element) {
    el.getBoundingClientRect = () => ({ left: 0, top: 0, width: 1000, height: 260, right: 1000, bottom: 260, x: 0, y: 0, toJSON: () => ({}) });
  }
  const windowText = () => screen.getByText(/^window /).textContent;

  it('wheel zooms, and a burst of wheel events compounds instead of reading a stale span', () => {
    view();
    const svg = screen.getByTestId('io-svg');
    stubRect(svg);
    act(() => {
      svg.dispatchEvent(new WheelEvent('wheel', { deltaY: 100, clientX: 500, bubbles: true, cancelable: true }));
      svg.dispatchEvent(new WheelEvent('wheel', { deltaY: 100, clientX: 500, bubbles: true, cancelable: true }));
    });
    expect(windowText()).toBe('window 1.6 min'); // 60 s * 1.25 * 1.25
  });

  it('drag pans and pauses; hover shows the readout for the interval under the cursor', () => {
    view();
    const svg = screen.getByTestId('io-svg');
    stubRect(svg);
    // Hover over the last interval: x = 64 + 872 * 0.99.
    fireEvent.pointerMove(svg, { clientX: 927, pointerId: 1 });
    expect(screen.getByTestId('io-readout')).toHaveTextContent('all100 pkt/s');
    fireEvent.pointerDown(svg, { clientX: 500, pointerId: 1 });
    fireEvent.pointerMove(svg, { clientX: 600, pointerId: 1 });
    fireEvent.pointerUp(svg, { pointerId: 1 });
    expect(screen.getByTestId('io-follow')).toHaveTextContent('paused');
    expect(screen.getByTestId('io-follow-announce')).toHaveTextContent('Paused');
  });

  it('two-finger pinch zooms', () => {
    view();
    const svg = screen.getByTestId('io-svg');
    stubRect(svg);
    fireEvent.pointerDown(svg, { clientX: 400, pointerId: 1 });
    fireEvent.pointerDown(svg, { clientX: 600, pointerId: 2 });
    fireEvent.pointerMove(svg, { clientX: 300, pointerId: 1 });
    fireEvent.pointerMove(svg, { clientX: 700, pointerId: 2 });
    expect(windowText()).toBe('window 30 s'); // fingers 200 -> 400 px apart: half the 60 s span
  });

  it('readout names the not-observed reason and share', () => {
    const h = createHistory();
    ingestStatus(h, status);
    ingestBuckets(h, {
      revision: 3, epoch: 'aaaabbbb', bucketMs: 100, coveredFromMs: T0 - 1000, coveredToMs: T0, loss: { kernelDropped: 0, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 },
      notObserved: [{ fromMs: T0 - 300, toMs: T0 - 100, reason: 'backlog' }],
      series: [{ id: 'all', late: 0, lateBuckets: [], buckets: [] }, { id: 'dns', late: 0, lateBuckets: [], buckets: [] }],
    });
    view({ history: h });
    const svg = screen.getByTestId('io-svg');
    stubRect(svg);
    fireEvent.pointerMove(svg, { clientX: 935, pointerId: 1 });
    expect(screen.getByTestId('io-readout')).toHaveTextContent('not observed (backlog), 200 ms of 1 s');
  });
});

describe('IoGraphView: what the chart states (minors 2, 3, 4)', () => {
  it('a lone value between gaps is drawn as a dot', () => {
    const h = createHistory();
    ingestStatus(h, { ...status, series: [{ id: 'all', filter: '', ok: true }] });
    ingestBuckets(h, {
      revision: 3, epoch: 'aaaabbbb', bucketMs: 100, coveredFromMs: T0 - 1000, coveredToMs: T0, notObserved: [],
      loss: { kernelDropped: 0, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 },
      series: [{ id: 'all', late: 0, lateBuckets: [], buckets: [[T0 - 1000, 5, 50]] }],
    });
    view({ history: h, status: { ...status, series: [{ id: 'all', filter: '', ok: true }] } });
    expect(screen.getByTestId('io-path-all').getAttribute('d')).toMatch(/^M[\d.]+,[\d.]+l0,0$/);
  });

  it('shows zero-length markers, the series count and the agent session start', () => {
    const h = filledHistory();
    ingestBuckets(h, {
      revision: 3, epoch: 'aaaabbbb', bucketMs: 100, coveredFromMs: T0 + 60_000, coveredToMs: T0 + 60_000,
      notObserved: [{ fromMs: T0 + 59_000, toMs: T0 + 59_000, reason: 'replay_error' }],
      loss: { kernelDropped: 0, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 },
      series: [{ id: 'all', late: 0, lateBuckets: [], buckets: [] }, { id: 'dns', late: 0, lateBuckets: [], buckets: [] }],
    });
    view({ history: h, status: { ...status, series: [status.series[0], { id: 'dns', filter: 'dns ==', ok: false }] } });
    expect(screen.getByTestId('io-marker')).toBeInTheDocument();
    expect(screen.getByTestId('io-series-count')).toHaveTextContent('Showing 1 of 2 series · agent session since 06:40:00');
  });

  it('states late frames whose interval is no longer held', () => {
    const h = filledHistory();
    ingestBuckets(h, {
      revision: 3, epoch: 'aaaabbbb', bucketMs: 100, coveredFromMs: T0 + 60_000, coveredToMs: T0 + 60_000, notObserved: [],
      loss: { kernelDropped: 0, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 },
      series: [{ id: 'all', late: 3, lateBuckets: [], buckets: [] }, { id: 'dns', late: 0, lateBuckets: [], buckets: [] }],
    });
    view({ history: h });
    expect(screen.getByTestId('io-unplaced-late')).toHaveTextContent('all 3');
  });
});

describe('IoGraphView: click-through (JAM-18 Task 4)', () => {
  function stubRect(el: Element) {
    el.getBoundingClientRect = () => ({ left: 0, top: 0, width: 1000, height: 260, right: 1000, bottom: 260, x: 0, y: 0, toJSON: () => ({}) });
  }

  it('a click (not a drag) pins the interval, and each series row opens its packets', () => {
    const onDrill = vi.fn();
    view({ onDrill });
    const svg = screen.getByTestId('io-svg');
    stubRect(svg);
    // The window follows the newest data (T0 + 60 s); x = 930 is its last 1 s interval.
    fireEvent.pointerDown(svg, { clientX: 930, pointerId: 1 });
    fireEvent.pointerUp(svg, { clientX: 931, pointerId: 1 });
    fireEvent.pointerLeave(svg, { pointerId: 1 });
    // Still shown after the pointer leaves: it is pinned.
    expect(screen.getByTestId('io-readout')).toHaveTextContent('pinned');
    expect(screen.getByTestId('io-follow')).toHaveTextContent('live'); // a click does not pan
    fireEvent.click(screen.getByTestId('io-drill-dns'));
    expect(onDrill).toHaveBeenCalledWith('dns', 1000, T0 + 59_000);
  });

  it('a drag does not pin, and Escape unpins', () => {
    view({ onDrill: vi.fn() });
    const svg = screen.getByTestId('io-svg');
    stubRect(svg);
    fireEvent.pointerDown(svg, { clientX: 500, pointerId: 1 });
    fireEvent.pointerMove(svg, { clientX: 600, pointerId: 1 });
    fireEvent.pointerUp(svg, { clientX: 600, pointerId: 1 });
    fireEvent.pointerLeave(svg, { pointerId: 1 });
    expect(screen.queryByTestId('io-readout')).toBeNull();
    fireEvent.keyDown(screen.getByTestId('io-graph'), { key: 'Enter' });
    expect(screen.getByTestId('io-readout')).toHaveTextContent('pinned');
    fireEvent.keyDown(screen.getByTestId('io-graph'), { key: 'Escape' });
    expect(screen.queryByTestId('io-readout')).toBeNull();
  });

  it('without onDrill there are no packet buttons', () => {
    view();
    fireEvent.keyDown(screen.getByTestId('io-graph'), { key: 'Enter' });
    expect(screen.queryByTestId('io-drill-dns')).toBeNull();
  });
});
