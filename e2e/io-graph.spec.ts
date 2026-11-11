// JAM-18 Task 3: the IO graph in a real browser, fed through the real relay
// by the fake agent. Checks that 8 series of ~1 800 visible 100 ms points
// render, and records how long an interaction (keyboard pan -> React render
// and commit) and a live update (ingest + the chart's recompute) take.
import { test, expect } from '@playwright/test';
import { FakeAgentDouble } from './fake-agent';

let agent: FakeAgentDouble;

test.beforeAll(async () => {
  agent = new FakeAgentDouble();
  await agent.start();
});

test.afterAll(async () => {
  await agent.stop();
});

const EPOCH = 'aaaabbbbccccdddd';
const SERIES = Array.from({ length: 8 }, (_, i) => `s${i + 1}`);
const T0 = Math.floor(Date.now() / 1000) * 1000 - 200_000;

test('IO graph renders 8 series of ~1800 points and stays within a frame per update', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText(/capture agent not connected/i)).toBeHidden({ timeout: 15_000 });

  agent.send({
    type: 'io_series_status', revision: 1, epoch: EPOCH, replayWaiting: false,
    series: SERIES.map((id) => ({ id, filter: '', ok: true })),
  });
  // 200 s of 100 ms buckets for 8 series, 20 s per line (well under 64 KiB).
  for (let chunk = 0; chunk < 10; chunk++) {
    const from = T0 + chunk * 20_000;
    agent.send({
      type: 'io_buckets', revision: 1, epoch: EPOCH, bucketMs: 100,
      coveredFromMs: from, coveredToMs: from + 20_000, notObserved: [],
      loss: { kernelDropped: 0, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 },
      series: SERIES.map((id, i) => ({
        id, late: 0, lateBuckets: [],
        buckets: Array.from({ length: 200 }, (_, k) => [from + k * 100, 1 + ((k + i * 7) % 13), 100 * (i + 1)]),
      })),
    });
  }

  await page.getByTestId('tab-io').click();
  const graph = page.getByTestId('io-graph');
  await expect(page.getByTestId('io-path-s8')).toHaveAttribute('d', /L/);

  // Zoom out to ~183 s and pick the 100 ms interval: ~1 830 points per series.
  await graph.focus();
  for (let i = 0; i < 5; i++) await page.keyboard.press('-');
  await page.getByTestId('io-interval').selectOption('100');
  await expect(page.getByTestId('io-interval')).toHaveValue('100');
  const segments = await page.getByTestId('io-path-s1').getAttribute('d');
  expect((segments ?? '').split('L').length).toBeGreaterThan(1500);

  // The one-frame budget (16.7 ms) is only meaningful against a production
  // build: `next dev` runs React in StrictMode, which renders (and runs the
  // chart's useMemo) twice, plus dev-only checks. CI sets E2E_PRODUCTION=1,
  // which builds and serves a production bundle (playwright.config.ts) and
  // enforces the frame budget. A local run without it uses `next dev`, where
  // the bound only catches a large regression. Both modes assert the median
  // of 9 runs, and log every run.
  const production = process.env.E2E_PRODUCTION === '1';
  const budget = production ? 16.7 : 100;
  const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
  const fmt = (xs: number[]) => xs.map((t) => t.toFixed(1)).join(', ');

  // 1. Interaction: from the keyboard event until React has committed the
  // new path to the DOM (a MutationObserver on a series path). Excludes paint.
  const keys = await page.evaluate(async () => {
    const el = document.querySelector('[data-testid="io-graph"]') as HTMLElement;
    const path = document.querySelector('[data-testid="io-path-s1"]') as SVGPathElement;
    const update: number[] = [];
    const compute: number[] = [];
    for (let i = 0; i < 9; i++) {
      performance.clearMeasures('io-graph-compute');
      const committed = new Promise<number>((resolve) => {
        const obs = new MutationObserver(() => { obs.disconnect(); resolve(performance.now()); });
        obs.observe(path, { attributes: true, attributeFilter: ['d'] });
      });
      const t0 = performance.now();
      el.dispatchEvent(new KeyboardEvent('keydown', { key: i % 2 ? 'ArrowRight' : 'ArrowLeft', bubbles: true }));
      update.push((await committed) - t0);
      const m = performance.getEntriesByName('io-graph-compute');
      compute.push(m.length ? m[m.length - 1].duration : NaN);
      await new Promise((r) => requestAnimationFrame(() => r(null)));
    }
    return { update, compute };
  });

  // 2. Live data: one second of 100 ms buckets for all 8 series arrives
  // while following live. Cost = ingest (io-graph-ingest, in the stream
  // handler) + the chart's recompute for the render it schedules.
  await page.keyboard.press('End');
  await expect(page.getByTestId('io-follow')).toHaveText(/live/);
  const live: { ingest: number; compute: number }[] = [];
  for (let k = 0; k < 9; k++) {
    await page.evaluate(() => {
      performance.clearMeasures('io-graph-ingest');
      performance.clearMeasures('io-graph-compute');
      const path = document.querySelector('[data-testid="io-path-s1"]') as SVGPathElement;
      (window as unknown as { __ioCommit: Promise<void> }).__ioCommit = new Promise((resolve) => {
        const obs = new MutationObserver(() => { obs.disconnect(); resolve(); });
        obs.observe(path, { attributes: true, attributeFilter: ['d'] });
      });
    });
    const from = T0 + 200_000 + k * 1000;
    agent.send({
      type: 'io_buckets', revision: 1, epoch: EPOCH, bucketMs: 100,
      coveredFromMs: from, coveredToMs: from + 1000, notObserved: [],
      loss: { kernelDropped: 0, ifDropped: 0, unparseable: 0, evaluationSkipped: 0 },
      series: SERIES.map((id, i) => ({
        id, late: 0, lateBuckets: [],
        buckets: Array.from({ length: 10 }, (_, j) => [from + j * 100, 1 + ((j + i * 7) % 13), 100 * (i + 1)]),
      })),
    });
    live.push(await page.evaluate(async () => {
      await (window as unknown as { __ioCommit: Promise<void> }).__ioCommit;
      const last = (name: string) => {
        const m = performance.getEntriesByName(name);
        return m.length ? m[m.length - 1].duration : NaN;
      };
      return { ingest: last('io-graph-ingest'), compute: last('io-graph-compute') };
    }));
  }
  const liveTotal = live.map((l) => l.ingest + l.compute);

  console.log(`JAM-18 IO graph (${production ? 'production' : 'next dev'}), 8 series x ~1830 points, median of 9:`
    + ` key update ${median(keys.update).toFixed(1)} ms (worst ${Math.max(...keys.update).toFixed(1)}),`
    + ` compute ${median(keys.compute).toFixed(1)} ms,`
    + ` live ingest+compute ${median(liveTotal).toFixed(1)} ms (worst ${Math.max(...liveTotal).toFixed(1)}; ingest ${median(live.map((l) => l.ingest)).toFixed(2)} ms)`
    + ` | updates: ${fmt(keys.update)} | live: ${fmt(liveTotal)}`);
  expect(keys.compute.every((c) => Number.isFinite(c))).toBe(true);
  expect(liveTotal.every((c) => Number.isFinite(c))).toBe(true);
  expect(median(keys.update)).toBeLessThan(budget);
  expect(median(liveTotal)).toBeLessThan(budget);
});
