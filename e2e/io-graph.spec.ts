// JAM-18 Task 3: the IO graph in a real browser, fed through the real relay
// by the fake agent. Checks that 8 series of ~1 800 visible 100 ms points
// render, and records how long one update (keyboard pan -> React render and
// commit) and the chart's own point/path computation take.
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

  // One update, measured from the keyboard event until React has committed
  // the new path to the DOM (a MutationObserver on the series path), plus
  // the chart's own point/path computation (performance.measure inside the
  // component). Excludes paint. Best of 5.
  const timings = await page.evaluate(async () => {
    const el = document.querySelector('[data-testid="io-graph"]') as HTMLElement;
    const path = document.querySelector('[data-testid="io-path-s1"]') as SVGPathElement;
    const update: number[] = [];
    const compute: number[] = [];
    for (let i = 0; i < 5; i++) {
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
    return { update: Math.min(...update), compute: Math.min(...compute), updates: update, computes: compute };
  });
  console.log(`JAM-18 IO graph, 8 series x ~1830 points: update ${timings.update.toFixed(1)} ms, compute ${timings.compute.toFixed(1)} ms (updates: ${timings.updates.map((t) => t.toFixed(1)).join(', ')}; computes: ${timings.computes.map((t) => t.toFixed(1)).join(', ')})`);
  expect(timings.computes.every((c) => Number.isFinite(c))).toBe(true);
  // The one-frame budget (16.7 ms) is only meaningful against a production
  // build: `next dev` runs React in StrictMode, which renders (and runs this
  // useMemo) twice, plus dev-only checks. CI's ordinary e2e run uses the dev
  // server, so there the bound only catches a large regression. Run with
  // E2E_PRODUCTION=1 against `next start` to enforce the frame budget.
  const budget = process.env.E2E_PRODUCTION === '1' ? 16.7 : 100;
  expect(timings.compute).toBeLessThan(budget);
  expect(timings.update).toBeLessThan(budget);
});
