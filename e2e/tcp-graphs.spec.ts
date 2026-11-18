// KAN-129 Task 4: the TCP graphs in a real browser, fed through the real
// relay route by the fake agent. A full 4 096-sample ring arrives in two
// pages (3 072, then 1 024), and an update with the full ring held stays
// within a frame: a keyboard pan (React render and commit), and a live poll
// (reply parsed -> accumulate, series, commit). Measured as
// e2e/io-graph.spec.ts measures the IO graph.
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

const ID = 'Tcp-192.168.1.10:51000-93.184.216.34:443';
const GEN = '00000000feedbeef:1';
const RING = 4096;
const PER_REPLY = 3072;
const T0_US = (Math.floor(Date.now() / 1000) - 60) * 1_000_000;

// Even indices: outbound 1 000-byte data (every 97th a retransmission).
// Odd: the inbound ACK for it, with an RTT sample and an irregular window
// (so a live shift of the fitted window changes the receive-window path).
function sample(i: number) {
  const out = i % 2 === 0;
  const k = Math.floor(i / 2);
  return out
    ? { tUs: T0_US + i * 1000, seq: k * 1000, ack: 1, win: 512, len: 1000, flags: 24, mark: 1 | (k % 97 === 50 ? 2 : 0), rttUs: 0 }
    : { tUs: T0_US + i * 1000, seq: 1, ack: (k + 1) * 1000, win: 20_000 + ((k * 7919) % 40_000), len: 0, flags: 16, mark: 4 | 16, rttUs: 20_000 + (k % 50) * 100 };
}

function samplesReply(requestId: string, fromIndex: number, total: number) {
  const first = Math.max(0, total - RING);
  const start = Math.max(fromIndex, first);
  const count = Math.max(0, Math.min(PER_REPLY, total - start));
  const rows = Array.from({ length: count }, (_, i) => sample(start + i));
  return {
    type: 'tcp_samples', requestId, connectionId: ID, found: true, stale: false, generation: GEN,
    handshakeSeen: true, windowScale: { local: 7, remote: 7 }, seqBase: { outbound: 0, inbound: 0 }, relativeTo: 'isn',
    firstIndex: first, nextIndex: start + count, more: start + count < total, droppedOlder: start - fromIndex,
    samples: {
      tUs: rows.map((r, i) => (i === 0 ? r.tUs : r.tUs - rows[i - 1].tUs)),
      seq: rows.map((r) => r.seq), ack: rows.map((r) => r.ack), win: rows.map((r) => r.win), len: rows.map((r) => r.len),
      flags: rows.map((r) => r.flags), mark: rows.map((r) => r.mark), rttUs: rows.map((r) => r.rttUs),
    },
  };
}

test('TCP graphs load a full ring in two pages and stay within a frame per update', async ({ page }) => {
  let total = RING;
  const fromIndices: number[] = [];
  agent.responder = (msg) => {
    if (msg.type !== 'get_tcp_samples' || msg.connectionId !== ID) return null;
    const fromIndex = typeof msg.fromIndex === 'number' ? msg.fromIndex : 0;
    fromIndices.push(fromIndex);
    return samplesReply(String(msg.requestId), fromIndex, total);
  };

  // Timestamp each samples reply as the page finishes parsing it.
  await page.addInitScript(() => {
    const w = window as unknown as { __tcpParsed: number[] };
    w.__tcpParsed = [];
    const original = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      const res = await original(input, init);
      if (String(input) !== '/api/tcp-samples') return res;
      const json = res.json.bind(res);
      res.json = async () => {
        const body = await json();
        w.__tcpParsed.push(performance.now());
        return body;
      };
      return res;
    };
  });

  await page.goto('/');
  await expect(page.getByText(/capture agent not connected/i)).toBeHidden({ timeout: 15_000 });
  agent.send({
    type: 'connection_update',
    connection: {
      id: ID, protocol: 'HTTPS/TLS', appLayerProtocol: 'HTTPS/TLS', transportProtocol: 'TCP', osiStack: 'x',
      localAddr: '192.168.1.10', localPort: 51000, remoteAddr: '93.184.216.34', remotePort: 443, processName: 'curl', pid: 1,
      rxSpeed: 0, txSpeed: 0, rxBytesTotal: 0, txBytesTotal: 0, latencyMs: 20, packetLoss: 0, status: 'ESTABLISHED',
      encryption: 'TLS', sparkline: [],
    },
  });
  await page.getByTestId('tab-connections').click();
  await page.getByRole('button', { name: /tcp graphs/i }).click();

  // The whole ring: 2 048 outbound data segments, 2 048 ACKs.
  const dots = async (testId: string) => ((await page.getByTestId(testId).getAttribute('d')) ?? '').split('M').length - 1;
  await expect.poll(() => dots('tcp-data-path').then(async (n) => n + (await dots('tcp-retransmit-path'))), { timeout: 10_000 }).toBe(RING / 2);
  expect(await dots('tcp-retransmit-path')).toBeGreaterThan(0);
  expect(await dots('tcp-rtt-path')).toBe(RING / 2);
  // Two pages: 3 072 from 0, then the 1 024 that `more` asked for.
  expect(fromIndices.slice(0, 2)).toEqual([0, PER_REPLY]);
  await expect(page.getByTestId('tcp-horizon')).toHaveText(/0 older dropped/);
  await expect(page.getByTestId('tcp-rtt-ref')).toBeAttached();

  const production = process.env.E2E_PRODUCTION === '1';
  const budget = production ? 16.7 : 100;
  const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
  const fmt = (xs: number[]) => xs.map((t) => t.toFixed(1)).join(', ');

  // 1. Interaction: keyboard pan until React commits the new data path.
  await page.getByTestId('tcp-graphs').focus();
  await page.keyboard.press('-');
  const keys = await page.evaluate(async () => {
    const el = document.querySelector('[data-testid="tcp-graphs"]') as HTMLElement;
    const path = document.querySelector('[data-testid="tcp-data-path"]') as SVGPathElement;
    const update: number[] = [];
    for (let i = 0; i < 9; i++) {
      const committed = new Promise<number>((resolve) => {
        const obs = new MutationObserver(() => { obs.disconnect(); resolve(performance.now()); });
        obs.observe(path, { attributes: true, attributeFilter: ['d'] });
      });
      const t0 = performance.now();
      el.dispatchEvent(new KeyboardEvent('keydown', { key: i % 2 ? 'ArrowRight' : 'ArrowLeft', bubbles: true }));
      update.push((await committed) - t0);
      await new Promise((r) => requestAnimationFrame(() => r(null)));
    }
    return update;
  });

  // 2. Live: back to fit-and-follow; each poll brings 32 new samples, so the
  // ring overwrites its oldest and the plot moves. Reply parsed -> commit.
  await page.keyboard.press('0');
  const live: number[] = [];
  for (let k = 0; k < 9; k++) {
    await page.evaluate(() => {
      const w = window as unknown as { __tcpCommit: Promise<number> };
      const path = document.querySelector('[data-testid="tcp-window-path"]') as SVGPathElement;
      w.__tcpCommit = new Promise((resolve) => {
        const obs = new MutationObserver(() => { obs.disconnect(); resolve(performance.now()); });
        obs.observe(path, { attributes: true, attributeFilter: ['d'] });
      });
    });
    total += 32;
    live.push(await page.evaluate(async () => {
      const w = window as unknown as { __tcpCommit: Promise<number>; __tcpParsed: number[] };
      const committed = await w.__tcpCommit;
      return committed - w.__tcpParsed[w.__tcpParsed.length - 1];
    }));
  }
  await expect(page.getByTestId('tcp-horizon')).toHaveText(/older dropped/);
  expect(await dots('tcp-rtt-path')).toBe(RING / 2);

  console.log(`KAN-129 TCP graphs (${production ? 'production' : 'next dev'}), full ring of ${RING} samples, median of 9:`
    + ` key update ${median(keys).toFixed(1)} ms (worst ${Math.max(...keys).toFixed(1)}),`
    + ` live poll ${median(live).toFixed(1)} ms (worst ${Math.max(...live).toFixed(1)})`
    + ` | updates: ${fmt(keys)} | live: ${fmt(live)}`);
  expect(live.every((t) => Number.isFinite(t) && t >= 0)).toBe(true);
  expect(median(keys)).toBeLessThan(budget);
  expect(median(live)).toBeLessThan(budget);
});
