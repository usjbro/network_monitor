// KAN-130 Task 4: the flow ladder in a real browser, fed through the real
// relay route by the fake agent. A wrapped ring (4 206 segments, the agent
// keeps the newest 4 096) arrives with its pinned 16-sample head and its
// ClientHello/ServerHello labels. The ladder draws the handshake, one gap
// row and collapsed bulk; a linked arrow opens its frame in Packets; the
// panel never scrolls sideways at 320 or 1 280 px; and a live poll with the
// full ring held commits within a frame (production build).
import { test, expect, type Page } from '@playwright/test';
import { FakeAgentDouble } from './fake-agent';
import { TCP_CONNECTION, TCP_ID as ID, columns, instrumentSamplesFetch, median, type SampleRow as Row } from './tcp-samples-fixture';

let agent: FakeAgentDouble;

test.beforeAll(async () => {
  agent = new FakeAgentDouble();
  await agent.start();
});

test.afterAll(async () => {
  await agent.stop();
});

const GEN = '00000000feedbeef:2';
const RING = 4096;
const HEAD = 16;
const PER_REPLY = 3072;
const T0_US = (Math.floor(Date.now() / 1000) - 60) * 1_000_000;
// A 64-byte label: the widest the agent sends.
const HELLO = `ClientHello (SNI: ${'a'.repeat(45)})`;

// 0 SYN out, 1 SYN-ACK in, 2 ACK out, 3 ClientHello out, 4 ServerHello in,
// then outbound 1 000-byte data (even) and its inbound ACK (odd).
function sample(i: number): Row {
  const t = T0_US + i * 1000;
  switch (i) {
    case 0: return { tUs: t, seq: 0, ack: 0, win: 65535, len: 0, flags: 2, mark: 1, rttUs: 0 };
    case 1: return { tUs: t, seq: 0, ack: 1, win: 65535, len: 0, flags: 18, mark: 0, rttUs: 0 };
    case 2: return { tUs: t, seq: 1, ack: 1, win: 512, len: 0, flags: 16, mark: 1, rttUs: 0 };
    case 3: return { tUs: t, seq: 1, ack: 1, win: 512, len: 517, flags: 24, mark: 1, rttUs: 0 };
    case 4: return { tUs: t, seq: 1, ack: 518, win: 512, len: 1400, flags: 24, mark: 0, rttUs: 0 };
  }
  const k = i - 5;
  return k % 2 === 0
    ? { tUs: t, seq: 518 + (k / 2) * 1000, ack: 1401, win: 512, len: 1000, flags: 24, mark: 1, rttUs: 0 }
    : { tUs: t, seq: 1401, ack: 518 + ((k + 1) / 2) * 1000, win: 512, len: 0, flags: 16, mark: 0, rttUs: 0 };
}

function reply(requestId: string, fromIndex: number, total: number) {
  const first = Math.max(0, total - RING);
  const start = Math.max(fromIndex, first);
  const count = Math.max(0, Math.min(PER_REPLY, total - start));
  const rows = Array.from({ length: count }, (_, i) => sample(start + i));
  const headEnd = Math.min(HEAD, first);
  const head = fromIndex < headEnd ? Array.from({ length: headEnd - fromIndex }, (_, i) => sample(fromIndex + i)) : [];
  const labels = [[3, 'tls_client_hello', HELLO], [4, 'tls_server_hello', 'ServerHello']]
    .filter(([index]) => (index as number) >= fromIndex && ((index as number) < headEnd || (index as number) >= start));
  return {
    type: 'tcp_samples', requestId, connectionId: ID, found: true, stale: false, generation: GEN,
    handshakeSeen: true, windowScale: null, seqBase: { outbound: 0, inbound: 0 }, relativeTo: 'isn',
    firstIndex: first, nextIndex: start + count, more: start + count < total, droppedOlder: Math.max(0, first - fromIndex),
    samples: columns(rows),
    ...(head.length > 0 ? { head: { firstIndex: fromIndex, ...columns(head) } } : {}),
    labels,
  };
}

// The packet event for sample 1 (the SYN-ACK), as the agent would send it.
function synAckPacket() {
  const s = sample(1);
  const f = (path: string, value: number | boolean) => ({ path, label: path, type: typeof value === 'boolean' ? 'bool' : 'uint', value, region: 'header', offset: 0, len: 1 });
  return {
    type: 'packet',
    packet: {
      id: 'pkt-synack', timestamp: String(Math.floor(s.tUs / 1000)), relativeTimeMs: 0, layer: 4, protocol: 'TCP',
      src: '93.184.216.34:443', dst: '192.168.1.10:51000', length: 60, summary: 'SYN-ACK frame', hexDump: '', headerHexDump: '',
      fields: [f('tcp.seq', 0), f('tcp.ack_number', 1), f('tcp.flags.syn', true), f('tcp.flags.ack', true), f('tcp.flags.fin', false), f('tcp.flags.rst', false)],
    },
  };
}

let total = 4206;

async function openLadder(page: Page) {
  agent.responder = (msg) => {
    if (msg.type !== 'get_tcp_samples' || msg.connectionId !== ID) return null;
    return reply(String(msg.requestId), typeof msg.fromIndex === 'number' ? msg.fromIndex : 0, total);
  };
  await page.goto('/');
  await expect(page.getByText(/capture agent not connected/i)).toBeHidden({ timeout: 15_000 });
  agent.send({ type: 'connection_update', connection: TCP_CONNECTION });
  agent.send(synAckPacket());
  await page.getByTestId('tab-connections').click();
  await page.getByRole('button', { name: /^ladder$/i }).click();
  await expect(page.getByTestId('ladder-row-gap')).toBeVisible({ timeout: 10_000 });
}

test('the ladder draws the pinned handshake, labels, one gap and collapsed bulk, and opens a frame', async ({ page }) => {
  total = 4206;
  await openLadder(page);
  const texts = page.getByTestId('ladder-text');
  await expect(texts.nth(0)).toHaveText('SYN');
  await expect(texts.nth(1)).toHaveText('SYN,ACK');
  await expect(texts.nth(3)).toHaveText(`PSH,ACK len=517 · ${HELLO}`);
  await expect(texts.nth(4)).toHaveText('PSH,ACK len=1400 · ServerHello');
  await expect(page.getByTestId('ladder-row-gap')).toHaveCount(1);
  await expect(page.getByTestId('ladder-row-gap')).toHaveText(`${4206 - RING - HEAD} segments not retained`);
  await expect(page.getByTestId('ladder-row-run').first()).toBeVisible();

  const synAck = page.getByTestId('ladder-row-arrow').nth(1);
  await expect(synAck.getByTestId('ladder-linked')).toBeVisible();
  await synAck.click();
  await expect(page.locator('[data-packet-row][data-selected="true"]')).toContainText('SYN-ACK frame');
});

for (const width of [320, 1280]) {
  test(`the ladder panel does not scroll sideways at ${width} px`, async ({ page }) => {
    total = 4206;
    await page.setViewportSize({ width, height: 900 });
    await openLadder(page);
    const panel = page.getByTestId('flow-ladder');
    await expect(page.getByTestId('ladder-text').nth(3)).toContainText('ClientHello');
    const overflow = await panel.evaluate((el) => {
      const out: string[] = [];
      for (const node of [el, ...Array.from(el.querySelectorAll<HTMLElement>('[data-ladder-row]'))]) {
        if (node.scrollWidth > node.clientWidth + 1) out.push(`${node.getAttribute('data-testid')}: ${node.scrollWidth} > ${node.clientWidth}`);
      }
      return out;
    });
    expect(overflow).toEqual([]);
    const panelBox = await page.getByTestId('tcp-graphs').evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }));
    expect(panelBox.scroll).toBeLessThanOrEqual(panelBox.client + 1);
  });
}

test('a live poll with the full ring held commits the ladder within a frame', async ({ page }) => {
  total = 4206;
  await instrumentSamplesFetch(page);
  await openLadder(page);

  const production = process.env.E2E_PRODUCTION === '1';
  const budget = production ? 16.7 : 100;
  const live: number[] = [];
  for (let k = 0; k < 9; k++) {
    await page.evaluate(() => {
      const w = window as unknown as { __ladderCommit: Promise<number> };
      const list = document.querySelector('[data-testid="flow-ladder"] [role="list"]') as HTMLElement;
      w.__ladderCommit = new Promise((resolve) => {
        const obs = new MutationObserver(() => { obs.disconnect(); resolve(performance.now()); });
        obs.observe(list, { subtree: true, childList: true, characterData: true, attributes: true });
      });
    });
    total += 32;
    live.push(await page.evaluate(async () => {
      const w = window as unknown as { __ladderCommit: Promise<number>; __tcpParsed: number[] };
      const committed = await w.__ladderCommit;
      return committed - w.__tcpParsed[w.__tcpParsed.length - 1];
    }));
  }
  const mid = median(live);
  console.log(`KAN-130 flow ladder (${production ? 'production' : 'next dev'}), full ring + head, live poll median of 9: ${mid.toFixed(1)} ms | ${live.map((t) => t.toFixed(1)).join(', ')}`);
  expect(live.every((t) => Number.isFinite(t) && t >= 0)).toBe(true);
  expect(mid).toBeLessThan(budget);
});
