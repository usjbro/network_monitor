import { test, expect } from '@playwright/test';
import { FakeAgentDouble } from './fake-agent';

// The one real-browser smoke test for this app (issue #117 / JAM-55). Every
// other test in this repo (lib/__tests__) drives app/page.tsx through
// jsdom, which never runs real layout/CSS and mocks EventSource entirely —
// so none of them can catch a bug that only shows up once a real browser
// parses real SSE bytes over a real socket and lays the result out. This
// test exercises the whole real pipeline instead: a fake TCP "capture
// agent" (see fake-agent.ts, sharing #116's double) -> the real AgentClient
// singleton -> the real /api/stream SSE route -> a real EventSource in a
// real headless Chromium -> real DOM.
//
// Kept to the few assertions the issue's acceptance criteria call for
// (connection data lands in the DOM, the capture-degraded banner reacts to
// a real event, a user action round-trips back through /api/control to the
// agent) rather than re-covering ground the jsdom component suite already
// owns.

let agent: FakeAgentDouble;

test.beforeAll(async () => {
  agent = new FakeAgentDouble();
  await agent.start();
});

test.afterAll(async () => {
  await agent.stop();
});

test('real browser sees live agent data flow through the whole relay pipeline', async ({ page }) => {
  await page.goto('/');

  // The "agent not connected" banner is shown until the real AgentClient's
  // TCP connection to the fake agent actually completes and the resulting
  // connection_status event reaches this real EventSource — this is the
  // one assertion in the whole test that has nothing to fake: if the real
  // socket/relay/SSE chain is broken anywhere, this never happens.
  await expect(page.getByText(/capture agent not connected/i)).toBeHidden({ timeout: 15_000 });

  // A connection_update event, sent over the real socket, should reach the
  // real DOM inside the Connections view.
  agent.send({
    type: 'connection_update',
    connection: {
      id: 'Tcp-192.168.1.10:51000-203.0.113.55:443',
      protocol: 'HTTPS/TLS',
      appLayerProtocol: 'HTTPS/TLS',
      transportProtocol: 'TCP',
      osiStack: 'L4:Tcp -> L3:IP',
      localAddr: '192.168.1.10',
      localPort: 51000,
      remoteAddr: '203.0.113.55',
      remotePort: 443,
      processName: 'Safari',
      pid: 1234,
      rxSpeed: 1024.0,
      txSpeed: 512.0,
      rxBytesTotal: 4096,
      txBytesTotal: 2048,
      latencyMs: 20.0,
      packetLoss: 0.0,
      status: 'ESTABLISHED',
      encryption: 'TLS',
      sparkline: [],
    },
  });

  await page.getByRole('button', { name: /F3: SOCKETS/ }).click();
  await expect(page.getByText('203.0.113.55:443')).toBeVisible({ timeout: 10_000 });

  // A capture_stats event reporting drops should surface the persistent
  // "capture degraded" banner — real DOM, real conditional render, not a
  // jsdom toBeInTheDocument() check that wouldn't notice a CSS mistake.
  await expect(page.getByText(/capture degraded/i)).toHaveCount(0);
  agent.send({
    type: 'capture_stats',
    stats: { received: 100, dropped: 7, ifDropped: 0, relayLaggedEvents: 0, unparseableFrames: 0 },
  });
  await expect(page.getByText(/capture degraded/i)).toBeVisible({ timeout: 10_000 });

  // Typing "pause" into the command bar should round-trip through the real
  // /api/control POST handler and reach the fake agent as a real "pause"
  // line over the real socket — not a mocked fetch.
  const commandInput = page.getByPlaceholder(/Type CLI command/i);
  await commandInput.fill('pause');
  await commandInput.press('Enter');

  await agent.waitForControlMessage(
    (msg) => typeof msg === 'object' && msg !== null && (msg as { type?: string }).type === 'pause'
  );
});
