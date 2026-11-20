// Shared by the TCP graphs (KAN-129) and flow ladder (KAN-130) specs: the
// connection both open, the columnar reply encoding, and a fetch wrapper
// that timestamps each `/api/tcp-samples` reply as the page finishes
// parsing it (window.__tcpParsed), for the one-frame budget.
import type { Page } from '@playwright/test';

export const TCP_ID = 'Tcp-192.168.1.10:51000-93.184.216.34:443';

export const TCP_CONNECTION = {
  id: TCP_ID, protocol: 'HTTPS/TLS', appLayerProtocol: 'HTTPS/TLS', transportProtocol: 'TCP', osiStack: 'x',
  localAddr: '192.168.1.10', localPort: 51000, remoteAddr: '93.184.216.34', remotePort: 443, processName: 'curl', pid: 1,
  rxSpeed: 0, txSpeed: 0, rxBytesTotal: 0, txBytesTotal: 0, latencyMs: 20, packetLoss: 0, status: 'ESTABLISHED',
  encryption: 'TLS', sparkline: [],
};

export interface SampleRow { tUs: number; seq: number; ack: number; win: number; len: number; flags: number; mark: number; rttUs: number }

/** The reply's columnar layout: `tUs[0]` absolute, then deltas. */
export function columns(rows: SampleRow[]) {
  return {
    tUs: rows.map((r, i) => (i === 0 ? r.tUs : r.tUs - rows[i - 1].tUs)),
    seq: rows.map((r) => r.seq), ack: rows.map((r) => r.ack), win: rows.map((r) => r.win), len: rows.map((r) => r.len),
    flags: rows.map((r) => r.flags), mark: rows.map((r) => r.mark), rttUs: rows.map((r) => r.rttUs),
  };
}

export async function instrumentSamplesFetch(page: Page): Promise<void> {
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
}

export const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
