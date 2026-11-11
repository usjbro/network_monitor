// KAN-129 Task 2 (spec D5, plan P5): POST /api/tcp-samples, the Pages API
// route behind the TCP stream graphs. Exercised through a real Node HTTP
// server (the route's transport is Node's ServerResponse, whose
// finish/close/error events release admission), with a fake agent.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import http from 'node:http';
import net from 'node:net';
import { EventEmitter } from 'node:events';
import { handleTcpSamples, type TcpSamplesAgent } from '../tcp-samples-route';
import { Admission } from '../agent-admission';
import { AgentRequestError } from '../agent-request';
import { getAgentClient } from '../agent-client-singleton';
import { buildStreamResponse, type StreamEnrichmentClient, type StreamGeoIpClient } from '../stream-response';
import type { AgentClient } from '../agent-client';

type Call = { message: Record<string, unknown>; opts: { replyType: string; signal: AbortSignal; timeoutMs?: number } };

class FakeAgent implements TcpSamplesAgent {
  calls: Call[] = [];
  answer: (call: Call) => Promise<unknown> = (call) =>
    Promise.resolve({ type: 'tcp_samples', connectionId: call.message.connectionId, found: false });
  request<T>(message: Record<string, unknown>, opts: Call['opts']): Promise<T> {
    const call = { message, opts };
    this.calls.push(call);
    return this.answer(call) as Promise<T>;
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

let server: http.Server;
let port: number;
let agent: FakeAgent;
let admission: Admission;
const sockets: net.Socket[] = [];

beforeEach(async () => {
  agent = new FakeAgent();
  admission = new Admission({ maxInFlight: 4, reservationBytes: 256 * 1024 });
  server = http.createServer((req, res) => {
    void handleTcpSamples(req, res, { agent, admission });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as net.AddressInfo).port;
});

afterEach(async () => {
  for (const socket of sockets.splice(0)) socket.destroy();
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
});

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

interface Reply {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function send(
  body: string | Buffer | undefined,
  { method = 'POST', headers = {} as Record<string, string> } = {},
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: '/api/tcp-samples', method, headers: { 'content-type': 'application/json', ...headers } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    if (body !== undefined) req.end(body);
    else req.end();
  });
}

const post = (value: unknown, headers: Record<string, string> = {}) => send(JSON.stringify(value), { headers });

function expectFixedError(reply: Reply, status: number) {
  expect(reply.status).toBe(status);
  expect(reply.headers['cache-control']).toBe('no-store');
  expect(Buffer.byteLength(reply.body)).toBeLessThanOrEqual(256);
  expect(JSON.parse(reply.body)).toEqual({ error: expect.any(String) });
}

describe('guards, in order', () => {
  it('405 for anything but POST, before any other check', async () => {
    for (const method of ['GET', 'PUT', 'DELETE']) {
      const reply = await send(undefined, { method, headers: { 'sec-fetch-site': 'cross-site' } });
      expectFixedError(reply, 405);
      expect(reply.headers.allow).toBe('POST');
    }
    expect(agent.calls).toEqual([]);
  });

  // The same Origin / Sec-Fetch-Site cases as /api/control's (same-origin.test.ts).
  it.each([
    [{ 'sec-fetch-site': 'same-origin' }, 200],
    [{ 'sec-fetch-site': 'none' }, 200],
    [{ 'sec-fetch-site': 'cross-site' }, 403],
    [{ 'sec-fetch-site': 'same-site' }, 403],
    [{ origin: 'SELF' }, 200],
    [{ origin: 'https://evil.example' }, 403],
    [{ origin: 'http://127.0.0.1:9999' }, 403],
    [{ origin: 'not a url' }, 403],
    [{}, 200],
    [{ 'sec-fetch-site': 'cross-site', origin: 'SELF' }, 403],
  ])('cross-site check %j → %i', async (headers: Record<string, string>, status) => {
    const resolved = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k, v === 'SELF' ? `http://127.0.0.1:${port}` : v]),
    );
    const reply = await post({ connectionId: 'c1' }, resolved);
    expect(reply.status).toBe(status);
    if (status === 403) {
      expectFixedError(reply, 403);
      expect(agent.calls).toEqual([]);
    }
  });

  it('a cross-site request is refused before its body is judged', async () => {
    const reply = await send('x'.repeat(4096), { headers: { 'sec-fetch-site': 'cross-site' } });
    expectFixedError(reply, 403);
  });

  it('413 for a body over 512 bytes, declared or streamed', async () => {
    const padded = JSON.stringify({ connectionId: 'c1', pad: 'x'.repeat(600) });
    expectFixedError(await send(padded), 413);
    expectFixedError(await send(padded, { headers: { 'transfer-encoding': 'chunked' } }), 413);
    expect(agent.calls).toEqual([]);
  });

  it('a body of exactly 512 bytes is accepted', async () => {
    const base = JSON.stringify({ connectionId: 'c1', pad: '' });
    const body = JSON.stringify({ connectionId: 'c1', pad: 'x'.repeat(512 - base.length) });
    expect(Buffer.byteLength(body)).toBe(512);
    expect((await send(body)).status).toBe(200);
  });

  it.each([
    ['not json', '{connectionId'],
    ['an array', '[]'],
    ['null', 'null'],
    ['no connectionId', '{}'],
    ['an empty connectionId', JSON.stringify({ connectionId: '' })],
    ['a connectionId over 128 characters', JSON.stringify({ connectionId: 'c'.repeat(129) })],
    ['a non-string connectionId', JSON.stringify({ connectionId: 5 })],
    ['a generation without the counter', JSON.stringify({ connectionId: 'c', generation: '4be1a07c9d22f310' })],
    ['an uppercase generation', JSON.stringify({ connectionId: 'c', generation: '4BE1A07C9D22F310:1' })],
    ['a short generation epoch', JSON.stringify({ connectionId: 'c', generation: '4be1:1' })],
    ['a 21-digit generation counter', JSON.stringify({ connectionId: 'c', generation: `4be1a07c9d22f310:${'1'.repeat(21)}` })],
    ['a non-string generation', JSON.stringify({ connectionId: 'c', generation: 7 })],
    ['a negative fromIndex', JSON.stringify({ connectionId: 'c', fromIndex: -1 })],
    ['a fractional fromIndex', JSON.stringify({ connectionId: 'c', fromIndex: 1.5 })],
    ['an unsafe fromIndex', JSON.stringify({ connectionId: 'c', fromIndex: 2 ** 53 })],
    ['a string fromIndex', JSON.stringify({ connectionId: 'c', fromIndex: '5' })],
  ])('400 for %s', async (_label, body) => {
    expectFixedError(await send(body), 400);
    expect(agent.calls).toEqual([]);
  });

  it('a connectionId of exactly 128 characters is accepted', async () => {
    expect((await post({ connectionId: 'c'.repeat(128) })).status).toBe(200);
  });
});

describe('forwarding', () => {
  it('sends get_tcp_samples with only the validated fields and returns the reply with no-store', async () => {
    agent.answer = async (call) => ({ type: 'tcp_samples', connectionId: call.message.connectionId, found: true, nextIndex: 3 });
    const reply = await post({
      connectionId: 'Tcp-192.168.1.10:51000-93.184.216.34:443',
      generation: '4be1a07c9d22f310:17',
      fromIndex: 18230,
      extra: 'ignored',
    });
    expect(reply.status).toBe(200);
    expect(reply.headers['cache-control']).toBe('no-store');
    expect(reply.headers['content-type']).toMatch(/^application\/json/);
    expect(JSON.parse(reply.body)).toEqual({
      type: 'tcp_samples',
      connectionId: 'Tcp-192.168.1.10:51000-93.184.216.34:443',
      found: true,
      nextIndex: 3,
    });
    expect(agent.calls).toHaveLength(1);
    expect(agent.calls[0].message).toEqual({
      type: 'get_tcp_samples',
      connectionId: 'Tcp-192.168.1.10:51000-93.184.216.34:443',
      generation: '4be1a07c9d22f310:17',
      fromIndex: 18230,
    });
    expect(agent.calls[0].opts.replyType).toBe('tcp_samples');
    expect(admission.inFlight()).toBe(0);
  });

  it('omits absent optional fields', async () => {
    await post({ connectionId: 'c1' });
    expect(agent.calls[0].message).toEqual({ type: 'get_tcp_samples', connectionId: 'c1' });
  });

  it('a reply for a different connection is a 502', async () => {
    agent.answer = async () => ({ type: 'tcp_samples', connectionId: 'other', found: false });
    expectFixedError(await post({ connectionId: 'c1' }), 502);
  });

  it.each([
    [503, 503],
    [504, 504],
    [502, 502],
  ] as const)('an agent failure with status %i answers %i', async (status, expected) => {
    agent.answer = async () => {
      throw new AgentRequestError(status, 'x');
    };
    expectFixedError(await post({ connectionId: 'c1' }), expected);
    expect(admission.inFlight()).toBe(0);
  });

  it('an unexpected failure is a 502 that reveals nothing', async () => {
    agent.answer = async () => {
      throw new Error('secret detail /home/user/.network-monitor');
    };
    const reply = await post({ connectionId: 'c1' });
    expectFixedError(reply, 502);
    expect(reply.body).not.toContain('secret');
  });
});

describe('admission', () => {
  it('20 concurrent distinct connections: at most 4 reach the agent, the rest get 429 at once', async () => {
    const gates = Array.from({ length: 20 }, () => deferred<unknown>());
    agent.answer = (call) => gates[Number(String(call.message.connectionId).slice(1))].promise;
    const replies = Array.from({ length: 20 }, (_, i) => post({ connectionId: `c${i}` }));
    for (let i = 0; i < 100 && agent.calls.length < 4; i++) await delay(5);
    await delay(30);
    expect(agent.calls).toHaveLength(4);
    expect(admission.inFlight()).toBe(4);
    for (const call of agent.calls) {
      gates[Number(String(call.message.connectionId).slice(1))].resolve({
        type: 'tcp_samples',
        connectionId: call.message.connectionId,
        found: false,
      });
    }
    const statuses = (await Promise.all(replies)).map((r) => r.status);
    expect(statuses.filter((s) => s === 200)).toHaveLength(4);
    expect(statuses.filter((s) => s === 429)).toHaveLength(16);
    expect(agent.calls).toHaveLength(4);
    expect(admission.inFlight()).toBe(0);
  });

  it('two concurrent requests for one connection: one is forwarded', async () => {
    const gate = deferred<unknown>();
    agent.answer = () => gate.promise;
    const first = post({ connectionId: 'same' });
    for (let i = 0; i < 100 && agent.calls.length < 1; i++) await delay(5);
    const second = await post({ connectionId: 'same' });
    expectFixedError(second, 429);
    gate.resolve({ type: 'tcp_samples', connectionId: 'same', found: false });
    expect((await first).status).toBe(200);
    expect(agent.calls).toHaveLength(1);
  });

  it('a client that disconnects mid-request aborts the agent request and frees its slot', async () => {
    agent.answer = (call) =>
      new Promise((_, reject) => call.opts.signal.addEventListener('abort', () => reject(new AgentRequestError(499, 'aborted'))));
    const socket = net.connect(port, '127.0.0.1');
    sockets.push(socket);
    const body = JSON.stringify({ connectionId: 'gone' });
    socket.write(`POST /api/tcp-samples HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
    for (let i = 0; i < 100 && agent.calls.length < 1; i++) await delay(5);
    expect(admission.inFlight()).toBe(1);
    socket.destroy();
    for (let i = 0; i < 100 && admission.inFlight() > 0; i++) await delay(5);
    expect(agent.calls[0].opts.signal.aborted).toBe(true);
    expect(admission.inFlight()).toBe(0);
  });
});

describe('slow readers hold their slots until the HTTP response ends', () => {
  // A response held in the relay's memory is what the reservation bounds,
  // so the slot is released on ServerResponse finish/close/error, never when
  // the agent replies. The fake reply is larger than the real 256 KiB
  // ceiling so it cannot fit in loopback socket buffers: these clients
  // really do leave it unread in the relay.
  const big = 'p'.repeat(8 * 1024 * 1024);

  function stalledClient(connectionId: string): net.Socket {
    const socket = net.connect(port, '127.0.0.1');
    sockets.push(socket);
    const body = JSON.stringify({ connectionId });
    socket.write(`POST /api/tcp-samples HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
    socket.pause();
    return socket;
  }

  it('four stalled readers hold all four slots after the agent replied; a fifth gets 429 until one ends', async () => {
    const replied: string[] = [];
    agent.answer = async (call) => {
      replied.push(String(call.message.connectionId));
      return { type: 'tcp_samples', connectionId: call.message.connectionId, found: true, pad: big };
    };
    const stalled = ['s0', 's1', 's2', 's3'].map(stalledClient);
    for (let i = 0; i < 200 && replied.length < 4; i++) await delay(5);
    await delay(100);
    expect(replied).toHaveLength(4);
    expect(admission.inFlight()).toBe(4);

    agent.answer = async (call) => ({ type: 'tcp_samples', connectionId: call.message.connectionId, found: false });
    expectFixedError(await post({ connectionId: 'fifth' }), 429);

    // An aborted stalled reader frees its slot.
    stalled[0].destroy();
    for (let i = 0; i < 100 && admission.inFlight() > 3; i++) await delay(5);
    expect(admission.inFlight()).toBe(3);
    expect((await post({ connectionId: 'fifth' })).status).toBe(200);

    // A reader that drains its body to the end frees its slot on finish.
    const drained = new Promise((resolve) => stalled[1].on('end', resolve));
    stalled[1].on('data', () => {});
    stalled[1].resume();
    stalled[1].end();
    for (let i = 0; i < 400 && admission.inFlight() > 2; i++) await delay(5);
    expect(admission.inFlight()).toBe(2);
    void drained;
  }, 20_000);
});

describe('one agent connection per process', () => {
  afterEach(() => {
    global.__agentClient = undefined;
  });

  it('the Pages route and the SSE stream share global.__agentClient', async () => {
    const shared = Object.assign(new EventEmitter(), {
      isConnected: () => true,
      calls: [] as unknown[],
      request(message: unknown) {
        this.calls.push(message);
        return Promise.resolve({ type: 'tcp_samples', connectionId: 'c1', found: false });
      },
    });
    global.__agentClient = shared as unknown as AgentClient;
    expect(getAgentClient()).toBe(shared);

    const routeServer = http.createServer((req, res) => void handleTcpSamples(req, res, { admission }));
    await new Promise<void>((resolve) => routeServer.listen(0, '127.0.0.1', resolve));
    const routePort = (routeServer.address() as net.AddressInfo).port;
    const status = await new Promise<number>((resolve) => {
      const req = http.request({ host: '127.0.0.1', port: routePort, path: '/api/tcp-samples', method: 'POST' }, (res) => {
        res.resume();
        resolve(res.statusCode!);
      });
      req.end(JSON.stringify({ connectionId: 'c1' }));
    });
    routeServer.close();
    expect(status).toBe(200);
    expect(shared.calls).toHaveLength(1);

    const enrichment = Object.assign(new EventEmitter(), { getMode: () => 'off', notifyObservedConnections() {} });
    const geoip = Object.assign(new EventEmitter(), { getMode: () => 'off', lookup() {} });
    const response = buildStreamResponse({
      enrichment: enrichment as unknown as StreamEnrichmentClient,
      geoip: geoip as unknown as StreamGeoIpClient,
    });
    const reader = response.body!.getReader();
    await reader.read();
    expect(shared.listenerCount('event')).toBeGreaterThan(0);
    await reader.cancel();
  });
});
