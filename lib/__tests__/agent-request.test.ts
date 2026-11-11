// KAN-129 Task 2 (spec D5, plan P3/P4): the relay's shared request/response
// core. A request gets a random requestId, the agent's correlated reply
// resolves only that request and never reaches 'event' listeners, and every
// pending request settles exactly once.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import net from 'node:net';
import { AgentClient } from '../agent-client';
import { AgentRequestError, REQUEST_TIMEOUT_MS, registerReplyType, replyTypeFor } from '../agent-request';
import { createAuthFixture } from './fixtures/agent-auth';

const TEST_REPLY = 'test_reply';
const MAX_LINE = 1024;

registerReplyType({
  type: TEST_REPLY,
  maxLineBytes: MAX_LINE,
  validate(json) {
    const reply = json as { ok?: unknown };
    if (reply.ok !== true) throw new Error('not ok');
    return { ok: true, echo: (json as { echo?: unknown }).echo };
  },
});

let auth: ReturnType<typeof createAuthFixture>;
let server: net.Server | undefined;
let client: AgentClient | undefined;
const peers: net.Socket[] = [];

beforeEach(() => {
  auth = createAuthFixture();
});
afterEach(() => {
  client?.stop();
  client = undefined;
  for (const peer of peers.splice(0)) peer.destroy();
  server?.close();
  server = undefined;
  auth.close();
});

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** A fake agent that records every control line after authentication. */
async function connect() {
  const lines: Record<string, unknown>[] = [];
  let peer!: net.Socket;
  const accepted = new Promise<void>((resolve) => {
    server = auth.createServer((socket) => {
      peer = socket;
      peers.push(socket);
      // Each test write is its own segment: no Nagle/delayed-ACK coalescing delay.
      socket.setNoDelay(true);
      let buffer = '';
      socket.on('data', (chunk) => {
        buffer += chunk.toString('utf8');
        let end: number;
        while ((end = buffer.indexOf('\n')) >= 0) {
          lines.push(JSON.parse(buffer.slice(0, end)));
          buffer = buffer.slice(end + 1);
        }
      });
      resolve();
    });
  });
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
  client = new AgentClient('127.0.0.1', (server!.address() as net.AddressInfo).port, auth.file);
  const events: unknown[] = [];
  client.on('event', (event) => events.push(event));
  const ready = new Promise((resolve) => client!.once('status', resolve));
  client.start();
  await accepted;
  await ready;
  const nextLine = async () => {
    const start = lines.length;
    for (let i = 0; i < 100 && lines.length === start; i++) await delay(5);
    return lines[lines.length - 1];
  };
  return { client: client!, peer, lines, events, nextLine };
}

function request(c: AgentClient, extra: Record<string, unknown> = {}, opts: { signal?: AbortSignal; timeoutMs?: number } = {}) {
  return c.request<{ ok: boolean; echo?: unknown }>(
    { type: 'test_request', ...extra },
    { replyType: TEST_REPLY, signal: opts.signal ?? new AbortController().signal, timeoutMs: opts.timeoutMs ?? 2000 },
  );
}

async function rejection(promise: Promise<unknown>): Promise<AgentRequestError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(AgentRequestError);
    return error as AgentRequestError;
  }
  throw new Error('expected a rejection');
}

describe('AgentClient.request correlation', () => {
  it('writes one line carrying a fresh 128-bit requestId and resolves with the matching reply only', async () => {
    const { client, peer, events, nextLine } = await connect();
    const pending = request(client, { connectionId: 'c1' });
    const sent = await nextLine();
    expect(sent).toMatchObject({ type: 'test_request', connectionId: 'c1' });
    expect(sent.requestId).toMatch(/^[0-9a-f]{32}$/);

    peer.write(JSON.stringify({ type: TEST_REPLY, requestId: sent.requestId, ok: true, echo: 7 }) + '\n');
    peer.write('{"type":"agent_status","capturing":true}\n');
    await expect(pending).resolves.toEqual({ ok: true, echo: 7 });
    await delay(10);
    expect(events).toEqual([{ type: 'agent_status', capturing: true }]);
    expect(client.pendingRequestCount()).toBe(0);
  });

  it('a requestId supplied by the caller is replaced, never trusted', async () => {
    const { client, nextLine } = await connect();
    void request(client, { requestId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }).catch(() => {});
    expect((await nextLine()).requestId).not.toBe('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  });

  it('routes concurrent replies to their own requests in any order', async () => {
    const { client, peer, nextLine } = await connect();
    const a = request(client, { n: 1 });
    const idA = (await nextLine()).requestId;
    const b = request(client, { n: 2 });
    const idB = (await nextLine()).requestId;
    expect(idA).not.toBe(idB);
    peer.write(JSON.stringify({ type: TEST_REPLY, requestId: idB, ok: true, echo: 'b' }) + '\n');
    peer.write(JSON.stringify({ type: TEST_REPLY, requestId: idA, ok: true, echo: 'a' }) + '\n');
    await expect(a).resolves.toEqual({ ok: true, echo: 'a' });
    await expect(b).resolves.toEqual({ ok: true, echo: 'b' });
  });

  it('drops and counts unknown, late, malformed and mismatched replies without emitting them', async () => {
    const { client, peer, events, nextLine } = await connect();
    const timedOut = request(client, {}, { timeoutMs: 30 });
    const lateId = (await nextLine()).requestId;
    expect((await rejection(timedOut)).status).toBe(504);

    const live = request(client);
    const liveId = (await nextLine()).requestId as string;
    for (const line of [
      { type: TEST_REPLY, requestId: '0'.repeat(32), ok: true }, // unknown (forged)
      { type: TEST_REPLY, requestId: lateId, ok: true }, // late
      { type: TEST_REPLY, ok: true }, // malformed: no requestId
      { type: TEST_REPLY, requestId: liveId.toUpperCase(), ok: true }, // malformed: not lowercase hex
      { type: 'tcp_samples', requestId: liveId, connectionId: 'x', found: false }, // mismatched type
    ]) {
      peer.write(JSON.stringify(line) + '\n');
    }
    await delay(30);
    expect(client.droppedReplies()).toMatchObject({ unknown: 1, late: 1, malformed: 2, mismatched: 1 });
    expect(events).toEqual([]);
    expect(client.pendingRequestCount()).toBe(1);

    // The live request is still answerable after all of that.
    peer.write(JSON.stringify({ type: TEST_REPLY, requestId: liveId, ok: true }) + '\n');
    await expect(live).resolves.toEqual({ ok: true, echo: undefined });
  });

  it('a reply that fails validation fails its request with 502 and is counted', async () => {
    const { client, peer, nextLine } = await connect();
    const pending = request(client);
    const id = (await nextLine()).requestId;
    peer.write(JSON.stringify({ type: TEST_REPLY, requestId: id, ok: false }) + '\n');
    expect((await rejection(pending)).status).toBe(502);
    expect(client.droppedReplies().invalid).toBe(1);
    expect(client.pendingRequestCount()).toBe(0);
  });
});

describe('AgentClient.request settles exactly once', () => {
  it('times out with 504 and forgets the request', async () => {
    const { client } = await connect();
    const started = Date.now();
    expect((await rejection(request(client, {}, { timeoutMs: 40 }))).status).toBe(504);
    expect(Date.now() - started).toBeGreaterThanOrEqual(35);
    expect(client.pendingRequestCount()).toBe(0);
  });

  it('defaults to the spec’s 5 s correlation timeout', () => {
    expect(REQUEST_TIMEOUT_MS).toBe(5000);
  });

  it('an abort rejects with 499, clears the timer and ignores a later reply', async () => {
    const { client, peer, events, nextLine } = await connect();
    const controller = new AbortController();
    const pending = request(client, {}, { signal: controller.signal });
    const id = (await nextLine()).requestId;
    controller.abort();
    expect((await rejection(pending)).status).toBe(499);
    expect(client.pendingRequestCount()).toBe(0);
    peer.write(JSON.stringify({ type: TEST_REPLY, requestId: id, ok: true }) + '\n');
    await delay(20);
    expect(client.droppedReplies().late).toBe(1);
    expect(events).toEqual([]);
  });

  it('an already-aborted signal writes nothing', async () => {
    const { client, lines } = await connect();
    const controller = new AbortController();
    controller.abort();
    expect((await rejection(request(client, {}, { signal: controller.signal }))).status).toBe(499);
    await delay(20);
    expect(lines).toEqual([]);
  });

  it('a disconnect fails every pending request with 503', async () => {
    const { client, peer, nextLine } = await connect();
    const a = request(client);
    await nextLine();
    const b = request(client);
    await nextLine();
    peer.destroy();
    expect((await rejection(a)).status).toBe(503);
    expect((await rejection(b)).status).toBe(503);
    expect(client.pendingRequestCount()).toBe(0);
  });

  it('stop() fails pending requests with 503', async () => {
    const { client, nextLine } = await connect();
    const pending = request(client);
    await nextLine();
    client.stop();
    expect((await rejection(pending)).status).toBe(503);
  });

  it('a request while not authenticated fails with 503 without writing', async () => {
    const c = new AgentClient('127.0.0.1', 1, auth.file);
    expect((await rejection(request(c))).status).toBe(503);
  });

  it('a socket write backlog over 64 KiB fails with 503 without writing', async () => {
    const { client, lines } = await connect();
    const socket = (client as unknown as { socket: net.Socket }).socket;
    Object.defineProperty(socket, 'writableLength', { value: 64 * 1024 + 1, configurable: true });
    expect((await rejection(request(client))).status).toBe(503);
    Object.defineProperty(socket, 'writableLength', { value: 64 * 1024, configurable: true });
    const atLimit = request(client, {}, { timeoutMs: 20 });
    expect((await rejection(atLimit)).status).toBe(504);
    expect(lines).toHaveLength(1);
  });

  it('an unregistered reply type is refused before anything is written', async () => {
    const { client, lines } = await connect();
    await expect(
      client.request({ type: 'x' }, { replyType: 'never_registered', signal: new AbortController().signal }),
    ).rejects.toThrow();
    expect(lines).toEqual([]);
  });
});

describe('byte-bounded framing for registered reply types', () => {
  it('a reply line over its byte ceiling fails its request with 502, measured in UTF-8 bytes', async () => {
    const { client, peer, events, nextLine } = await connect();
    const pending = request(client);
    const id = (await nextLine()).requestId as string;
    const head = JSON.stringify({ type: TEST_REPLY, requestId: id, ok: true, echo: '' }).length;
    // Under the ceiling in UTF-16 code units, over it in bytes ('é' is 2 bytes).
    const echo = 'é'.repeat(MAX_LINE - head - 10);
    const line = JSON.stringify({ type: TEST_REPLY, requestId: id, ok: true, echo });
    expect(line.length).toBeLessThan(MAX_LINE);
    expect(Buffer.byteLength(line + '\n')).toBeGreaterThan(MAX_LINE);
    peer.write(line + '\n');
    peer.write('{"type":"agent_status"}\n');
    expect((await rejection(pending)).status).toBe(502);
    await delay(10);
    expect(client.droppedReplies().oversized).toBe(1);
    expect(events).toEqual([{ type: 'agent_status' }]);
  });

  it('a reply exactly at the ceiling, newline included, is accepted', async () => {
    const { client, peer, nextLine } = await connect();
    const pending = request(client);
    const id = (await nextLine()).requestId as string;
    const head = JSON.stringify({ type: TEST_REPLY, requestId: id, ok: true, echo: '' }).length;
    const line = JSON.stringify({ type: TEST_REPLY, requestId: id, ok: true, echo: 'x'.repeat(MAX_LINE - head - 1) });
    expect(Buffer.byteLength(line + '\n')).toBe(MAX_LINE);
    peer.write(line + '\n');
    await expect(pending).resolves.toMatchObject({ ok: true });
  });

  it('an oversized reply arriving in pieces is failed and discarded before its newline, not retained', async () => {
    const { client, peer, events, nextLine } = await connect();
    const pending = request(client);
    const failed = rejection(pending);
    const id = (await nextLine()).requestId as string;
    peer.write(JSON.stringify({ type: TEST_REPLY, requestId: id, ok: true }).slice(0, -1) + ',"echo":"');
    for (let i = 0; i < 8; i++) {
      peer.write('y'.repeat(MAX_LINE));
      await delay(5);
    }
    expect((await failed).status).toBe(502);
    expect((client as unknown as { buffer: string }).buffer.length).toBeLessThanOrEqual(MAX_LINE);
    peer.write('yyy"}\n{"type":"agent_status"}\n');
    await delay(20);
    expect(events).toEqual([{ type: 'agent_status' }]);
    expect(client.droppedReplies().oversized).toBe(1);
  });

  it('ordinary event lines are not capped', async () => {
    const { peer, events } = await connect();
    const big = { type: 'agent_status', pad: 'z'.repeat(MAX_LINE * 64) };
    peer.write(JSON.stringify(big) + '\n');
    await delay(30);
    expect(events).toEqual([big]);
  });
});

describe('reply type registry', () => {
  it('is shared through globalThis so separately bundled copies of the module agree', () => {
    expect(replyTypeFor(TEST_REPLY)?.maxLineBytes).toBe(MAX_LINE);
    expect(globalThis.__agentReplyTypes?.get(TEST_REPLY)).toBeDefined();
  });

  it('tcp_samples is registered by the agent client itself, with a 256 KiB ceiling', () => {
    expect(replyTypeFor('tcp_samples')?.maxLineBytes).toBe(256 * 1024);
  });
});
