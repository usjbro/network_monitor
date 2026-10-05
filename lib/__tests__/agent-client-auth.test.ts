import { afterEach, expect, test, vi } from 'vitest';
import net from 'node:net';
import fs from 'node:fs';
import { AgentClient } from '../agent-client';
import { createAuthFixture } from './fixtures/agent-auth';
const fixtures: ReturnType<typeof createAuthFixture>[] = [];
const servers: net.Server[] = [];
const clients: AgentClient[] = [];
const sockets: net.Socket[] = [];
afterEach(() => { for (const c of clients.splice(0))
    c.stop(); for (const s of sockets.splice(0))
    s.destroy(); for (const s of servers.splice(0))
    s.close(); for (const f of fixtures.splice(0))
    f.close(); vi.restoreAllMocks(); });
const delay = (ms: number) => new Promise(r => setTimeout(r, ms));
async function setup(accept: (socket: net.Socket) => void) { const f = createAuthFixture(); fixtures.push(f); const server = net.createServer(socket => { sockets.push(socket); accept(socket); }); servers.push(server); await new Promise<void>(r => server.listen(0, '127.0.0.1', r)); const client = new AgentClient('127.0.0.1', (server.address() as net.AddressInfo).port, f.file); clients.push(client); return { f, client, server }; }
test('auth is first and controls wait for ack', async () => { let peer!: net.Socket; let received = ''; const { f, client } = await setup(s => { peer = s; s.on('data', c => received += c.toString()); }); const events: unknown[] = []; const statuses: unknown[] = []; client.on('event', e => events.push(e)); client.on('status', s => statuses.push(s)); client.start(); await delay(60); expect(client.isConnected()).toBe(false); client.sendControl({ type: 'pause' }); await delay(30); expect(JSON.parse(received.trim())).toEqual({ type: 'authenticate', token: f.token }); expect(events).toEqual([]); expect(statuses).toEqual([]); const ready = new Promise(r => client.once('status', r)); peer.write('{"type":"authenticated"}\n'); await ready; expect(client.isConnected()).toBe(true); client.sendControl({ type: 'pause' }); await delay(30); expect(received.split('\n').filter(Boolean).map(x => JSON.parse(x).type)).toEqual(['authenticate', 'pause']); });
test('split ack is consumed and coalesced large events survive', async () => { const { client } = await setup(s => s.once('data', () => { s.write('{"type":"auth'); setTimeout(() => s.write('enticated"}\n' + JSON.stringify({ type: 'test', data: 'x'.repeat(1024) }) + '\n'), 10); })); const event = new Promise(r => client.once('event', r)); client.start(); expect(await event).toEqual({ type: 'test', data: 'x'.repeat(1024) }); });
test.each(['{"type":"packet"}\n', '{"type":"authenticated","extra":true}\n', 'x'.repeat(256) + '\n', '{bad}\n'])('rejects unexpected acknowledgement without emission: %s', async (ack) => { const { client } = await setup(s => s.once('data', () => s.write(ack))); const events: unknown[] = []; client.on('event', e => events.push(e)); const disconnected = new Promise(r => client.once('status', r)); client.start(); expect(await disconnected).toEqual({ connected: false }); expect(events).toEqual([]); expect(client.isConnected()).toBe(false); });
test('missing credential fails closed without opening TCP', async () => { let accepts = 0; const { f, client } = await setup(() => accepts++); fs.unlinkSync(f.file); const status = new Promise(r => client.once('status', r)); client.start(); expect(await status).toEqual({ connected: false }); await delay(30); expect(accepts).toBe(0); });
test('reconnect reads rotated token and resets partial buffers', async () => { let attempts = 0; let first!: net.Socket; const tokens: string[] = []; const { f, client } = await setup(s => s.once('data', c => { tokens.push(JSON.parse(c.toString().trim()).token); s.write('{"type":"authenticated"}\n'); if (++attempts === 1) {
    first = s;
    s.write('{"type":"old');
}
else {
    s.write('{"type":"new"}\n');
} })); const ready = new Promise(r => client.once('status', r)); client.start(); await ready; f.rotate(); const event = new Promise(r => client.once('event', r)); first.destroy(); expect(await event).toEqual({ type: 'new' }); expect(tokens[0]).not.toBe(tokens[1]); expect(tokens[1]).toBe(f.token); }, 8000);
test('stop ignores old socket callbacks and cancels authentication timeout', async () => { const { client } = await setup(() => { }); const events: unknown[] = []; const statuses: unknown[] = []; client.on('event', e => events.push(e)); client.on('status', s => statuses.push(s)); client.start(); await delay(50); const socket = (client as unknown as {
    socket: net.Socket;
}).socket; client.stop(); socket.emit('data', Buffer.from('{"type":"authenticated"}\n{"type":"old"}\n')); socket.emit('close'); await delay(30); expect(events).toEqual([]); expect(statuses).toEqual([]); expect(client.isConnected()).toBe(false); });
test('missing ack expires at the absolute deadline', async () => { const { client } = await setup(s => { const timer = setInterval(() => s.write(' '), 400); s.on('close', () => clearInterval(timer)); }); const status = new Promise(r => client.once('status', r)); const start = Date.now(); client.start(); expect(await status).toEqual({ connected: false }); expect(Date.now() - start).toBeLessThan(6000); expect(client.isConnected()).toBe(false); }, 7000);
test('accepts acknowledgement split at every byte boundary', async () => { for (let split = 1; split < 25; split++) {
    const ack = '{\"type\":\"authenticated\"}\n';
    const { client } = await setup(s => s.once('data', () => { s.write(ack.slice(0, split)); setTimeout(() => s.write(ack.slice(split)), 1); }));
    const status = new Promise(r => client.once('status', r));
    client.start();
    expect(await status).toEqual({ connected: true });
    client.stop();
} });
