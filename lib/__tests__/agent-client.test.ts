import { describe, expect, it, vi, afterEach } from 'vitest';
import net from 'node:net';
import { AgentClient } from '../agent-client';

describe('AgentClient', () => {
  let server: net.Server;
  let port: number;

  afterEach(() => {
    server?.close();
  });

  it('parses newline-delimited JSON lines into "event" emissions', async () => {
    server = net.createServer((socket) => {
      socket.write('{"type":"agent_status","interface":"en0","capturing":true}\n');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as net.AddressInfo).port;

    const client = new AgentClient('127.0.0.1', port);
    const received = await new Promise((resolve) => {
      client.on('event', resolve);
      client.start();
    });

    expect(received).toEqual({ type: 'agent_status', interface: 'en0', capturing: true });
    client.stop();
  });

  it('emits a disconnected status when the agent is unreachable', async () => {
    const client = new AgentClient('127.0.0.1', 1); // port 1 refuses connections
    const status = await new Promise((resolve) => {
      client.on('status', resolve);
      client.start();
    });
    expect(status).toEqual({ connected: false });
    client.stop();
  });
});
