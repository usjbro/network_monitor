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

  it('does not double-schedule reconnects when a failed attempt emits both "error" and "close"', async () => {
    // Regression test for a reconnect storm: a refused TCP connection fires
    // BOTH 'error' and 'close' on the socket. If handleDisconnect isn't
    // guarded against running twice, each failed attempt schedules two
    // reconnect timers instead of one, doubling the attempt rate every cycle.
    const client = new AgentClient('127.0.0.1', 1); // port 1 refuses connections
    const statuses: unknown[] = [];
    client.on('status', (s) => statuses.push(s));

    // Spy on the private connect() path indirectly by counting how many times
    // a new socket connection is attempted via the 'status' events it
    // produces — each real connection attempt yields exactly one
    // {connected:false} status if (and only if) the double-emit is guarded.
    client.start();

    // Wait for the first failed attempt's status to land.
    await new Promise((resolve) => client.once('status', resolve));
    expect(statuses).toHaveLength(1);

    client.stop();
    // Give any stray timers a moment to prove they don't fire after stop().
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(statuses).toHaveLength(1);
  });
});
