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

  it('reassembles a JSON line split across two separate socket writes', async () => {
    // Exercises the `this.buffer.indexOf('\n')` accumulation loop itself,
    // not just whole-line writes — a real TCP stream gives no guarantee a
    // JSON line arrives in a single `data` chunk.
    const line = '{"type":"agent_status","interface":"en0","capturing":true}\n';
    const splitAt = 20; // lands mid-object, well before the trailing newline
    server = net.createServer((socket) => {
      socket.write(line.slice(0, splitAt));
      setTimeout(() => socket.write(line.slice(splitAt)), 20);
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

  it('emits a connected status on a successful connection', async () => {
    server = net.createServer(() => {
      // Accept the connection and go idle — this test only cares about the
      // 'connect' handler's status emission, not any subsequent data.
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as net.AddressInfo).port;

    const client = new AgentClient('127.0.0.1', port);
    const status = await new Promise((resolve) => {
      client.on('status', resolve);
      client.start();
    });

    expect(status).toEqual({ connected: true });
    client.stop();
  });

  it('parses multiple newline-delimited JSON events delivered in a single chunk', async () => {
    server = net.createServer((socket) => {
      socket.write(
        '{"type":"agent_status","interface":"en0","capturing":true}\n' +
          '{"type":"agent_status","interface":"en0","capturing":false}\n'
      );
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as net.AddressInfo).port;

    const client = new AgentClient('127.0.0.1', port);
    const received: unknown[] = [];
    await new Promise<void>((resolve) => {
      client.on('event', (event) => {
        received.push(event);
        if (received.length === 2) resolve();
      });
      client.start();
    });

    expect(received).toEqual([
      { type: 'agent_status', interface: 'en0', capturing: true },
      { type: 'agent_status', interface: 'en0', capturing: false },
    ]);
    client.stop();
  });

  it('skips a malformed JSON line and still parses the valid line that follows', async () => {
    server = net.createServer((socket) => {
      socket.write('not valid json\n{"type":"agent_status","interface":"en0","capturing":true}\n');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as net.AddressInfo).port;

    const client = new AgentClient('127.0.0.1', port);
    const received: unknown[] = [];
    await new Promise<void>((resolve) => {
      client.on('event', (event) => {
        received.push(event);
        resolve();
      });
      client.start();
    });

    // Only the valid line surfaces as an 'event' — the malformed one is
    // dropped silently rather than crashing the relay or emitting garbage.
    expect(received).toEqual([{ type: 'agent_status', interface: 'en0', capturing: true }]);
    client.stop();
  });

  it('skips blank lines without emitting an event for them', async () => {
    server = net.createServer((socket) => {
      socket.write('\n\n{"type":"agent_status","interface":"en0","capturing":true}\n');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as net.AddressInfo).port;

    const client = new AgentClient('127.0.0.1', port);
    const received: unknown[] = [];
    await new Promise<void>((resolve) => {
      client.on('event', (event) => {
        received.push(event);
        resolve();
      });
      client.start();
    });

    expect(received).toEqual([{ type: 'agent_status', interface: 'en0', capturing: true }]);
    client.stop();
  });

  it('writes control messages as newline-delimited JSON', async () => {
    const receivedRaw = new Promise<string>((resolve) => {
      server = net.createServer((socket) => {
        socket.on('data', (chunk) => resolve(chunk.toString('utf8')));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as net.AddressInfo).port;

    const client = new AgentClient('127.0.0.1', port);
    await new Promise<void>((resolve) => {
      client.on('status', (s) => {
        if ((s as { connected: boolean }).connected) resolve();
      });
      client.start();
    });

    client.sendControl({ type: 'set_capture_filter', filter: 'tcp port 443' });

    const raw = await receivedRaw;
    expect(raw).toBe('{"type":"set_capture_filter","filter":"tcp port 443"}\n');
    client.stop();
  });

  it('silently no-ops sendControl when there is no active connection', () => {
    // Constructed but never start()ed — this.socket stays null, exercising
    // the `this.socket?.write(...)` optional chain rather than throwing.
    const client = new AgentClient('127.0.0.1', 1);
    expect(() => client.sendControl({ type: 'pause' })).not.toThrow();
  });

  it('tracks isConnected() across the connect/disconnect lifecycle', async () => {
    server = net.createServer(() => {});
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as net.AddressInfo).port;

    const client = new AgentClient('127.0.0.1', port);
    expect(client.isConnected()).toBe(false);

    await new Promise<void>((resolve) => {
      client.on('status', (s) => {
        if ((s as { connected: boolean }).connected) resolve();
      });
      client.start();
    });
    expect(client.isConnected()).toBe(true);

    client.stop();
    expect(client.isConnected()).toBe(false);
  });

  it('destroys the underlying socket on stop()', async () => {
    const serverSawClose = new Promise<void>((resolve) => {
      server = net.createServer((socket) => {
        socket.on('close', resolve);
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as net.AddressInfo).port;

    const client = new AgentClient('127.0.0.1', port);
    await new Promise<void>((resolve) => {
      client.on('status', (s) => {
        if ((s as { connected: boolean }).connected) resolve();
      });
      client.start();
    });

    client.stop();
    await serverSawClose;
  });

  it('reconnects automatically once the agent becomes reachable again', async () => {
    // Full end-to-end reconnect cycle: connect, server-side disconnect,
    // observe the 'connected: false' status, then wait past
    // RECONNECT_DELAY_MS and observe a fresh 'connected: true' — proving
    // the reconnect timer set up in handleDisconnect actually fires and
    // succeeds, not just that it's scheduled (covered separately by the
    // double-schedule regression test above).
    server = net.createServer((socket) => {
      socket.end();
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as net.AddressInfo).port;

    const client = new AgentClient('127.0.0.1', port);
    const statuses: Array<{ connected: boolean }> = [];
    const sawSecondConnect = new Promise<void>((resolve) => {
      client.on('status', (s) => {
        statuses.push(s as { connected: boolean });
        const connects = statuses.filter((x) => x.connected).length;
        if (connects === 2) resolve();
      });
    });

    client.start();
    await sawSecondConnect;
    expect(statuses.filter((s) => s.connected)).toHaveLength(2);
    expect(statuses.filter((s) => !s.connected).length).toBeGreaterThanOrEqual(1);

    client.stop();
  }, 8000);
});
