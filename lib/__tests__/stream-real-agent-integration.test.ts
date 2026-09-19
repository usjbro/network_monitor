import { describe, expect, it, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import { AgentClient } from '../agent-client';
import { buildStreamResponse, StreamEnrichmentClient, StreamGeoIpClient } from '../stream-response';

// Every other buildStreamResponse test (enrichment-stream.test.ts,
// traceroute-stream.test.ts) injects a bare-EventEmitter StreamAgentClient
// fake — real and valuable for the route's own forwarding logic, but it
// never proves the route works against the *real* AgentClient: a real
// net.Socket, its newline-delimited-JSON buffering, and its connect/status
// lifecycle. This file plugs that one gap — issue #116 / JAM-54's
// "companion test driving /api/stream's actual route handler against an
// AgentClient pointed at the fake server" requirement — by running a real
// AgentClient against a plain net.createServer() fake agent double and
// reading the actual SSE bytes buildStreamResponse produces.

class NoopEnrichmentClient extends EventEmitter implements StreamEnrichmentClient {
  getMode(): 'off' | 'on-demand' | 'background' {
    return 'off';
  }
  notifyObservedConnections(): void {
    // not exercised by this test
  }
}

class NoopGeoIpClient extends EventEmitter implements StreamGeoIpClient {
  getMode(): 'off' | 'on' {
    return 'off';
  }
  lookup(): void {
    // not exercised by this test
  }
}

async function readUntil(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  predicate: (text: string) => boolean,
  maxReads = 10
): Promise<string> {
  for (let i = 0; i < maxReads; i++) {
    const { value, done } = await reader.read();
    if (done) break;
    const text = new TextDecoder().decode(value);
    if (predicate(text)) return text;
  }
  throw new Error(`expected SSE chunk not seen within ${maxReads} reads`);
}

describe('/api/stream driven by a real AgentClient against a fake TCP agent', () => {
  let server: net.Server;
  let agent: AgentClient;

  afterEach(() => {
    agent?.stop();
    server?.close();
  });

  it('forwards an event that arrived over a real socket as a matching SSE data: line', async () => {
    server = net.createServer((socket) => {
      socket.write('{"type":"capture_stats","packetsReceived":1,"packetsDropped":0}\n');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as net.AddressInfo).port;

    agent = new AgentClient('127.0.0.1', port);
    // Listeners are attached inside buildStreamResponse's ReadableStream
    // `start()`, which the Streams spec runs synchronously during
    // construction — calling it before agent.start() guarantees those
    // listeners are already in place before the real connect/data events
    // this test depends on can possibly fire, avoiding a race with the
    // fake agent's own connection handler.
    const response = buildStreamResponse({
      agent,
      enrichment: new NoopEnrichmentClient(),
      geoip: new NoopGeoIpClient(),
    });
    agent.start();
    const reader = response.body!.getReader();

    const first = await reader.read();
    expect(new TextDecoder().decode(first.value)).toContain('connection_status');

    // The connection_status replay above and this connection's eventual
    // {connected: true} status update race the capture_stats event for
    // which SSE chunk arrives next — read forward until the expected one
    // shows up rather than assuming a fixed position.
    const text = await readUntil(reader, (t) => t.includes('capture_stats'));
    expect(text).toContain('data: ');
    expect(JSON.parse(text.replace('data: ', '').trim())).toEqual({
      type: 'capture_stats',
      packetsReceived: 1,
      packetsDropped: 0,
    });
  });
});
