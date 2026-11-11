// KAN-129 Task 2 (spec D5): tcp_samples replies belong to the tab that asked
// and never reach the SSE feed, and /api/tcp-samples sits behind the same
// Host allowlist (DNS-rebinding guard) as every other route.
import { describe, expect, it } from 'vitest';
import { EventEmitter } from 'node:events';
import { NextRequest } from 'next/server';
import { buildStreamResponse, type StreamAgentClient, type StreamEnrichmentClient, type StreamGeoIpClient } from '@/lib/stream-response';
import { middleware } from '@/middleware';

class FakeAgent extends EventEmitter implements StreamAgentClient {
  isConnected() {
    return true;
  }
}

describe('the SSE stream drops registered reply types defensively', () => {
  it('a tcp_samples event injected straight into the stream is never enqueued; ordinary events are', async () => {
    const agent = new FakeAgent();
    const enrichment = Object.assign(new EventEmitter(), { getMode: () => 'off', notifyObservedConnections() {} });
    const geoip = Object.assign(new EventEmitter(), { getMode: () => 'off', lookup() {} });
    const response = buildStreamResponse({
      agent,
      enrichment: enrichment as unknown as StreamEnrichmentClient,
      geoip: geoip as unknown as StreamGeoIpClient,
    });
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    await reader.read(); // connection_status

    agent.emit('event', { type: 'tcp_samples', requestId: 'a'.repeat(32), connectionId: 'c', found: false });
    agent.emit('event', { type: 'agent_status', capturing: true });
    const next = decoder.decode((await reader.read()).value);
    expect(next).toContain('agent_status');
    expect(next).not.toContain('tcp_samples');
    await reader.cancel();
  });
});

describe('the Host allowlist covers /api/tcp-samples', () => {
  it('refuses a foreign Host before the route runs', () => {
    const response = middleware(
      new NextRequest('http://attacker.example:3000/api/tcp-samples', {
        method: 'POST',
        headers: { host: 'attacker.example:3000' },
      }),
    );
    expect(response.status).toBe(421);
  });

  it('lets a loopback Host through', () => {
    const response = middleware(
      new NextRequest('http://127.0.0.1:3000/api/tcp-samples', { method: 'POST', headers: { host: '127.0.0.1:3000' } }),
    );
    expect(response.status).toBe(200);
  });
});
