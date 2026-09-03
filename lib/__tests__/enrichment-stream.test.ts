import { describe, expect, it } from 'vitest';
import { EventEmitter } from 'node:events';
import { buildStreamResponse, StreamAgentClient, StreamEnrichmentClient } from '@/lib/stream-response';

// Exercises the *real* app/api/stream/route.ts stream-construction logic
// directly, rather than a reimplementation of its SSE-forwarding behavior.
// GET() itself is a thin wrapper (`return buildStreamResponse();`, no
// parameters) so it satisfies Next.js's generated route-handler type — the
// deps-injection point lives on buildStreamResponse() instead, letting this
// test inject fakes in place of the real global.__agentClient/
// global.__enrichmentClient singletons (which open a live TCP socket / touch
// disk respectively, and are awkward to reset between tests). A real
// regression in the route (forgetting `enrichmentClient.on('result', ...)`,
// a wrong field name, a wrong event name in the emitted SSE line) will now
// fail this test, not just a one-time manual curl check.

class FakeAgentClient extends EventEmitter implements StreamAgentClient {
  isConnected(): boolean {
    return true;
  }
}

class FakeEnrichmentClient extends EventEmitter implements StreamEnrichmentClient {
  getMode(): 'off' | 'on-demand' | 'background' {
    return 'off';
  }
  notifyObservedConnections(): void {
    // not exercised by this test
  }
}

describe('GET /api/stream forwards connection_enrichment from the real route', () => {
  it('relays an EnrichmentClient "result" event as an SSE data: line, matching the documented shape', async () => {
    const agent = new FakeAgentClient();
    const enrichment = new FakeEnrichmentClient();

    const response = buildStreamResponse({ agent, enrichment });
    const reader = response.body!.getReader();

    // Read the initial connection_status replay (emitted synchronously in
    // GET()'s start()) before the enrichment result, so this assertion
    // isn't order-dependent on stream internals.
    const first = await reader.read();
    expect(new TextDecoder().decode(first.value)).toContain('connection_status');

    const event = {
      type: 'connection_enrichment',
      connectionId: 'Tcp-192.168.1.10:51000-93.184.216.34:443',
      remoteAddr: '93.184.216.34',
      enrichment: {
        org: 'EXAMPLE-ORG',
        asn: 'AS15133',
        asnOrg: 'EDGECAST',
        country: 'US',
        source: 'rdap',
        fetchedAt: '2026-08-28T00:00:00.000Z',
      },
    };
    enrichment.emit('result', event);

    const { value } = await reader.read();
    const text = new TextDecoder().decode(value);
    expect(text).toContain('data: ');
    expect(JSON.parse(text.replace('data: ', '').trim())).toEqual(event);
  });

  it('stops forwarding after cancel() unregisters the listener', async () => {
    const agent = new FakeAgentClient();
    const enrichment = new FakeEnrichmentClient();

    const response = buildStreamResponse({ agent, enrichment });
    expect(enrichment.listenerCount('result')).toBe(1);

    await response.body!.cancel();
    expect(enrichment.listenerCount('result')).toBe(0);
  });
});
