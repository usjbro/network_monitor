import { describe, expect, it } from 'vitest';
import { EventEmitter } from 'node:events';

// This test exercises the *route's* SSE-forwarding behavior in isolation by
// constructing a minimal fake EnrichmentClient (an EventEmitter with the
// same 'result'/'status' surface) rather than importing the real Next.js
// route module directly — Next.js route handlers close over module-level
// globals (`global.__agentClient`/`global.__enrichmentClient`) that are hard
// to reset between tests. `app/api/stream/route.ts`'s `GET()` follows the
// same no-injection pattern as the pre-existing `AgentClient` wiring it sits
// alongside (see `app/api/control/route.ts`), so it isn't directly
// unit-testable without changing that established pattern; this
// reimplementation is the fallback the task brief calls for in that case.
// Either way, the assertion below — a `connection_enrichment` event reaching
// an SSE `data:` line unchanged — is the one that must hold against the real
// route, and Step 6's manual curl check exercises that directly.

class FakeEnrichmentClient extends EventEmitter {}

function buildStreamHandler(client: FakeEnrichmentClient) {
  return () => {
    const encoder = new TextEncoder();
    let onResult: ((e: unknown) => void) | null = null;
    const stream = new ReadableStream({
      start(controller) {
        onResult = (event) => controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
        client.on('result', onResult);
      },
      cancel() {
        if (onResult) client.off('result', onResult);
      },
    });
    return new Response(stream);
  };
}

describe('connection_enrichment reaches the SSE stream unchanged', () => {
  it('forwards an EnrichmentClient "result" event as a data: line', async () => {
    const client = new FakeEnrichmentClient();
    const GET = buildStreamHandler(client);
    const response = GET();
    const reader = response.body!.getReader();

    const event = {
      type: 'connection_enrichment',
      connectionId: 'conn-1',
      remoteAddr: '93.184.216.34',
      enrichment: { org: 'EXAMPLE-ORG', source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' },
    };
    client.emit('result', event);

    const { value } = await reader.read();
    const text = new TextDecoder().decode(value);
    expect(text).toContain('data: ');
    expect(JSON.parse(text.replace('data: ', '').trim())).toEqual(event);
  });
});
