import { AgentClient } from '@/lib/agent-client';
import { EnrichmentClient } from '@/lib/enrichment';
import { join } from 'node:path';

declare global {
  var __agentClient: AgentClient | undefined;
  var __enrichmentClient: EnrichmentClient | undefined;
}

function getAgentClient(): AgentClient {
  if (!global.__agentClient) {
    global.__agentClient = new AgentClient('127.0.0.1', 9990);
    global.__agentClient.start();
  }
  return global.__agentClient;
}

// Exported (rather than kept module-private like getAgentClient above) so
// app/api/enrichment/control/route.ts and app/api/enrichment/lookup/route.ts
// share the exact same singleton instead of each re-deriving it from the
// bare global — mirrors how global.__agentClient is already shared across
// stream/control today, just made explicit.
export function getEnrichmentClient(): EnrichmentClient {
  if (!global.__enrichmentClient) {
    global.__enrichmentClient = new EnrichmentClient({ dataDir: join(process.cwd(), '.data', 'enrichment') });
  }
  return global.__enrichmentClient;
}

export async function GET() {
  const client = getAgentClient();
  const enrichmentClient = getEnrichmentClient();
  const encoder = new TextEncoder();

  // Hoisted so `cancel()` can remove the exact same listener references
  // `start()` registered. Without this, every browser connect/disconnect
  // (including the reconnects this app's "agent not connected" banner
  // relies on) leaks a pair of listeners on the shared AgentClient
  // singleton — it's shared across every browser talking to this server,
  // not per-request, so this isn't a theoretical leak.
  let onEvent: ((event: unknown) => void) | null = null;
  let onStatus: ((status: { connected: boolean }) => void) | null = null;
  let onResult: ((event: unknown) => void) | null = null;

  const stream = new ReadableStream({
    start(controller) {
      onEvent = (event: unknown) => {
        // controller.enqueue() throws if the stream has already closed/errored
        // (e.g. the browser tab navigated away between the emit and this
        // callback running). These callbacks run synchronously inside
        // AgentClient's EventEmitter.emit(), so an uncaught throw here would
        // both surface as an unhandled exception from an I/O callback AND stop
        // emit() from notifying any other listener (other browser tabs) for
        // this same event. There's nothing meaningful to do but ignore it.
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
        } catch {
          // stream already closed/closing — ignore
        }

        // When background enrichment is on, feed every observed connection
        // into it so it gets queued for lookup without the browser having to
        // ask per-connection. EnrichmentClient.notifyObservedConnections
        // already no-ops outside background mode and already filters
        // private/reserved IPs internally, so this call site doesn't need
        // its own guard beyond the mode check.
        if (event && (event as { type?: string }).type === 'connection_update') {
          const conn = (event as { connection?: { id?: string; remoteAddr?: string } }).connection;
          if (conn?.id && conn?.remoteAddr && enrichmentClient.getMode() === 'background') {
            enrichmentClient.notifyObservedConnections([{ id: conn.id, remoteAddr: conn.remoteAddr }]);
          }
        }
      };
      onStatus = (status: { connected: boolean }) => {
        try {
          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify({ type: 'connection_status', ...status })}\n\n`)
          );
        } catch {
          // stream already closed/closing — ignore
        }
      };
      onResult = (event: unknown) => {
        // Same closed-stream tolerance as onEvent/onStatus above.
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
        } catch {
          // stream already closed/closing — ignore
        }
      };
      client.on('event', onEvent);
      client.on('status', onStatus);
      enrichmentClient.on('result', onResult);

      // Replay current connection status immediately so a fresh client
      // doesn't wait for the next status change to know the agent's state.
      onStatus({ connected: client['socket'] !== null });
    },
    cancel() {
      if (onEvent) client.off('event', onEvent);
      if (onStatus) client.off('status', onStatus);
      if (onResult) enrichmentClient.off('result', onResult);
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    },
  });
}
