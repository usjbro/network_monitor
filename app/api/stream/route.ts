import { AgentClient } from '@/lib/agent-client';

declare global {
  // eslint-disable-next-line no-var
  var __agentClient: AgentClient | undefined;
}

function getAgentClient(): AgentClient {
  if (!global.__agentClient) {
    global.__agentClient = new AgentClient('127.0.0.1', 9990);
    global.__agentClient.start();
  }
  return global.__agentClient;
}

export async function GET() {
  const client = getAgentClient();
  const encoder = new TextEncoder();

  // Hoisted so `cancel()` can remove the exact same listener references
  // `start()` registered. Without this, every browser connect/disconnect
  // (including the reconnects this app's "agent not connected" banner
  // relies on) leaks a pair of listeners on the shared AgentClient
  // singleton — it's shared across every browser talking to this server,
  // not per-request, so this isn't a theoretical leak.
  let onEvent: ((event: unknown) => void) | null = null;
  let onStatus: ((status: { connected: boolean }) => void) | null = null;

  const stream = new ReadableStream({
    start(controller) {
      onEvent = (event: unknown) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
      };
      onStatus = (status: { connected: boolean }) => {
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify({ type: 'connection_status', ...status })}\n\n`)
        );
      };
      client.on('event', onEvent);
      client.on('status', onStatus);

      // Replay current connection status immediately so a fresh client
      // doesn't wait for the next status change to know the agent's state.
      onStatus({ connected: client['socket'] !== null });
    },
    cancel() {
      if (onEvent) client.off('event', onEvent);
      if (onStatus) client.off('status', onStatus);
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
