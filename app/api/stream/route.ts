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

  const stream = new ReadableStream({
    start(controller) {
      const onEvent = (event: unknown) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
      };
      const onStatus = (status: { connected: boolean }) => {
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
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    },
  });
}
