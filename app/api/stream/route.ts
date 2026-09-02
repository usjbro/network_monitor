import { AgentClient } from '@/lib/agent-client';

declare global {
  var __agentClient: AgentClient | undefined;
}

function getAgentClient(): AgentClient {
  if (!global.__agentClient) {
    global.__agentClient = new AgentClient('127.0.0.1', 9990);
    global.__agentClient.start();
  }
  return global.__agentClient;
}

// Gates `decrypted_payload` events (Tier B — opt-in decrypted TLS content)
// separately from every other event type on this same stream: those events
// are refused outright unless the request is either (a) direct loopback
// dev usage with no reverse proxy in front at all (no `x-mtls-verified`
// header present — the capture agent's own `127.0.0.1:9990` bind and this
// route's Next.js `-H 127.0.0.1` bind are the only gate in that case), or
// (b) proxied through deploy/Caddyfile's mTLS reverse proxy AND carrying a
// verified client certificate. A present-but-false header (proxied, but the
// client cert didn't verify) is refused — Caddy's `client_auth
// require_and_verify` would already reject the connection before it got
// this far in practice, but this is a defense-in-depth check on the
// application side, not the only one. See docs/wire-protocol.md's
// `decrypted_payload` section.
export function isDecryptedPayloadAllowed(request: Request): boolean {
  const header = request.headers.get('x-mtls-verified');
  if (header === null) return true; // no Caddy in front — direct loopback access
  return header === 'true';
}

export async function GET(request: Request) {
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
        if ((event as { type?: string }).type === 'decrypted_payload' && !isDecryptedPayloadAllowed(request)) {
          return; // refused per transport gating — spec Components §5
        }
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
