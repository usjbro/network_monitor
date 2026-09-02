import { AgentClient } from '@/lib/agent-client';
import { EnrichmentClient, EnrichmentMode } from '@/lib/enrichment';
import { GeoIpClient } from '@/lib/geoip';
import { buildGeoHopEvent } from '@/lib/geoip-mapping';
import { join } from 'node:path';

declare global {
  var __agentClient: AgentClient | undefined;
  var __enrichmentClient: EnrichmentClient | undefined;
  var __geoIpClient: GeoIpClient | undefined;
}

// Minimal structural interfaces for what GET() actually calls on each
// client — narrower than the concrete AgentClient/EnrichmentClient/GeoIpClient
// classes so tests can inject a small fake (a bare EventEmitter plus these
// methods) without needing to construct/mock a real singleton (a real
// AgentClient opens a TCP socket in its constructor's start() path; a real
// EnrichmentClient/GeoIpClient touches disk). All three concrete classes
// satisfy these structurally, so production callers pass no deps and get the
// real thing via getAgentClient()/getEnrichmentClient()/getGeoIpClient() below.
export interface StreamAgentClient {
  on(event: 'event', listener: (event: unknown) => void): unknown;
  on(event: 'status', listener: (status: { connected: boolean }) => void): unknown;
  off(event: 'event', listener: (event: unknown) => void): unknown;
  off(event: 'status', listener: (status: { connected: boolean }) => void): unknown;
  isConnected(): boolean;
}

export interface StreamEnrichmentClient {
  on(event: 'result', listener: (event: unknown) => void): unknown;
  off(event: 'result', listener: (event: unknown) => void): unknown;
  getMode(): EnrichmentMode;
  notifyObservedConnections(conns: Array<{ id: string; remoteAddr: string }>): void;
}

export interface StreamGeoIpClient {
  on(event: 'result', listener: (result: { ip: string; location: unknown }) => void): unknown;
  off(event: 'result', listener: (result: { ip: string; location: unknown }) => void): unknown;
  getMode(): 'off' | 'on';
  lookup(ip: string): Promise<void> | void;
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

// Same rationale as getEnrichmentClient above — shared with
// app/api/geoip/control/route.ts.
export function getGeoIpClient(): GeoIpClient {
  if (!global.__geoIpClient) {
    global.__geoIpClient = new GeoIpClient();
  }
  return global.__geoIpClient;
}

// The actual SSE-stream construction, factored out of GET() so tests can
// call it directly with injected fakes. It's kept out of GET()'s own
// signature (rather than GET() taking a second `deps` parameter) because
// Next.js's generated route-handler type validator (`.next/types/validator.ts`,
// checked by `next build`'s typecheck step) requires GET's second parameter
// to match its own `{ params: Promise<...> }` route-context shape — a `deps`
// parameter there fails that check. This function has no such constraint.
export function buildStreamResponse(
  deps: { agent?: StreamAgentClient; enrichment?: StreamEnrichmentClient; geoip?: StreamGeoIpClient } = {}
): Response {
  const client = deps.agent ?? getAgentClient();
  const enrichmentClient = deps.enrichment ?? getEnrichmentClient();
  const geoIpClient = deps.geoip ?? getGeoIpClient();
  const encoder = new TextEncoder();

  // Hoisted so `cancel()` can remove the exact same listener references
  // `start()` registered. Without this, every browser connect/disconnect
  // (including the reconnects this app's "agent not connected" banner
  // relies on) leaks listeners on the shared AgentClient/EnrichmentClient/
  // GeoIpClient singletons — they're shared across every browser talking to
  // this server, not per-request, so this isn't a theoretical leak.
  let onEvent: ((event: unknown) => void) | null = null;
  let onStatus: ((status: { connected: boolean }) => void) | null = null;
  let onResult: ((event: unknown) => void) | null = null;
  let onTracerouteHop: ((event: unknown) => void) | null = null;
  let onGeoResult: ((result: { ip: string; location: unknown }) => void) | null = null;

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

      // Tracks the (targetIp, hopNumber) that produced each hopIp we've seen
      // on this stream, so that when GeoIpClient's bare `'result'` event
      // comes back (keyed only by ip) we can reattach the trace-correlation
      // fields `geo_hop_update` needs. Scoped to this one SSE connection —
      // not persisted, not shared across browser tabs — since it only needs
      // to outlive the traceroute that populated it.
      const hopContextByIp = new Map<string, { targetIp: string; hopNumber: number }>();

      // NOTE: `onEvent` above already forwards every agent event verbatim,
      // traceroute_hop included, so this listener does NOT re-enqueue it —
      // doing so would double-send the same hop to the browser. This
      // listener's only job is the geoIP side effect: remembering which
      // (targetIp, hopNumber) produced a given hopIp, and kicking off a
      // lookup for it when geoIP is enabled.
      onTracerouteHop = (event: unknown) => {
        const hop = event as { type?: string; targetIp?: string; hopNumber?: number; hopIp?: string };
        if (hop.type !== 'traceroute_hop') return;
        if (hop.hopIp && hop.targetIp !== undefined && hop.hopNumber !== undefined) {
          hopContextByIp.set(hop.hopIp, { targetIp: hop.targetIp, hopNumber: hop.hopNumber });
          if (geoIpClient.getMode() === 'on') {
            geoIpClient.lookup(hop.hopIp);
          }
        }
      };
      onGeoResult = (result: { ip: string; location: unknown }) => {
        const context = hopContextByIp.get(result.ip);
        if (!context) return; // a result for a hop this stream never reported — nothing to correlate it to
        const event = buildGeoHopEvent(result.ip, context.hopNumber, context.targetIp, result.location as any);
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
        } catch {
          // stream already closed/closing — ignore
        }
      };

      client.on('event', onEvent);
      client.on('status', onStatus);
      client.on('event', onTracerouteHop);
      enrichmentClient.on('result', onResult);
      geoIpClient.on('result', onGeoResult);

      // Replay current connection status immediately so a fresh client
      // doesn't wait for the next status change to know the agent's state.
      onStatus({ connected: client.isConnected() });
    },
    cancel() {
      if (onEvent) client.off('event', onEvent);
      if (onStatus) client.off('status', onStatus);
      if (onResult) enrichmentClient.off('result', onResult);
      if (onTracerouteHop) client.off('event', onTracerouteHop);
      if (onGeoResult) geoIpClient.off('result', onGeoResult);
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

export async function GET() {
  return buildStreamResponse();
}
