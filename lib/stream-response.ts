// lib/stream-response.ts
//
// The actual SSE-stream construction backing app/api/stream/route.ts's
// GET(), factored into its own module (rather than living directly in
// route.ts) so tests can import buildStreamResponse with injected fakes.
// It can't live in route.ts as an additional export: Next.js's generated
// route-handler type validator (`.next/types/validator.ts`, checked by
// `next build`'s typecheck step) requires every value exported from a
// `route.ts` file to be either a recognized HTTP-verb handler or one of a
// fixed set of route config keys — any other value export (this function
// included) fails that check. Keeping it in a plain lib/ module sidesteps
// that constraint entirely, since Next only applies the check to files
// matching the app/**/route.ts convention.
import { AgentClient } from './agent-client';
import { EnrichmentClient, EnrichmentMode } from './enrichment';
import { GeoIpClient } from './geoip';
import { buildGeoHopEvent } from './geoip-mapping';
import { isDecryptedPayloadAllowed } from './decrypted-payload-gate';
import { join } from 'node:path';

declare global {
  var __agentClient: AgentClient | undefined;
  var __enrichmentClient: EnrichmentClient | undefined;
  var __geoIpClient: GeoIpClient | undefined;
}

// Minimal structural interfaces for what buildStreamResponse actually calls
// on each client — narrower than the concrete AgentClient/EnrichmentClient/
// GeoIpClient classes so tests can inject a small fake (a bare EventEmitter
// plus these methods) without needing to construct/mock a real singleton (a
// real AgentClient opens a TCP socket in its constructor's start() path; a
// real EnrichmentClient/GeoIpClient touches disk). All three concrete
// classes satisfy these structurally, so production callers pass no deps
// and get the real thing via getAgentClient()/getEnrichmentClient()/
// getGeoIpClient() below.
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

// Exported so app/api/enrichment/control/route.ts and
// app/api/enrichment/lookup/route.ts share the exact same singleton
// instead of each re-deriving it from the bare global — mirrors how
// global.__agentClient is already shared across stream/control today, just
// made explicit.
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

export interface StreamRouteDeps {
  agent?: StreamAgentClient;
  enrichment?: StreamEnrichmentClient;
  geoip?: StreamGeoIpClient;
  // The incoming request, used only to gate `decrypted_payload` events
  // (Tier B — see lib/decrypted-payload-gate.ts). Optional so existing
  // tests that don't exercise decrypted_payload don't need to construct
  // one — absent request behaves like direct loopback access (permissive),
  // matching isDecryptedPayloadAllowed's own no-header default.
  request?: Request;
}

export function buildStreamResponse(deps: StreamRouteDeps = {}): Response {
  const client = deps.agent ?? getAgentClient();
  const enrichmentClient = deps.enrichment ?? getEnrichmentClient();
  const geoIpClient = deps.geoip ?? getGeoIpClient();
  const decryptedPayloadAllowed = deps.request ? isDecryptedPayloadAllowed(deps.request) : true;
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
        if ((event as { type?: string }).type === 'decrypted_payload' && !decryptedPayloadAllowed) {
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
        // Wire shape (capture-agent/src/wire.rs's `TracerouteHop { hop:
        // Box<TracerouteHopJson> }`): hop fields nest under `hop`, not flat
        // on the event.
        const envelope = event as { type?: string; hop?: { targetIp?: string; hopNumber?: number; hopIp?: string } };
        if (envelope.type !== 'traceroute_hop') return;
        const hop = envelope.hop;
        if (hop?.hopIp && hop.targetIp !== undefined && hop.hopNumber !== undefined) {
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
