// lib/traceroute-state.ts
//
// Pure state-merge helpers for app/page.tsx's SSE handling of
// traceroute_hop/geo_hop_update events, extracted out so this logic gets
// real unit-test coverage rather than being manual-verification-only (the
// posture the rest of app/page.tsx's SSE wiring takes, since it has no
// route-level test precedent in this repo).
import { TracerouteHop } from './types';

// Hop ceiling mirrors capture-agent/src/traceroute.rs's HOP_CEILING (30) —
// see docs/wire-protocol.md's `traceroute_hop` field notes: "hopNumber
// never exceeds the hop ceiling (30)". Kept in sync manually since there's
// no compiler check across the wire boundary (same caveat wire-protocol.md
// states generally).
export const TRACEROUTE_HOP_CEILING = 30;

/** Appends a newly-arrived hop to the given connection's hop list. */
export function mergeTracerouteHop(
  traceroute: Record<string, TracerouteHop[]>,
  connectionId: string,
  hop: TracerouteHop
): Record<string, TracerouteHop[]> {
  const existing = traceroute[connectionId] ?? [];
  return { ...traceroute, [connectionId]: [...existing, hop] };
}

/**
 * Attaches a resolved geoIP location to the hop matching `hopNumber` for
 * the given connection. A no-op (returns the same reference) if that
 * connection has no tracked hops at all — e.g. a stale geo_hop_update
 * arriving after `reset` cleared traceroute state.
 */
export function mergeGeoHopUpdate(
  traceroute: Record<string, TracerouteHop[]>,
  connectionId: string,
  hopNumber: number,
  location: TracerouteHop['location']
): Record<string, TracerouteHop[]> {
  const hops = traceroute[connectionId];
  if (!hops) return traceroute;
  return {
    ...traceroute,
    [connectionId]: hops.map((h) => (h.hopNumber === hopNumber ? { ...h, location } : h)),
  };
}

/**
 * A trace is done, from the browser's point of view, once either the
 * destination itself replied or the hop ceiling was reached — the agent
 * never emits a hop past the ceiling (see docs/wire-protocol.md), and there
 * is no separate "trace complete" wire event, so this is the only signal
 * available client-side for clearing `traceInFlight`.
 */
export function isTraceComplete(
  hop: TracerouteHop,
  remoteAddr: string,
  hopCeiling: number = TRACEROUTE_HOP_CEILING
): boolean {
  return hop.hopIp === remoteAddr || hop.hopNumber >= hopCeiling;
}
