import { CaptureConfig, CaptureStats, NetworkConnection, OSILayerInfo, OSILayerNumber, PacketFrame, SystemStats, TracerouteHop } from './types';
import { STATIC_LAYER_INFO } from './osi-engine';

function requireField<T>(obj: Record<string, unknown>, key: string): T {
  if (!(key in obj) || obj[key] === undefined) {
    throw new Error(`agent event missing required field "${key}"`);
  }
  return obj[key] as T;
}

export function mapConnectionEvent(json: unknown): NetworkConnection {
  const w = json as Record<string, unknown>;
  return {
    id: requireField(w, 'id'),
    protocol: requireField(w, 'protocol'),
    appLayerProtocol: requireField(w, 'appLayerProtocol'),
    transportProtocol: requireField(w, 'transportProtocol'),
    osiStack: requireField(w, 'osiStack'),
    localAddr: requireField(w, 'localAddr'),
    localPort: requireField(w, 'localPort'),
    remoteAddr: requireField(w, 'remoteAddr'),
    remotePort: requireField(w, 'remotePort'),
    processName: requireField(w, 'processName'),
    pid: requireField(w, 'pid'),
    rxSpeed: requireField(w, 'rxSpeed'),
    txSpeed: requireField(w, 'txSpeed'),
    rxBytesTotal: requireField(w, 'rxBytesTotal'),
    txBytesTotal: requireField(w, 'txBytesTotal'),
    latencyMs: requireField(w, 'latencyMs'),
    packetLoss: requireField(w, 'packetLoss'),
    status: requireField(w, 'status'),
    encryption: requireField(w, 'encryption'),
    sparkline: requireField(w, 'sparkline'),
    ja3Fingerprint: w.ja3Fingerprint as string | undefined,
    ja3Label: w.ja3Label as string | undefined,
  };
}

// Accepts the full `traceroute_hop` event envelope, not just its payload —
// mirrors mapDecryptedPayloadEvent's shape (lib/decrypted-mapping.ts) for
// the structurally identical DecryptedPayload wire variant. Owning the
// envelope's `hop` unwrap here, in the one place both of this event's
// consumers (app/page.tsx and lib/stream-response.ts) call through, means a
// caller can no longer independently get the wire shape wrong the way the
// two of them each once did (see issue #46).
export function mapTracerouteHopEvent(json: unknown): TracerouteHop {
  const envelope = json as { hop?: Record<string, unknown> };
  const w = envelope.hop;
  if (!w) {
    throw new Error('malformed traceroute_hop event: missing "hop" field');
  }
  return {
    targetIp: requireField(w, 'targetIp'),
    hopNumber: requireField(w, 'hopNumber'),
    hopIp: w.hopIp as string | undefined,
    rttMs: w.rttMs as number | undefined,
    location: undefined,
  };
}

export function mapConnectionClosedEvent(json: unknown): string {
  const w = json as Record<string, unknown>;
  return requireField(w, 'id');
}

// Accepts the full `capture_stats` event envelope, not just its `stats`
// payload — mirrors mapTracerouteHopEvent's shape above, for the same
// reason (see issue #61 and docs/wire-protocol.md).
export function mapCaptureStatsEvent(json: unknown): CaptureStats {
  const envelope = json as { stats?: Record<string, unknown> };
  const w = envelope.stats;
  if (!w) {
    throw new Error('malformed capture_stats event: missing "stats" field');
  }
  return {
    received: requireField(w, 'received'),
    dropped: requireField(w, 'dropped'),
    ifDropped: requireField(w, 'ifDropped'),
    relayLaggedEvents: requireField(w, 'relayLaggedEvents'),
    unparseableFrames: requireField(w, 'unparseableFrames'),
  };
}

// Same nested-envelope shape as mapCaptureStatsEvent/mapTracerouteHopEvent
// above — see issue #64 and docs/wire-protocol.md.
export function mapSystemStatsEvent(json: unknown): SystemStats {
  const envelope = json as { stats?: Record<string, unknown> };
  const w = envelope.stats;
  if (!w) {
    throw new Error('malformed system_stats event: missing "stats" field');
  }
  return {
    hostname: requireField(w, 'hostname'),
    interfaceName: requireField(w, 'interfaceName'),
    ipAddress: requireField(w, 'ipAddress'),
    rxTotalMbps: requireField(w, 'rxTotalMbps'),
    txTotalMbps: requireField(w, 'txTotalMbps'),
    rxPpsTotal: requireField(w, 'rxPpsTotal'),
    txPpsTotal: requireField(w, 'txPpsTotal'),
    totalPacketsCaptured: requireField(w, 'totalPacketsCaptured'),
  };
}

// Same nested-envelope shape as mapCaptureStatsEvent/mapSystemStatsEvent
// above — see issue #68 and docs/wire-protocol.md. `filter` is `null`
// (present, not omitted) when no filter is active, so requireField's
// undefined-only check correctly lets it through as a real value.
export function mapCaptureConfigEvent(json: unknown): CaptureConfig {
  const envelope = json as { config?: Record<string, unknown> };
  const w = envelope.config;
  if (!w) {
    throw new Error('malformed capture_config event: missing "config" field');
  }
  return {
    filter: requireField(w, 'filter'),
    snaplen: requireField(w, 'snaplen'),
  };
}

// capture_config_error is flat (no nested envelope) — a one-off signal,
// not a per-tick snapshot, so it carries just the message.
export function mapCaptureConfigErrorEvent(json: unknown): string {
  const w = json as Record<string, unknown>;
  return requireField(w, 'message');
}

export function mapPacketEvent(json: unknown): PacketFrame {
  const w = json as Record<string, unknown>;
  return {
    id: requireField(w, 'id'),
    timestamp: requireField(w, 'timestamp'),
    relativeTimeMs: requireField(w, 'relativeTimeMs'),
    layer: requireField<OSILayerNumber>(w, 'layer'),
    protocol: requireField(w, 'protocol'),
    src: requireField(w, 'src'),
    dst: requireField(w, 'dst'),
    length: requireField(w, 'length'),
    summary: requireField(w, 'summary'),
    hexDump: requireField(w, 'hexDump'),
    headerBreakdown: requireField<PacketFrame['headerBreakdown']>(w, 'headerBreakdown'),
  };
}

function healthStatusFor(errorRate: number): 'OPTIMAL' | 'WARNING' | 'CRITICAL' {
  if (errorRate < 1) return 'OPTIMAL';
  if (errorRate < 5) return 'WARNING';
  return 'CRITICAL';
}

export function mergeLayerStats(
  liveLayers: Record<OSILayerNumber, Partial<OSILayerInfo>>
): OSILayerInfo[] {
  // Object.keys() always enumerates integer-like keys in ascending numeric
  // order (1..7) regardless of declaration order, which is the reverse of
  // the display order the layer stack expects (7..1, Application-to-Physical)
  // and relies on via its own `.reverse()` calls. Sort explicitly rather than
  // depending on key-enumeration order to produce it incidentally.
  return (Object.keys(STATIC_LAYER_INFO) as unknown as OSILayerNumber[])
    .map((layer) => {
      const staticInfo = STATIC_LAYER_INFO[layer];
      const live = liveLayers[layer] ?? {};
      const rxSpeed = live.rxSpeed ?? 0;
      const txSpeed = live.txSpeed ?? 0;
      const errorRate = live.errorRate ?? 0;
      return {
        ...staticInfo,
        rxSpeed,
        txSpeed,
        rxPacketsPerSec: live.rxPacketsPerSec ?? 0,
        txPacketsPerSec: live.txPacketsPerSec ?? 0,
        totalBytes: live.totalBytes ?? 0,
        errorRate,
        activeSockets: live.activeSockets ?? 0,
        sparkline: live.sparkline ?? [],
        details: {
          primaryMetric: 'Throughput',
          primaryValue: `${Math.round(rxSpeed + txSpeed)} B/s`,
          secondaryMetric: 'Active Sockets',
          secondaryValue: String(live.activeSockets ?? 0),
          tertiaryMetric: 'Error Rate',
          tertiaryValue: `${errorRate.toFixed(2)}%`,
          healthStatus: healthStatusFor(errorRate),
          keyMetrics: {},
        },
      };
    })
    .sort((a, b) => b.layer - a.layer);
}
