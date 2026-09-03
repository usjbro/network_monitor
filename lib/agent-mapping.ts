import { NetworkConnection, OSILayerInfo, OSILayerNumber, PacketFrame, TracerouteHop } from './types';
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

export function mapTracerouteHopEvent(json: unknown): TracerouteHop {
  const w = json as Record<string, unknown>;
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
