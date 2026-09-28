import { AgentStatus, CaptureConfig, CaptureFileStatus, CaptureStats, Conversation, Endpoint, Finding, NetworkConnection, NetworkInterface, OSILayerInfo, OSILayerNumber, PacketFrame, ProtocolNode, SystemStats, TracerouteHop } from './types';
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
    latencyMs: w.latencyMs as number | undefined,
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

function mapProtocolNode(w: Record<string, unknown>): ProtocolNode {
  return {
    name: requireField(w, 'name'),
    bytes: requireField(w, 'bytes'),
    packets: requireField(w, 'packets'),
    children: ((w.children as Record<string, unknown>[] | undefined) ?? []).map(mapProtocolNode),
  };
}

// JAM-13. Same envelope convention as mapTracerouteHopEvent above (fields
// nest under `hierarchy`, not flat on the event) — see docs/wire-protocol.md.
export function mapProtocolHierarchyEvent(json: unknown): ProtocolNode {
  const envelope = json as { hierarchy?: Record<string, unknown> };
  const w = envelope.hierarchy;
  if (!w) {
    throw new Error('malformed protocol_hierarchy_update event: missing "hierarchy" field');
  }
  return mapProtocolNode(w);
}

// Accepts the full `finding` event envelope, not just its `finding`
// payload — mirrors mapTracerouteHopEvent's/mapCaptureStatsEvent's shape
// above (the mapper owns the envelope unwrap, per issue #46), rather than
// mapPacketEvent's older caller-does-the-unwrap convention.
export function mapFindingEvent(json: unknown): Finding {
  const envelope = json as { finding?: Record<string, unknown> };
  const w = envelope.finding;
  if (!w) {
    throw new Error('malformed finding event: missing "finding" field');
  }
  return {
    id: requireField(w, 'id'),
    timestamp: requireField(w, 'timestamp'),
    severity: requireField(w, 'severity'),
    code: requireField(w, 'code'),
    summary: requireField(w, 'summary'),
    frameId: w.frameId as string | undefined,
    flowId: w.flowId as string | undefined,
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
    totalConnectionsObserved: requireField(w, 'totalConnectionsObserved'),
    capacityEvictions: requireField(w, 'capacityEvictions'),
    idleEvictions: requireField(w, 'idleEvictions'),
  };
}

// Same nested-envelope shape as mapCaptureStatsEvent/mapSystemStatsEvent/
// mapCaptureFileStatusEvent — under a `status` key, matching what
// `capture-agent/src/wire.rs`'s `AgentStatus { status: AgentStatusJson }`
// actually serializes.
//
// This previously read the fields off the top level, because
// docs/wire-protocol.md described the event as flat (JAM-150). Nothing
// caught it: both TS test layers fed the mapper the same flat shape the
// mapper expected, and wire.rs's own test only asserts `line.contains(..)`
// on individual field substrings, which passes either way. Against a real
// agent every tick threw `missing required field "interface"` into the SSE
// handler's catch, so agentMode stayed null and JAM-145's "replaying
// <file>" banner never rendered.
//
// `replaySource` is genuinely optional (absent in live mode); every other
// field is required for every mode.
export function mapAgentStatusEvent(json: unknown): AgentStatus {
  const envelope = json as { status?: Record<string, unknown> };
  const w = envelope.status;
  if (!w) {
    throw new Error('malformed agent_status event: missing "status" field');
  }
  return {
    interface: requireField(w, 'interface'),
    capturing: requireField(w, 'capturing'),
    mode: requireField(w, 'mode'),
    replaySource: w.replaySource as string | undefined,
    directionAttributionUnavailable: requireField(w, 'directionAttributionUnavailable'),
  };
}

// Same nested-envelope shape as mapCaptureStatsEvent/mapSystemStatsEvent
// above, under a `status` key — see epic #55 (JAM-132/GitHub #70) and
// docs/wire-protocol.md. `path`/`ringFile`/`ringTotal`/`autostopReason`
// are all genuinely optional — see the wire doc's field notes for when
// each is present vs. absent.
export function mapCaptureFileStatusEvent(json: unknown): CaptureFileStatus {
  const envelope = json as { status?: Record<string, unknown> };
  const w = envelope.status;
  if (!w) {
    throw new Error('malformed capture_file_status event: missing "status" field');
  }
  return {
    writing: requireField(w, 'writing'),
    path: w.path as string | undefined,
    bytesWritten: requireField(w, 'bytesWritten'),
    ringFile: w.ringFile as number | undefined,
    ringTotal: w.ringTotal as number | undefined,
    autostopReason: w.autostopReason as string | undefined,
    backpressureDrops: requireField(w, 'backpressureDrops'),
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

// Accepts the full `interface_list` event envelope — issue #69. Sent
// on-demand in response to a `list_interfaces` control message (the "iface
// list" command), not per-tick, so a malformed/missing `interfaces` array
// throws rather than silently returning an empty list a caller can't tell
// apart from "no capturable interfaces exist".
export function mapInterfaceListEvent(json: unknown): NetworkInterface[] {
  const w = json as { interfaces?: unknown[] };
  if (!w.interfaces) {
    throw new Error('malformed interface_list event: missing "interfaces" field');
  }
  return w.interfaces.map((entry) => {
    const e = entry as Record<string, unknown>;
    return {
      name: requireField<string>(e, 'name'),
      addresses: requireField<string[]>(e, 'addresses'),
    };
  });
}

// interface_error is flat, same shape as capture_config_error above.
export function mapInterfaceErrorEvent(json: unknown): string {
  const w = json as Record<string, unknown>;
  return requireField(w, 'message');
}

// JAM-14. Accepts the full `endpoint_update` event envelope — same
// array-under-a-key convention as mapInterfaceListEvent above. Sent as a
// full replacement list every tick (the agent's rollups only ever grow, so
// there's nothing to diff); a missing/malformed `endpoints` array throws
// rather than silently rendering an empty table. `enrichment` always comes
// back `undefined` here — it's filled in client-side, once per host, the
// same way `NetworkConnection.enrichment` is per flow.
export function mapEndpointUpdateEvent(json: unknown): Endpoint[] {
  const w = json as { endpoints?: unknown[] };
  if (!w.endpoints) {
    throw new Error('malformed endpoint_update event: missing "endpoints" field');
  }
  return w.endpoints.map((entry) => {
    const e = entry as Record<string, unknown>;
    return {
      host: requireField<string>(e, 'host'),
      rxBytesTotal: requireField<number>(e, 'rxBytesTotal'),
      txBytesTotal: requireField<number>(e, 'txBytesTotal'),
      rxPacketsTotal: requireField<number>(e, 'rxPacketsTotal'),
      txPacketsTotal: requireField<number>(e, 'txPacketsTotal'),
      rxSpeed: requireField<number>(e, 'rxSpeed'),
      txSpeed: requireField<number>(e, 'txSpeed'),
      flowCount: requireField<number>(e, 'flowCount'),
      firstSeenMs: requireField<number>(e, 'firstSeenMs'),
      lastSeenMs: requireField<number>(e, 'lastSeenMs'),
      processName: requireField<string>(e, 'processName'),
      pid: requireField<number>(e, 'pid'),
      ja3Label: e.ja3Label as string | undefined,
      enrichment: undefined,
    };
  });
}

// JAM-14. Same array-under-a-key convention as mapEndpointUpdateEvent above.
export function mapConversationUpdateEvent(json: unknown): Conversation[] {
  const w = json as { conversations?: unknown[] };
  if (!w.conversations) {
    throw new Error('malformed conversation_update event: missing "conversations" field');
  }
  return w.conversations.map((entry) => {
    const c = entry as Record<string, unknown>;
    return {
      localAddr: requireField<string>(c, 'localAddr'),
      remoteAddr: requireField<string>(c, 'remoteAddr'),
      rxBytesTotal: requireField<number>(c, 'rxBytesTotal'),
      txBytesTotal: requireField<number>(c, 'txBytesTotal'),
      rxPacketsTotal: requireField<number>(c, 'rxPacketsTotal'),
      txPacketsTotal: requireField<number>(c, 'txPacketsTotal'),
      rxSpeed: requireField<number>(c, 'rxSpeed'),
      txSpeed: requireField<number>(c, 'txSpeed'),
      flowCount: requireField<number>(c, 'flowCount'),
      firstSeenMs: requireField<number>(c, 'firstSeenMs'),
      lastSeenMs: requireField<number>(c, 'lastSeenMs'),
      durationMs: requireField<number>(c, 'durationMs'),
      processName: requireField<string>(c, 'processName'),
      pid: requireField<number>(c, 'pid'),
      ja3Label: c.ja3Label as string | undefined,
      enrichment: undefined,
    };
  });
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
    headerHexDump: requireField(w, 'headerHexDump'),
    fields: requireField<PacketFrame['fields']>(w, 'fields'),
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
