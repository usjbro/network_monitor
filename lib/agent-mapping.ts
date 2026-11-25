import { AgentStatus, CaptureConfig, CaptureFileStatus, CaptureStats, Conversation, DecryptionDirection, DecryptionStatus, Endpoint, Finding, FOLLOW_LIMITS, FollowDirectionPage, FollowGap, FollowMask, FollowResponse, FollowTurn, IoAggregateBucket, IoAggregateFn, IoBucket, IoBuckets, IoPlainBucket, IoNotObserved, IoNotObservedReason, IoSeriesStatus, NetworkConnection, NetworkInterface, OSILayerInfo, OSILayerNumber, PacketFrame, ProtocolNode, RollupBounds, RollupTraffic, RollupUpdate, ServiceTimeSummary, SystemStats, TCP_LABEL_TEXT_MAX, TCP_SAMPLE_MARK, TcpSample, TcpSampleLabel, TcpSamplesPage, TcpSamplesRelativeTo, TracerouteHop } from './types';
import { STATIC_LAYER_INFO } from './osi-engine';

function requireField<T>(obj: Record<string, unknown>, key: string): T {
  if (!(key in obj) || obj[key] === undefined) {
    throw new Error(`agent event missing required field "${key}"`);
  }
  return obj[key] as T;
}

export function mapDecryptionStatusEvent(json: unknown): DecryptionStatus {
  const envelope = json as { status?: Record<string, unknown> };
  const status = envelope.status;
  if (!status) throw new Error('malformed decryption_status event: missing "status" field');
  return {
    connectionId: requireField(status, 'connectionId'),
    direction: requireField<DecryptionDirection>(status, 'direction'),
    status: requireField<'unavailable' | 'desynchronized'>(status, 'status'),
    reason: requireField(status, 'reason'),
  };
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

// JAM-15. Accepts the full `service_time_update` envelope, like the other
// tick-event mappers.
export function mapServiceTimeUpdateEvent(json: unknown): ServiceTimeSummary[] {
  const w = json as { summaries?: unknown[] };
  if (!w.summaries) {
    throw new Error('malformed service_time_update event: missing "summaries" field');
  }
  return w.summaries.map((entry) => {
    const e = entry as Record<string, unknown>;
    return {
      protocol: requireField<string>(e, 'protocol'),
      answered: requireField<number>(e, 'answered'),
      unanswered: requireField<number>(e, 'unanswered'),
      untracked: requireField<number>(e, 'untracked'),
      minUs: e.minUs as number | undefined,
      maxUs: e.maxUs as number | undefined,
      sampleCount: requireField<number>(e, 'sampleCount'),
      medianUs: e.medianUs as number | undefined,
      p95Us: e.p95Us as number | undefined,
    };
  });
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
    // Decode failures only; the agent excludes successfully framed non-IP traffic.
    unparseableFrames: requireField(w, 'unparseableFrames'),
    totalConnectionsObserved: requireField(w, 'totalConnectionsObserved'),
    capacityEvictions: requireField(w, 'capacityEvictions'),
    idleEvictions: requireField(w, 'idleEvictions'),
    // Optional, unlike its siblings: an older agent omits it, and a cosmetic
    // counter must not make the mapper throw and hide all capture health.
    // Absent stays undefined (unknown); it is never defaulted to 0, which
    // would claim "no evictions".
    observedNameEvictions: typeof w.observedNameEvictions === 'number' ? w.observedNameEvictions : undefined,
    // JAM-18: omitted by the agent when false.
    replayWaiting: w.replayWaiting === true ? true : undefined,
    // KAN-129: absent from an older agent, and then unknown, not zero.
    tcpSampleRings: typeof w.tcpSampleRings === 'number' ? w.tcpSampleRings : undefined,
    tcpSampleRingBytes: typeof w.tcpSampleRingBytes === 'number' ? w.tcpSampleRingBytes : undefined,
    tcpSampleRingsRecycled: typeof w.tcpSampleRingsRecycled === 'number' ? w.tcpSampleRingsRecycled : undefined,
  };
}

// KAN-110 `stream_data` (docs/wire-protocol.md). Strict about structure and
// bounds, so a malformed reply throws (the relay answers 502) rather than
// reaching a renderer; tolerant of unknown fields, and maps unknown enum
// values to 'unknown' so a newer agent never makes bytes render under a
// guessed classification or role.
const STREAM_REQUEST_ID = /^[0-9a-f]{32}$/;
const STREAM_GENERATION = /^[0-9a-f]{16}:(0|[1-9][0-9]{0,19})$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const STREAM_PAGE_BASE64_CHARS = Math.ceil(FOLLOW_LIMITS.pageBytes / 3) * 4;
const UTF8 = new TextEncoder();

function streamFail(what: string): never {
  throw new Error(`malformed stream_data: ${what}`);
}

function streamObject(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) streamFail(what);
  return value as Record<string, unknown>;
}

function streamBool(obj: Record<string, unknown>, key: string): boolean {
  if (typeof obj[key] !== 'boolean') streamFail(key);
  return obj[key] as boolean;
}

function streamInt(value: unknown, what: string, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > max) streamFail(what);
  return value;
}

// A u64 counter: exact up to MAX_SAFE_INTEGER, saturated above it.
function streamCounter(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) streamFail(what);
  return Math.min(value, Number.MAX_SAFE_INTEGER);
}

function streamArray(value: unknown, what: string, max: number): unknown[] {
  if (!Array.isArray(value) || value.length > max) streamFail(what);
  return value;
}

function streamEnum<T extends string>(value: unknown, what: string, known: readonly T[]): T | 'unknown' {
  if (typeof value !== 'string') streamFail(what);
  return (known as readonly string[]).includes(value) ? (value as T) : 'unknown';
}

function base64Bytes(text: string): number {
  return (text.length / 4) * 3 - (text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0);
}

function mapStreamTurn(value: unknown, what: string): FollowTurn {
  const t = streamObject(value, what);
  const start = streamInt(t.start, `${what}.start`, FOLLOW_LIMITS.directionBytes);
  return {
    dir: streamEnum(t.dir, `${what}.dir`, ['c2s', 's2c'] as const),
    start,
    len: streamInt(t.len, `${what}.len`, FOLLOW_LIMITS.directionBytes - start),
    firstSeenMs: streamCounter(t.firstSeenMs, `${what}.firstSeenMs`),
  };
}

function mapStreamPage(value: unknown, what: string): FollowDirectionPage {
  const p = streamObject(value, what);
  const max = FOLLOW_LIMITS.directionBytes;
  const offset = streamInt(p.offset, `${what}.offset`, max);
  const nextOffset = streamInt(p.nextOffset, `${what}.nextOffset`, max);
  const dataBase64 = p.dataBase64;
  if (typeof dataBase64 !== 'string' || dataBase64.length > STREAM_PAGE_BASE64_CHARS || !BASE64.test(dataBase64)) {
    streamFail(`${what}.dataBase64`);
  }
  if (nextOffset < offset || base64Bytes(dataBase64) !== nextOffset - offset) streamFail(`${what}: data does not span offset..nextOffset`);
  const gaps: FollowGap[] = streamArray(p.gaps, `${what}.gaps`, FOLLOW_LIMITS.pageGaps).map((g, i) => {
    const o = streamObject(g, `${what}.gaps[${i}]`);
    // A gap belongs to the page holding it; one at nextOffset only when the page is empty at the end.
    return {
      at: streamInt(o.at, `${what}.gaps[${i}].at`, max),
      missing: streamInt(o.missing, `${what}.gaps[${i}].missing`, 2 ** 32 - 1),
      reason: streamEnum(o.reason, `${what}.gaps[${i}].reason`, ['missing', 'snaplen_likely'] as const),
    };
  });
  const redactedRanges: FollowMask[] = streamArray(p.redactedRanges, `${what}.redactedRanges`, FOLLOW_LIMITS.pageRanges).map((r, i) => {
    const o = streamObject(r, `${what}.redactedRanges[${i}]`);
    const start = streamInt(o.start, `${what}.redactedRanges[${i}].start`, max);
    const len = streamInt(o.len, `${what}.redactedRanges[${i}].len`, max - start);
    if (len === 0) streamFail(`${what}.redactedRanges[${i}].len`);
    if (start < offset || start + len > nextOffset) streamFail(`${what}.redactedRanges[${i}]: outside the page`);
    return { start, len, reason: streamEnum(o.reason, `${what}.redactedRanges[${i}].reason`, ['credential', 'uncertain'] as const) };
  });
  for (const [i, g] of gaps.entries()) {
    if (g.at < offset || g.at > nextOffset || (g.at === nextOffset && nextOffset !== offset)) streamFail(`${what}.gaps[${i}]: outside the page`);
  }
  return {
    classification: streamEnum(p.classification, `${what}.classification`, ['pending', 'cleartext', 'tls'] as const),
    tlsFrom: p.tlsFrom === null ? null : streamInt(p.tlsFrom, `${what}.tlsFrom`, max),
    offset,
    nextOffset,
    storedBytes: streamInt(p.storedBytes, `${what}.storedBytes`, max),
    seenBytes: streamCounter(p.seenBytes, `${what}.seenBytes`),
    stoppedReason: p.stoppedReason === null ? null : streamEnum(p.stoppedReason, `${what}.stoppedReason`, ['store_cap', 'gap_limit', 'turn_limit', 'redaction_limit'] as const),
    gaps,
    conflictingOverlapBytes: streamCounter(p.conflictingOverlapBytes, `${what}.conflictingOverlapBytes`),
    redactedRanges,
    dataBase64,
  };
}

export function mapStreamData(json: unknown): FollowResponse {
  const w = streamObject(json, 'not an object');
  if (w.type !== 'stream_data') streamFail('type');
  if (typeof w.requestId !== 'string' || !STREAM_REQUEST_ID.test(w.requestId)) streamFail('requestId');
  if (typeof w.connectionId !== 'string' || w.connectionId.length === 0 || UTF8.encode(w.connectionId).length > FOLLOW_LIMITS.connectionIdBytes) {
    streamFail('connectionId');
  }
  const generation = w.generation;
  if (generation !== null && (typeof generation !== 'string' || !STREAM_GENERATION.test(generation))) streamFail('generation');
  if (w.clientIsLocal !== null && typeof w.clientIsLocal !== 'boolean') streamFail('clientIsLocal');
  const directions = streamObject(w.directions, 'directions');
  const turnsFrom = streamInt(w.turnsFrom, 'turnsFrom', FOLLOW_LIMITS.flowTurns);
  const turnsNext = w.turnsNext === null ? null : streamInt(w.turnsNext, 'turnsNext', FOLLOW_LIMITS.flowTurns);
  const turns = streamArray(w.turns, 'turns', FOLLOW_LIMITS.pageTurns).map((t, i) => mapStreamTurn(t, `turns[${i}]`));
  if (turnsNext !== null && turnsNext !== turnsFrom + turns.length) streamFail('turnsNext');
  let lastTurn: FollowResponse['lastTurn'] = null;
  if (w.lastTurn !== null) {
    const l = streamObject(w.lastTurn, 'lastTurn');
    lastTurn = { index: streamInt(l.index, 'lastTurn.index', FOLLOW_LIMITS.flowTurns - 1), ...mapStreamTurn(l, 'lastTurn') };
  }
  const reply: FollowResponse = {
    type: 'stream_data',
    requestId: w.requestId,
    connectionId: w.connectionId,
    enabled: streamBool(w, 'enabled'),
    found: streamBool(w, 'found'),
    stale: streamBool(w, 'stale'),
    generation: generation as string | null,
    flowStartCaptured: streamBool(w, 'flowStartCaptured'),
    closed: streamBool(w, 'closed'),
    clientIsLocal: w.clientIsLocal as boolean | null,
    directions: {
      clientToServer: mapStreamPage(directions.clientToServer, 'clientToServer'),
      serverToClient: mapStreamPage(directions.serverToClient, 'serverToClient'),
    },
    turnsFrom,
    turnsNext,
    lastTurn,
    turns,
  };
  if (w.busy !== undefined) {
    if (typeof w.busy !== 'boolean') streamFail('busy');
    reply.busy = w.busy;
  }
  if (w.unavailable !== undefined) reply.unavailable = streamEnum(w.unavailable, 'unavailable', ['relay_port_mismatch'] as const);
  return reply;
}

const TCP_SAMPLE_COLUMNS = ['tUs', 'seq', 'ack', 'win', 'len', 'flags', 'mark', 'rttUs'] as const;
const TCP_SAMPLES_RELATIVE_TO: ReadonlySet<string> = new Set(['isn', 'firstSeen']);

function tcpSamplesObject(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`malformed tcp_samples: ${what}`);
  return value as Record<string, unknown>;
}

function tcpSamplesBool(obj: Record<string, unknown>, key: string): boolean {
  if (typeof obj[key] !== 'boolean') throw new Error(`malformed tcp_samples: ${key}`);
  return obj[key] as boolean;
}

function tcpSamplesString(obj: Record<string, unknown>, key: string): string {
  if (typeof obj[key] !== 'string') throw new Error(`malformed tcp_samples: ${key}`);
  return obj[key] as string;
}

// An integer in [min, max]; anything else (a string, a fraction, an unsafe
// integer) throws, so a sample is exact or rejected, never approximated.
function tcpSamplesInt(value: unknown, what: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`malformed tcp_samples: ${what}`);
  }
  return value;
}

const U32_MAX = 2 ** 32 - 1;
const TCP_SAMPLE_COLUMN_MAX: Record<(typeof TCP_SAMPLE_COLUMNS)[number], number> = {
  tUs: Number.MAX_SAFE_INTEGER,
  seq: U32_MAX,
  ack: U32_MAX,
  win: U32_MAX,
  len: 0xffff,
  flags: 0xff,
  mark: 0xff,
  rttUs: U32_MAX,
};

// KAN-129 `tcp_samples` (docs/wire-protocol.md): columnar and
// delta-encoded on the wire, returned here as one object per sample with
// absolute timestamps. Sequence numbers stay relative to `seqBase`.
export function mapTcpSamplesReply(json: unknown): TcpSamplesPage {
  const w = tcpSamplesObject(json, 'not an object');
  const connectionId = tcpSamplesString(w, 'connectionId');
  if (!tcpSamplesBool(w, 'found')) return { found: false, connectionId };
  const generation = tcpSamplesString(w, 'generation');
  if (tcpSamplesBool(w, 'stale')) return { found: true, stale: true, connectionId, generation };

  const index = (key: string) => tcpSamplesInt(w[key], key, 0, Number.MAX_SAFE_INTEGER);
  const seqBase = tcpSamplesObject(w.seqBase, 'seqBase');
  const windowScale = w.windowScale === null ? null : tcpSamplesObject(w.windowScale, 'windowScale');
  const samples = decodeTcpSampleColumns(tcpSamplesObject(w.samples, 'samples'), 'samples');
  const count = samples.length;
  // KAN-130: absent from an agent that predates it, and whenever the
  // request did not reach back into the pinned head.
  let head: { firstIndex: number; samples: TcpSample[] } | null = null;
  if (w.head !== undefined) {
    const h = tcpSamplesObject(w.head, 'head');
    head = { firstIndex: tcpSamplesInt(h.firstIndex, 'head.firstIndex', 0, Number.MAX_SAFE_INTEGER), samples: decodeTcpSampleColumns(h, 'head') };
  }

  // The page runs from nextIndex − count to nextIndex and starts at or
  // after firstIndex; a reader paging by nextIndex relies on both.
  const firstIndex = index('firstIndex');
  const nextIndex = index('nextIndex');
  if (nextIndex - count < firstIndex) throw new Error('malformed tcp_samples: indices do not cover the samples');

  const relativeTo = tcpSamplesString(w, 'relativeTo');
  return {
    found: true,
    stale: false,
    connectionId,
    generation,
    handshakeSeen: tcpSamplesBool(w, 'handshakeSeen'),
    windowScale: windowScale && {
      // RFC 7323: the agent clamps shift counts to 14.
      local: tcpSamplesInt(windowScale.local, 'windowScale.local', 0, 14),
      remote: tcpSamplesInt(windowScale.remote, 'windowScale.remote', 0, 14),
    },
    seqBase: {
      outbound: tcpSamplesInt(seqBase.outbound, 'seqBase.outbound', 0, U32_MAX),
      inbound: tcpSamplesInt(seqBase.inbound, 'seqBase.inbound', 0, U32_MAX),
    },
    relativeTo: (TCP_SAMPLES_RELATIVE_TO.has(relativeTo) ? relativeTo : 'unknown') as TcpSamplesRelativeTo,
    firstIndex,
    nextIndex,
    more: tcpSamplesBool(w, 'more'),
    droppedOlder: index('droppedOlder'),
    samples,
    head,
    labels: Array.isArray(w.labels) ? w.labels.flatMap(mapTcpSampleLabel) : [],
  };
}

// Columnar, delta-encoded samples (`samples` and KAN-130's `head`).
function decodeTcpSampleColumns(columns: Record<string, unknown>, where: string): TcpSample[] {
  const cols = TCP_SAMPLE_COLUMNS.map((name) => {
    const col = columns[name];
    if (!Array.isArray(col)) throw new Error(`malformed tcp_samples: ${where}.${name}`);
    return col;
  });
  const count = cols[0].length;
  if (cols.some((col) => col.length !== count)) throw new Error(`malformed tcp_samples: ${where} column lengths differ`);

  const samples: TcpSample[] = [];
  let tUs = 0;
  for (let i = 0; i < count; i++) {
    const [t, seq, ack, win, len, flags, mark, rttUs] = TCP_SAMPLE_COLUMNS.map((name, c) => {
      const max = TCP_SAMPLE_COLUMN_MAX[name];
      // Every timestamp after the first is a signed delta.
      return tcpSamplesInt(cols[c][i], `${where}.${name}[${i}]`, name === 'tUs' && i > 0 ? -max : 0, max);
    });
    tUs = tcpSamplesInt(i === 0 ? t : tUs + t, `reconstructed ${where}.tUs[${i}]`, 0, Number.MAX_SAFE_INTEGER);
    samples.push({ tUs, seq, ack, win, len, flags, mark, rttUs, outbound: (mark & TCP_SAMPLE_MARK.OUTBOUND) !== 0 });
  }
  return samples;
}

// KAN-130: `[index, kind, text]`. The agent sends printable ASCII of at
// most 64 bytes; anything else is dropped here (one bad label never rejects
// the reply), so a label is always safe to render as text.
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;
function mapTcpSampleLabel(raw: unknown): TcpSampleLabel[] {
  if (!Array.isArray(raw) || raw.length !== 3) return [];
  const [index, kind, text] = raw;
  if (typeof index !== 'number' || !Number.isSafeInteger(index) || index < 0) return [];
  if (typeof kind !== 'string' || typeof text !== 'string') return [];
  if (text.length > TCP_LABEL_TEXT_MAX || !PRINTABLE_ASCII.test(text) || !PRINTABLE_ASCII.test(kind) || kind.length > 64) return [];
  return [{ index, kind, text }];
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

// KAN-131. Both rollup mappers reject a whole event rather than render part of
// it: a partial or misread list must never look complete (plan P5). Counters
// saturate and the relay re-encodes them, so any finite number >= 0 is
// accepted, above 2^53 included.
function rollupObject(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null) throw new Error(`malformed rollup event: "${what}" is not an object`);
  return value as Record<string, unknown>;
}

function rollupNumber(obj: Record<string, unknown>, key: string, min = 0): number {
  const value = obj[key];
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min) {
    throw new Error(`malformed rollup event: "${key}" is not a finite number >= ${min}`);
  }
  return value;
}

function rollupString(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== 'string') throw new Error(`malformed rollup event: "${key}" is not a string`);
  return value;
}

function rollupAddress(obj: Record<string, unknown>, key: string): string {
  const value = rollupString(obj, key);
  if (value === '') throw new Error(`malformed rollup event: "${key}" is empty`);
  return value;
}

function rollupLabel(obj: Record<string, unknown>, key: string): string | undefined {
  return obj[key] === undefined ? undefined : rollupString(obj, key);
}

function mapRollupTraffic(value: unknown, what: string): RollupTraffic {
  const t = rollupObject(value, what);
  return {
    rxBytes: rollupNumber(t, 'rxBytes'),
    txBytes: rollupNumber(t, 'txBytes'),
    rxPackets: rollupNumber(t, 'rxPackets'),
    txPackets: rollupNumber(t, 'txPackets'),
  };
}

function mapRollupBounds(value: unknown): RollupBounds {
  const b = rollupObject(value, 'bounds');
  const bounds: RollupBounds = {
    cap: rollupNumber(b, 'cap', 1),
    topN: rollupNumber(b, 'topN', 1),
    tracked: rollupNumber(b, 'tracked'),
    evictions: rollupNumber(b, 'evictions'),
    unkeyed: rollupNumber(b, 'unkeyed'),
    sinceMs: b.sinceMs === null ? null : rollupNumber(b, 'sinceMs'),
    horizonMs: b.horizonMs === null ? null : rollupNumber(b, 'horizonMs'),
    totals: mapRollupTraffic(b.totals, 'totals'),
    evicted: mapRollupTraffic(b.evicted, 'evicted'),
  };
  if (bounds.tracked > bounds.cap) throw new Error('malformed rollup event: "tracked" is above "cap"');
  return bounds;
}

// Row order is kept as sent: it is the rankings' last tie-break.
function mapRollup<T>(
  json: unknown,
  key: 'endpoints' | 'conversations',
  mapRow: (row: Record<string, unknown>) => T,
): RollupUpdate<T> {
  const w = rollupObject(json, 'event');
  const bounds = mapRollupBounds(w.bounds);
  const rows = w[key];
  if (!Array.isArray(rows)) throw new Error(`malformed rollup event: "${key}" is not an array`);
  if (rows.length > Math.min(bounds.tracked, 4 * bounds.topN)) {
    throw new Error('malformed rollup event: more rows than "tracked" or 4 x "topN"');
  }
  return { rows: rows.map((row) => mapRow(rollupObject(row, 'row'))), bounds };
}

// The fields both row types share. `enrichment` always comes back `undefined`
// here: it is filled in client-side, once per host (lib/rollup-state.ts).
function mapRollupRow(r: Record<string, unknown>) {
  if (typeof r.historyComplete !== 'boolean') {
    throw new Error('malformed rollup event: "historyComplete" is not a boolean');
  }
  return {
    historyComplete: r.historyComplete,
    rxBytesTotal: rollupNumber(r, 'rxBytesTotal'),
    txBytesTotal: rollupNumber(r, 'txBytesTotal'),
    rxPacketsTotal: rollupNumber(r, 'rxPacketsTotal'),
    txPacketsTotal: rollupNumber(r, 'txPacketsTotal'),
    rxSpeed: rollupNumber(r, 'rxSpeed'),
    txSpeed: rollupNumber(r, 'txSpeed'),
    flowCount: rollupNumber(r, 'flowCount'),
    firstSeenMs: rollupNumber(r, 'firstSeenMs'),
    lastSeenMs: rollupNumber(r, 'lastSeenMs'),
    processName: rollupString(r, 'processName'),
    pid: rollupNumber(r, 'pid'),
    ja3Label: rollupLabel(r, 'ja3Label'),
    enrichment: undefined,
  };
}

export function mapEndpointRollupEvent(json: unknown): RollupUpdate<Endpoint> {
  return mapRollup(json, 'endpoints', (row) => ({
    host: rollupAddress(row, 'host'),
    ...mapRollupRow(row),
    observedName: rollupLabel(row, 'observedName'),
  }));
}

export function mapConversationRollupEvent(json: unknown): RollupUpdate<Conversation> {
  return mapRollup(json, 'conversations', (row) => ({
    localAddr: rollupAddress(row, 'localAddr'),
    remoteAddr: rollupAddress(row, 'remoteAddr'),
    ...mapRollupRow(row),
    durationMs: rollupNumber(row, 'durationMs'),
  }));
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

export function isAgentAuthenticatedMessage(value: unknown): value is import('./types').AgentAuthenticatedMessage {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    && Object.keys(value).length === 1 && Object.prototype.hasOwnProperty.call(value, 'type')
    && (value as Record<string, unknown>).type === 'authenticated';
}

// IO graph (JAM-18). Both events are flat (fields at the top level, beside
// `type`), unlike the nested-envelope events above. Anything malformed
// throws, as the other mappers do; an unknown notObserved reason maps to
// 'unknown' rather than throwing, so a newer agent's reason is shown, not
// dropped (docs/security-plan-review-checklist.md §6).
function requireNumber(obj: Record<string, unknown>, key: string): number {
  const value = requireField<unknown>(obj, key);
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`agent event field "${key}" is not a number`);
  }
  return value;
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const value = requireField<unknown>(obj, key);
  if (typeof value !== 'string') throw new Error(`agent event field "${key}" is not a string`);
  return value;
}

function requireArray(obj: Record<string, unknown>, key: string): unknown[] {
  const value = requireField<unknown>(obj, key);
  if (!Array.isArray(value)) throw new Error(`agent event field "${key}" is not an array`);
  return value;
}

export function mapIoSeriesStatusEvent(json: unknown): IoSeriesStatus {
  const w = json as Record<string, unknown>;
  const series = requireArray(w, 'series').map((raw) => {
    const e = raw as Record<string, unknown>;
    const entry: IoSeriesStatus['series'][number] = {
      id: requireString(e, 'id'),
      filter: requireString(e, 'filter'),
      ok: requireField<boolean>(e, 'ok') === true,
    };
    if (e.error !== undefined) {
      const err = e.error as Record<string, unknown>;
      entry.error = { message: requireString(err, 'message'), token: requireString(err, 'token'), position: requireNumber(err, 'position') };
    }
    if (e.aggregate !== undefined) {
      const a = e.aggregate as Record<string, unknown>;
      const fn = requireString(a, 'fn');
      if (!IO_AGGREGATE_FNS.has(fn)) throw new Error(`unknown io aggregate fn "${fn}"`);
      entry.aggregate = { fn: fn as IoAggregateFn, field: requireString(a, 'field') };
    }
    return entry;
  });
  return {
    revision: requireNumber(w, 'revision'),
    epoch: requireString(w, 'epoch'),
    replayWaiting: w.replayWaiting === true,
    requestId: typeof w.requestId === 'string' ? w.requestId : undefined,
    rejected: typeof w.rejected === 'string' ? w.rejected : undefined,
    series,
  };
}

const IO_NOT_OBSERVED_REASONS: ReadonlySet<string> = new Set(['interface_switch', 'replay_error', 'backlog']);

const IO_AGGREGATE_FNS: ReadonlySet<string> = new Set(['sum', 'min', 'max', 'avg']);

const isCount = (n: unknown): n is number => typeof n === 'number' && Number.isFinite(n);

function mapIoPlainBuckets(value: unknown[], key: string): IoPlainBucket[] {
  return value.map((b) => {
    if (!Array.isArray(b) || b.length !== 3 || !b.every(isCount)) {
      throw new Error(`malformed io_buckets "${key}" entry`);
    }
    return [b[0], b[1], b[2]];
  });
}

// `buckets`: 3-tuples, or 7-tuples for an aggregate series (Task 5). The sum
// is a number, or a decimal string above 2^53 - 1; min/max may be null.
function mapIoBuckets(value: unknown[]): IoBucket[] {
  return value.map((b) => {
    if (Array.isArray(b) && b.length === 3) return mapIoPlainBuckets([b], 'buckets')[0];
    if (!Array.isArray(b) || b.length !== 7 || !b.slice(0, 4).every(isCount)) {
      throw new Error('malformed io_buckets "buckets" entry');
    }
    const sum = typeof b[4] === 'string' && /^\d+$/.test(b[4]) ? Number(b[4]) : b[4];
    const extreme = (n: unknown) => n === null || isCount(n);
    if (!isCount(sum) || !extreme(b[5]) || !extreme(b[6])) throw new Error('malformed io_buckets "buckets" entry');
    return [b[0], b[1], b[2], b[3], sum, b[5], b[6]] as IoAggregateBucket;
  });
}

export function mapIoBucketsEvent(json: unknown): IoBuckets {
  const w = json as Record<string, unknown>;
  const loss = requireField<Record<string, unknown>>(w, 'loss');
  const notObserved: IoNotObserved[] = requireArray(w, 'notObserved').map((raw) => {
    const n = raw as Record<string, unknown>;
    const reason = requireString(n, 'reason');
    return {
      fromMs: requireNumber(n, 'fromMs'),
      toMs: requireNumber(n, 'toMs'),
      reason: (IO_NOT_OBSERVED_REASONS.has(reason) ? reason : 'unknown') as IoNotObservedReason,
    };
  });
  return {
    revision: requireNumber(w, 'revision'),
    epoch: requireString(w, 'epoch'),
    bucketMs: requireNumber(w, 'bucketMs'),
    coveredFromMs: requireNumber(w, 'coveredFromMs'),
    coveredToMs: requireNumber(w, 'coveredToMs'),
    notObserved,
    loss: {
      kernelDropped: requireNumber(loss, 'kernelDropped'),
      ifDropped: requireNumber(loss, 'ifDropped'),
      unparseable: requireNumber(loss, 'unparseable'),
      evaluationSkipped: requireNumber(loss, 'evaluationSkipped'),
    },
    series: requireArray(w, 'series').map((raw) => {
      const s = raw as Record<string, unknown>;
      return {
        id: requireString(s, 'id'),
        late: requireNumber(s, 'late'),
        lateBuckets: mapIoPlainBuckets(requireArray(s, 'lateBuckets'), 'lateBuckets'),
        buckets: mapIoBuckets(requireArray(s, 'buckets')),
      };
    }),
  };
}
