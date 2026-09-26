export type OSILayerNumber = 1 | 2 | 3 | 4 | 5 | 6 | 7;

export interface OSILayerInfo {
  layer: OSILayerNumber;
  name: string;
  shortName: string;
  pdu: string;
  protocols: string[];
  color: string;
  badgeBg: string;
  badgeText: string;
  rxSpeed: number; // Bytes / sec
  txSpeed: number; // Bytes / sec
  rxPacketsPerSec: number;
  txPacketsPerSec: number;
  totalBytes: number;
  errorRate: number; // Percentage 0 - 100
  activeSockets: number;
  sparkline: number[];
  details: {
    primaryMetric: string;
    primaryValue: string;
    secondaryMetric: string;
    secondaryValue: string;
    tertiaryMetric: string;
    tertiaryValue: string;
    healthStatus: 'OPTIMAL' | 'WARNING' | 'CRITICAL';
    keyMetrics: Record<string, string | number>;
  };
}

export interface NetworkConnection {
  id: string;
  protocol: string;
  appLayerProtocol: string;
  transportProtocol: 'TCP' | 'UDP' | 'SCTP' | 'ICMP' | 'RAW';
  osiStack: string; // e.g., "L7:HTTP/3 -> L6:TLS1.3 -> L5:QUIC -> L4:UDP -> L3:IPv6 -> L2:Eth -> L1:Fiber"
  localAddr: string;
  localPort: number;
  remoteAddr: string;
  remotePort: number;
  remoteHostname?: string;
  processName: string;
  pid: number;
  rxSpeed: number; // B/s
  txSpeed: number; // B/s
  rxBytesTotal: number;
  txBytesTotal: number;
  latencyMs: number;
  packetLoss: number; // %
  status: 'ESTABLISHED' | 'SYN_SENT' | 'LISTEN' | 'TIME_WAIT' | 'CLOSE_WAIT';
  encryption: string;
  sparkline: number[];
  ja3Fingerprint?: string;
  ja3Label?: string;
  // Populated only when the user has opted into ownership enrichment
  // (docs/superpowers/specs/2026-08-28-ownership-enrichment-design.md).
  // `undefined` unambiguously means "never looked up" — a single presence
  // check gates whether the Ownership section shows anything but its
  // disabled/not-yet-looked-up state.
  enrichment?: {
    org?: string;
    asn?: string;    // best-effort RIR registry data, NOT BGP-observed routing data — see spec Scope
    asnOrg?: string;
    country?: string;
    registrant?: string; // extended tier only (domain registrant)
    source: 'rdap' | 'whois' | 'cache';
    fetchedAt: string;
  };
}

// One entry from the agent's per-packet field registry
// (capture-agent/src/fields.rs, docs/wire-protocol.md's `packet` event
// section). A `group` entry (type: 'group') carries no `value` — only a
// byte range spanning its children. `region` says which of the two
// hex-dump panes `offset`/`len` is relative to.
export interface WireField {
  path: string;
  label: string;
  group?: string;
  // 'str' matches Rust's lowercase serialization of FieldType::Str.
  type: 'group' | 'bool' | 'uint' | 'str' | 'addr' | 'bytes';
  value?: boolean | number | string;
  region: 'header' | 'payload';
  offset: number;
  len: number;
}

export interface PacketFrame {
  id: string;
  timestamp: string;
  relativeTimeMs: number;
  layer: OSILayerNumber;
  protocol: string;
  src: string;
  dst: string;
  length: number;
  summary: string;
  hexDump: string;
  // Header-region bytes (Ethernet/IP/transport) — a separate pane from
  // hexDump above, which covers only the L4 payload. No cap: every
  // currently-decoded field lives in a fixed header portion.
  headerHexDump: string;
  // Flat per-packet field list; components/FieldTree.ts groups entries
  // into a tree by each field's `group`.
  fields: WireField[];
}

// Tier B (opt-in, per-process decrypted TLS content via `osi-inspect` /
// SSLKEYLOGFILE) — one entry per decrypted HTTP/2 header block or DATA
// frame body. Kept as a separate type (not folded into PacketFrame) since
// it comes from a distinct, separately-gated wire event
// (`decrypted_payload`, see docs/wire-protocol.md) with different
// trust/sensitivity characteristics than ordinary packet metadata.
export interface DecryptedPayloadSegment {
  connectionId: string;
  streamId?: number;
  text: string;
  redacted: boolean;
}

// A single traceroute hop, as reported by capture-agent's `traceroute_hop`
// wire event (docs/wire-protocol.md) and, once resolved, enriched by the
// relay's `geo_hop_update` SSE event (docs/geoip-protocol.md). `hopIp`/
// `rttMs` are both absent — not an error state — when that hop got no
// reply within its retry budget. `location` starts undefined and is filled
// in later, separately, only if geoIP is enabled.
export interface TracerouteHop {
  targetIp: string;
  hopNumber: number;
  hopIp?: string;
  rttMs?: number;
  location?: { city?: string; country?: string };
}

// Capture health, from the agent's `capture_stats` wire event
// (docs/wire-protocol.md), sent once per tick alongside layer_update.
// `dropped`/`ifDropped` are kernel/driver-side losses (packets that never
// reached the agent process at all); `relayLaggedEvents` is this relay's
// own outbound backlog to a slow SSE client; `unparseableFrames` is frames
// the agent did receive but couldn't decode at all (e.g. an unsupported
// link-layer shape — see issue #63). All three are independent of, and a
// precondition for trusting, any connection's retransmit-derived
// `packetLoss` figure — see issue #61. `totalConnectionsObserved`/
// `capacityEvictions`/`idleEvictions` are the "showing N of M" horizon
// counters (JAM-6/GitHub #73): `totalConnectionsObserved` is the "N" half
// (every distinct flow this session has ever seen, never inflated by a
// repeat packet on an already-tracked flow); `capacityEvictions` (flows
// dropped for exceeding the table's capacity ceiling, not for going idle)
// and `idleEvictions` (ordinary connection turnover) are two independent
// health signals a nonzero-and-growing `capacityEvictions` distinguishes
// from normal churn.
export interface CaptureStats {
  received: number;
  dropped: number;
  ifDropped: number;
  relayLaggedEvents: number;
  unparseableFrames: number;
  totalConnectionsObserved: number;
  capacityEvictions: number;
  idleEvictions: number;
}

// Whether this agent process is capturing live traffic or replaying a
// previously-captured file — fixed for the life of the process (spec:
// live/replay is a startup-only choice, never runtime-switchable).
export type AgentMode = 'live' | 'replay';

// From the agent's `agent_status` wire event (docs/wire-protocol.md), sent
// once per tick alongside capture_stats/system_stats — revived by epic #55
// (JAM-125) to carry the live/replay mode indicator file-replay needs;
// previously defined but never sent. Consumers hold this as
// `AgentStatus | null`, matching `SystemStats`/`CaptureConfig`'s own
// "null until the first tick" discipline.
export interface AgentStatus {
  interface: string;
  capturing: boolean;
  mode: AgentMode;
  replaySource?: string;
  directionAttributionUnavailable: boolean;
}

// From the agent's `capture_file_status` wire event (docs/wire-protocol.md)
// — capture-to-file (epic #55/JAM-132/GitHub #70, ring rotation JAM-5/
// GitHub #72). Sent once per tick; `path`/`bytesWritten` keep reporting the
// last-active file's values even after `writing` goes back to `false`, so
// a client sees the run's actual end state rather than the fields just
// disappearing. `ringFile`/`ringTotal`/`autostopReason` are only present
// while a ring-mode capture is active/finished respectively — see the
// wire doc's field notes for exactly when each is absent vs. present.
export interface CaptureFileStatus {
  writing: boolean;
  path?: string;
  bytesWritten: number;
  ringFile?: number;
  ringTotal?: number;
  autostopReason?: string;
  backpressureDrops: number;
}

export type TerminalTheme = 'sophisticated' | 'macos_pro' | 'macos_homebrew' | 'iterm_snazzy' | 'matrix' | 'dracula' | 'amber' | 'cyberpunk' | 'catppuccin' | 'nord';

export interface ThemeConfig {
  id: TerminalTheme;
  name: string;
  bg: string;
  text: string;
  border: string;
  accent: string;
  secondaryAccent: string;
  highlight: string;
  cardBg: string;
  promptUser: string;
  promptHost: string;
  promptPath: string;
}

// From the agent's `system_stats` wire event (docs/wire-protocol.md), sent
// once per tick alongside layer_update/capture_stats. Every field here is a
// real measurement — issue #64 removed the placeholder shape this used to
// be (interfaceSpeedMbps, duplexMode, macAddress, cpuUsagePct, memUsagePct,
// uptimeSeconds) rather than wiring those up or faking them; none of them
// are measurable from this agent today. Consumers hold this as
// `SystemStats | null` — `null` until the first tick arrives, distinct
// from a genuine zero once at least one tick has been received.
export interface SystemStats {
  hostname: string;
  interfaceName: string;
  ipAddress: string;
  rxTotalMbps: number;
  txTotalMbps: number;
  rxPpsTotal: number;
  txPpsTotal: number;
  totalPacketsCaptured: number;
}

// The capture-time controls currently in effect, from the agent's
// `capture_config` wire event (docs/wire-protocol.md), sent once per tick
// alongside capture_stats/system_stats — issue #68. `filter: null` means no
// BPF filter is active (every frame is captured); `snaplen` is the number
// of bytes retained per frame before the kernel truncates the rest.
// Consumers hold this as `CaptureConfig | null` — `null` until the first
// tick arrives, matching the same "no placeholder" discipline as
// `SystemStats`/`CaptureStats` above.
export interface CaptureConfig {
  filter: string | null;
  snaplen: number;
}

// One capturable network interface, from the agent's `interface_list` wire
// event (docs/wire-protocol.md) — issue #69. Only interfaces with at least
// one assigned address are ever included: an addressless one can't be
// attributed as local/remote by FlowTable and would silently capture
// nothing if selected, so it's never offered as a choice at all.
export interface NetworkInterface {
  name: string;
  addresses: string[];
}
