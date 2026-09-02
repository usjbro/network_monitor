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
  transportProtocol: 'TCP' | 'UDP' | 'QUIC' | 'SCTP' | 'ICMP' | 'RAW';
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
  headerBreakdown: {
    layer7?: { app: string; methodOrType: string; pathOrQuery: string; statusOrCode?: string; payloadBytes: number };
    layer6?: { tlsVersion: string; cipherSuite: string; compression: string; payloadEncrypted: boolean };
    layer5?: { sessionType: string; sessionId: string; token: string };
    layer4?: { transport: string; srcPort: number; dstPort: number; flags: string; windowSize: number; seqAck: string };
    layer3?: { ipVersion: string; srcIp: string; dstIp: string; ttl: number; protocolNum: number; checksum: string };
    layer2?: { srcMac: string; dstMac: string; ethType: string; vlanTag?: string };
    layer1?: { phyType: string; bitrateMbps: number; snrDb: number; linkStatus: string };
  };
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

export interface SystemStats {
  hostname: string;
  interfaceName: string;
  interfaceSpeedMbps: number;
  duplexMode: string;
  ipAddress: string;
  macAddress: string;
  cpuUsagePct: number;
  memUsagePct: number;
  uptimeSeconds: number;
  rxTotalMbps: number;
  txTotalMbps: number;
  rxPpsTotal: number;
  txPpsTotal: number;
  totalPacketsCaptured: number;
}
