'use client';

import React from 'react';
import {
  ArrowLeft,
  Activity,
  CheckCircle2,
  Cpu,
  HelpCircle,
  Layers,
  Radio,
  Server,
  ShieldCheck,
  Sparkles,
  Zap,
} from 'lucide-react';
import { OSILayerInfo, ThemeConfig, OSILayerNumber } from '@/lib/types';
import { formatSpeed, formatBytes } from '@/lib/osi-engine';

interface LayerDetailViewProps {
  layer: OSILayerInfo;
  theme: ThemeConfig;
  onBack: () => void;
  onSelectLayer: (layerNum: OSILayerNumber) => void;
}

const LAYER_DESCRIPTIONS: Record<number, { title: string; desc: string; headerFields: string[] }> = {
  7: {
    title: 'Application Layer (Layer 7)',
    desc: 'Provides user-facing network services, HTTP/3 APIs, DNS resolution, SSH terminal streams, gRPC RPC calls, and MQTT telemetry.',
    headerFields: ['HTTP Method / Path', 'Host / Authority', 'User-Agent', 'Content-Type / Accept', 'Status Code', 'Payload Body Bytes'],
  },
  6: {
    title: 'Presentation Layer (Layer 6)',
    desc: 'Handles data formatting, syntax translation, TLS 1.3 cryptographic handshakes, JSON / Protobuf serialization, and Brotli compression.',
    headerFields: ['TLS Record Type', 'Cipher Suite (AES-256-GCM)', 'TLS Handshake Session Key', 'Compression Ratio', 'Protobuf Message Schema'],
  },
  5: {
    title: 'Session Layer (Layer 5)',
    desc: 'Establishes, manages, and terminates session connections between local and remote applications, RPC session tokens, and SOCKS5 tunnels.',
    headerFields: ['Session ID Hash', 'RPC Request Token', 'Keepalive Heartbeat Status', 'Dialog Control Flag', 'Session Termination Reason'],
  },
  4: {
    title: 'Transport Layer (Layer 4)',
    desc: 'Provides end-to-end communication, TCP flow control, congestion avoidance (BBR), UDP datagram multiplexing, and QUIC stream frames.',
    headerFields: ['Source Port Number', 'Destination Port Number', 'Sequence Number', 'Acknowledgment Number', 'TCP Flags (SYN/ACK/PSH/FIN)', 'Window Size'],
  },
  3: {
    title: 'Network Layer (Layer 3)',
    desc: 'Responsible for logical IP addressing (IPv4/IPv6), packet routing across gateways, ICMP control messages, and BGP/OSPF table lookups.',
    headerFields: ['IP Version (v4/v6)', 'Source IP Address', 'Destination IP Address', 'Time To Live (TTL)', 'Protocol Number (6=TCP/17=UDP)', 'Header Checksum'],
  },
  2: {
    title: 'Data Link Layer (Layer 2)',
    desc: 'Translates packets into hardware Ethernet II frames, handles physical MAC addressing, ARP caching, and 802.1Q VLAN trunk tagging.',
    headerFields: ['Destination MAC Address', 'Source MAC Address', 'EtherType (0x0800 IPv4 / 0x86DD IPv6)', '802.1Q VLAN Tag ID', 'Frame Check Sequence (FCS/CRC)'],
  },
  1: {
    title: 'Physical Layer (Layer 1)',
    desc: 'Transmits raw unstructured bit streams over physical copper cables, optical fiber transceivers, or wireless 802.11ax radio spectrum.',
    headerFields: ['Physical Medium (10GBASE-T / Fiber)', 'Link Carrier Status (UP/DOWN)', 'Clock Synchronization Bit Stream', 'Signal-to-Noise Ratio (SNR dB)', 'Transceiver Optical Power (dBm)'],
  },
};

export const LayerDetailView: React.FC<LayerDetailViewProps> = ({
  layer,
  theme,
  onBack,
  onSelectLayer,
}) => {
  const meta = LAYER_DESCRIPTIONS[layer.layer] || LAYER_DESCRIPTIONS[7];

  return (
    <div className="space-y-4 font-mono text-xs p-3">
      {/* Top Header Row with Navigation & Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center space-x-3">
          <button
            onClick={onBack}
            className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 border border-slate-700 hover:border-slate-500 text-slate-200 transition"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>BACK TO STACK</span>
          </button>

          <div className={`px-2.5 py-1 rounded text-xs font-bold ${layer.badgeBg} ${layer.badgeText}`}>
            Layer {layer.layer}: {layer.name}
          </div>

          <span className="text-slate-400 font-bold">PDU: {layer.pdu}</span>
        </div>

        {/* OSI Layer Quick Selector Switcher */}
        <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded border border-slate-800">
          {([7, 6, 5, 4, 3, 2, 1] as OSILayerNumber[]).map((num) => (
            <button
              key={num}
              onClick={() => onSelectLayer(num)}
              className={`px-2 py-0.5 rounded text-[11px] font-bold transition ${
                layer.layer === num
                  ? `${theme.highlight}`
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              L{num}
            </button>
          ))}
        </div>
      </div>

      {/* Layer Description Banner */}
      <div className={`p-3.5 rounded border ${theme.border} ${theme.cardBg} space-y-2`}>
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
            <Layers className={`h-4 w-4 ${theme.accent}`} />
            <span>{meta.title}</span>
          </h2>
        </div>

        <p className="text-slate-300 text-[11px] leading-relaxed">{meta.desc}</p>

        {/* Protocol Pills */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="text-slate-400 font-bold mr-1">Supported Protocols:</span>
          {layer.protocols.map((p) => (
            <span
              key={p}
              className="bg-slate-900 text-slate-200 border border-slate-700 px-2 py-0.5 rounded text-[10px] font-semibold"
            >
              {p}
            </span>
          ))}
        </div>
      </div>

      {/* Layer Speed & Performance KPI Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className={`p-3 rounded border ${theme.border} ${theme.cardBg} space-y-1`}>
          <div className="text-slate-400 text-[10px]">INBOUND SPEED (RX)</div>
          <div className="text-base font-bold text-emerald-400">{formatSpeed(layer.rxSpeed)}</div>
          <div className="text-[10px] text-slate-500">{layer.rxPacketsPerSec.toLocaleString()} pps</div>
        </div>

        <div className={`p-3 rounded border ${theme.border} ${theme.cardBg} space-y-1`}>
          <div className="text-slate-400 text-[10px]">OUTBOUND SPEED (TX)</div>
          <div className="text-base font-bold text-sky-400">{formatSpeed(layer.txSpeed)}</div>
          <div className="text-[10px] text-slate-500">{layer.txPacketsPerSec.toLocaleString()} pps</div>
        </div>

        <div className={`p-3 rounded border ${theme.border} ${theme.cardBg} space-y-1`}>
          <div className="text-slate-400 text-[10px]">TOTAL CUMULATIVE TRAFFIC</div>
          <div className="text-base font-bold text-indigo-300">{formatBytes(layer.totalBytes)}</div>
          <div className="text-[10px] text-slate-500">Active Sockets: {layer.activeSockets}</div>
        </div>

        <div className={`p-3 rounded border ${theme.border} ${theme.cardBg} space-y-1`}>
          <div className="text-slate-400 text-[10px]">ERROR DROP RATE</div>
          <div className="text-base font-bold text-rose-400">{layer.errorRate.toFixed(2)}%</div>
          <div className="text-[10px] text-emerald-400 flex items-center space-x-1">
            <CheckCircle2 className="h-3 w-3 inline" />
            <span>{layer.details.healthStatus}</span>
          </div>
        </div>
      </div>

      {/* Key Metrics Table & Field Specs */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* Key Metrics Breakdown */}
        <div className={`p-3.5 rounded border ${theme.border} ${theme.cardBg} space-y-2`}>
          <div className="font-bold text-slate-200 border-b border-slate-800 pb-1.5 flex items-center space-x-2">
            <Activity className={`h-4 w-4 ${theme.accent}`} />
            <span>KEY PROTOCOL METRICS (LAYER {layer.layer})</span>
          </div>

          <div className="space-y-1.5 pt-1">
            {Object.entries(layer.details.keyMetrics).map(([key, val]) => (
              <div key={key} className="flex justify-between items-center bg-slate-950/70 p-2 rounded border border-slate-800/80">
                <span className="text-slate-400">{key}:</span>
                <span className="font-bold text-slate-200">{val}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Frame / Packet Header Field Anatomy */}
        <div className={`p-3.5 rounded border ${theme.border} ${theme.cardBg} space-y-2`}>
          <div className="font-bold text-slate-200 border-b border-slate-800 pb-1.5 flex items-center space-x-2">
            <Cpu className={`h-4 w-4 ${theme.accent}`} />
            <span>HEADER SPECIFICATION & FIELD STRUCTURE</span>
          </div>

          <div className="space-y-1.5 pt-1">
            {meta.headerFields.map((field, idx) => (
              <div key={idx} className="flex items-center space-x-2 bg-black/40 p-2 rounded border border-slate-800 text-[11px]">
                <span className="bg-slate-800 text-slate-300 font-bold px-1.5 py-0.5 rounded text-[10px]">
                  Field {idx + 1}
                </span>
                <span className="text-slate-300 font-semibold">{field}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
