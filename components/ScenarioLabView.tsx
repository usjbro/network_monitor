'use client';

import React from 'react';
import {
  AlertTriangle,
  Globe,
  Radio,
  ShieldAlert,
  Sliders,
  Sparkles,
  Zap,
} from 'lucide-react';
import { TrafficScenario, ThemeConfig } from '@/lib/types';

interface ScenarioLabViewProps {
  currentScenario: TrafficScenario;
  onSelectScenario: (s: TrafficScenario) => void;
  theme: ThemeConfig;
  onInjectPacket: (proto: string) => void;
}

const SCENARIOS_LIST: { id: TrafficScenario; title: string; desc: string; danger?: boolean; icon: string }[] = [
  {
    id: 'normal',
    title: 'Normal Operational Mix',
    desc: 'Standard enterprise profile with standard proportions of HTTP/3, TLS 1.3, DNS, SSH, and WebSocket traffic.',
    icon: '🌐',
  },
  {
    id: 'web_heavy',
    title: 'Web Browsing & API Cluster',
    desc: 'High REST API request rate, HTTP/2 multiplexed streams, and Brotli-compressed JSON payload delivery.',
    icon: '🚀',
  },
  {
    id: 'video_stream',
    title: '4K Video Streaming (QUIC / UDP)',
    desc: 'Sustained high bandwidth on Layer 4 UDP/QUIC streams with minimal latency buffer requirements.',
    icon: '🎬',
  },
  {
    id: 'syn_flood',
    title: 'DDoS SYN Flood Attack',
    desc: 'Simulates a distributed TCP SYN packet flood triggering high L4 retransmit rates and CPU load.',
    danger: true,
    icon: '⚠️',
  },
  {
    id: 'iot_mesh',
    title: 'IoT Telemetry Swarm',
    desc: 'Dense population of MQTT v5 sensors producing high socket counts and small, high-frequency payloads.',
    icon: '📡',
  },
  {
    id: 'dns_storm',
    title: 'DNS Subdomain Query Storm',
    desc: 'Rapid UDP Port 53 queries testing Layer 7 DNS cache hit rates and recursive resolver latency.',
    danger: true,
    icon: '🌪️',
  },
];

export const ScenarioLabView: React.FC<ScenarioLabViewProps> = ({
  currentScenario,
  onSelectScenario,
  theme,
  onInjectPacket,
}) => {
  return (
    <div className="space-y-4 font-mono text-xs p-3">
      {/* Top Header */}
      <div className={`p-3.5 rounded border ${theme.border} ${theme.cardBg} space-y-1`}>
        <h2 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
          <Zap className={`h-4 w-4 ${theme.accent}`} />
          <span>REAL-TIME NETWORK TRAFFIC SIMULATOR & SCENARIO LAB</span>
        </h2>
        <p className="text-[11px] text-slate-400">
          Inject custom traffic scenarios to test protocol stack behavior, bandwidth meters, and AI diagnostic responses.
        </p>
      </div>

      {/* Scenario Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {SCENARIOS_LIST.map((scen) => {
          const isActive = currentScenario === scen.id;

          return (
            <div
              key={scen.id}
              onClick={() => onSelectScenario(scen.id)}
              className={`p-3.5 rounded border transition cursor-pointer space-y-2 relative overflow-hidden ${
                isActive
                  ? `${theme.highlight} shadow-lg ring-1 ring-emerald-500`
                  : scen.danger
                  ? 'border-rose-900/60 bg-rose-950/20 hover:bg-rose-950/40 text-slate-300'
                  : `${theme.border} ${theme.cardBg} hover:bg-slate-900/90 text-slate-300`
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <span className="text-base">{scen.icon}</span>
                  <span className="font-bold text-slate-100">{scen.title}</span>
                </div>

                {isActive && (
                  <span className="bg-emerald-500 text-black text-[10px] font-bold px-1.5 py-0.5 rounded">
                    ACTIVE
                  </span>
                )}
              </div>

              <p className="text-[11px] text-slate-400 leading-relaxed">{scen.desc}</p>
            </div>
          );
        })}
      </div>

      {/* Manual Packet Injection Console */}
      <div className={`p-3.5 rounded border ${theme.border} ${theme.cardBg} space-y-3`}>
        <div className="font-bold text-slate-200 border-b border-slate-800 pb-2 flex items-center space-x-2">
          <Sliders className={`h-4 w-4 ${theme.accent}`} />
          <span>MANUAL PACKET INJECTION CONSOLE</span>
        </div>

        <div className="flex flex-wrap gap-2 pt-1">
          <button
            onClick={() => onInjectPacket('HTTP/3 GET')}
            className="px-3 py-1.5 rounded bg-emerald-950 border border-emerald-600 text-emerald-300 font-bold hover:bg-emerald-900 transition"
          >
            + Inject HTTP/3 Request (L7)
          </button>

          <button
            onClick={() => onInjectPacket('TCP SYN')}
            className="px-3 py-1.5 rounded bg-amber-950 border border-amber-600 text-amber-300 font-bold hover:bg-amber-900 transition"
          >
            + Inject TCP SYN Handshake (L4)
          </button>

          <button
            onClick={() => onInjectPacket('DNS Query')}
            className="px-3 py-1.5 rounded bg-indigo-950 border border-indigo-600 text-indigo-300 font-bold hover:bg-indigo-900 transition"
          >
            + Inject DNS Resolver Query (L7)
          </button>

          <button
            onClick={() => onInjectPacket('ICMP Echo')}
            className="px-3 py-1.5 rounded bg-rose-950 border border-rose-600 text-rose-300 font-bold hover:bg-rose-900 transition"
          >
            + Inject ICMP Ping Packet (L3)
          </button>
        </div>
      </div>
    </div>
  );
};
