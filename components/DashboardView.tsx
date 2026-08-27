'use client';

import React from 'react';
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  ChevronRight,
  Layers,
  Network,
  ShieldCheck,
  ShieldAlert,
} from 'lucide-react';
import { OSILayerInfo, SystemStats, ThemeConfig, OSILayerNumber } from '@/lib/types';
import { formatBytes, formatSpeed } from '@/lib/osi-engine';

interface DashboardViewProps {
  layers: OSILayerInfo[];
  stats: SystemStats;
  theme: ThemeConfig;
  onSelectLayer: (layerNum: OSILayerNumber) => void;
  historyRx: number[];
  historyTx: number[];
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  layers,
  stats,
  theme,
  onSelectLayer,
  historyRx,
  historyTx,
}) => {
  const maxRxTx = Math.max(...historyRx, ...historyTx, 1);

  // Active sockets: the agent reports the SAME activeSockets count for both
  // L3 and L4 (every established flow is simultaneously "L3 active" and "L4
  // active"), plus a separate L7 count for flows with a recognized app
  // protocol — summing across layers would double/triple-count every
  // connection. Layer 4 (transport) is the natural "how many active
  // connections" metric.
  const totalSockets = layers.find((l) => l.layer === 4)?.activeSockets ?? 0;

  // Overall system health status. Only layers 3, 4, and 7 carry a measured
  // error rate — layers 1/2/5/6 aren't independently observable from
  // captured packets and always report 0, so averaging over all 7 layers
  // dilutes the real value. Average only over the layers this agent
  // actually measures.
  const MEASURED_ERROR_LAYERS = [3, 4, 7];
  const measuredLayers = layers.filter((l) => MEASURED_ERROR_LAYERS.includes(l.layer));
  const avgError =
    measuredLayers.length > 0
      ? measuredLayers.reduce((acc, l) => acc + l.errorRate, 0) / measuredLayers.length
      : 0;
  const isHealthy = avgError < 0.2;

  return (
    <div className="space-y-4 font-mono text-xs p-3">
      {/* Top Banner KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {/* RX Card */}
        <div className={`p-3 rounded border ${theme.border} ${theme.cardBg} space-y-1 relative overflow-hidden`}>
          <div className="flex items-center justify-between text-slate-400 text-[11px]">
            <span className="flex items-center space-x-1">
              <ArrowDownRight className="h-3.5 w-3.5 text-emerald-400" />
              <span>INBOUND (RX)</span>
            </span>
          </div>
          <div className="text-lg font-bold text-emerald-400 tracking-tight">
            {formatSpeed(stats.rxTotalMbps * 1024 * 1024)}
          </div>
          <div className="flex justify-between items-center text-[10px] text-slate-400 pt-1 border-t border-slate-800">
            <span>Packets: {stats.rxPpsTotal.toLocaleString()} pps</span>
            <span>Total: {formatBytes(stats.rxTotalMbps * 1024 * 1024 * 60)}</span>
          </div>
        </div>

        {/* TX Card */}
        <div className={`p-3 rounded border ${theme.border} ${theme.cardBg} space-y-1 relative overflow-hidden`}>
          <div className="flex items-center justify-between text-slate-400 text-[11px]">
            <span className="flex items-center space-x-1">
              <ArrowUpRight className="h-3.5 w-3.5 text-sky-400" />
              <span>OUTBOUND (TX)</span>
            </span>
          </div>
          <div className="text-lg font-bold text-sky-400 tracking-tight">
            {formatSpeed(stats.txTotalMbps * 1024 * 1024)}
          </div>
          <div className="flex justify-between items-center text-[10px] text-slate-400 pt-1 border-t border-slate-800">
            <span>Packets: {stats.txPpsTotal.toLocaleString()} pps</span>
            <span>Total: {formatBytes(stats.txTotalMbps * 1024 * 1024 * 60)}</span>
          </div>
        </div>

        {/* Sockets / Connections Card */}
        <div className={`p-3 rounded border ${theme.border} ${theme.cardBg} space-y-1 relative overflow-hidden`}>
          <div className="flex items-center justify-between text-slate-400 text-[11px]">
            <span className="flex items-center space-x-1">
              <Network className="h-3.5 w-3.5 text-indigo-400" />
              <span>ACTIVE SOCKETS</span>
            </span>
            <span className="text-[10px] text-indigo-400 bg-indigo-950/60 px-1 rounded">L4</span>
          </div>
          <div className="text-lg font-bold text-indigo-300 tracking-tight">
            {totalSockets} <span className="text-xs font-normal opacity-70">open streams</span>
          </div>
          <div className="flex justify-between items-center text-[10px] text-slate-400 pt-1 border-t border-slate-800">
            <span>Interface: {stats.interfaceName}</span>
            <span>Captured: {stats.totalPacketsCaptured.toLocaleString()}</span>
          </div>
        </div>

        {/* Health / Anomaly Status */}
        <div className={`p-3 rounded border ${theme.border} ${theme.cardBg} space-y-1 relative overflow-hidden`}>
          <div className="flex items-center justify-between text-slate-400 text-[11px]">
            <span className="flex items-center space-x-1">
              {isHealthy ? (
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
              )}
              <span>PROTOCOL HEALTH</span>
            </span>
            <span className={`text-[10px] px-1 rounded font-bold ${isHealthy ? 'text-emerald-400 bg-emerald-950' : 'text-rose-400 bg-rose-950'}`}>
              {isHealthy ? 'NOMINAL' : 'ATTENTION'}
            </span>
          </div>
          <div className={`text-lg font-bold tracking-tight ${isHealthy ? 'text-emerald-300' : 'text-rose-400'}`}>
            {isHealthy ? '99.8% Efficiency' : 'Retransmit Anomaly'}
          </div>
          <div className="flex justify-between items-center text-[10px] text-slate-400 pt-1 border-t border-slate-800">
            <span>Error Drop Rate: {avgError.toFixed(2)}%</span>
            <span>Layer Status: 7/7 UP</span>
          </div>
        </div>
      </div>

      {/* Real-Time Bandwidth Time-Series Graph */}
      <div className={`p-3 rounded border ${theme.border} ${theme.cardBg} space-y-2`}>
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div className="flex items-center space-x-2 font-bold tracking-wide">
            <Activity className={`h-4 w-4 ${theme.accent}`} />
            <span>REAL-TIME TRAFFIC BANDWIDTH (RX / TX SPEED HISTOGRAM)</span>
          </div>
          <div className="flex items-center space-x-4 text-[11px]">
            <span className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block"></span>
              <span className="text-emerald-400 font-semibold">RX Speed</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-sky-500 inline-block"></span>
              <span className="text-sky-400 font-semibold">TX Speed</span>
            </span>
          </div>
        </div>

        {/* Visual Bar Plot Graph */}
        <div className="h-28 w-full flex items-end space-x-1 pt-2 bg-black/40 rounded p-2 overflow-x-auto">
          {historyRx.map((rxVal, idx) => {
            const txVal = historyTx[idx] || 0;
            const rxHeight = Math.min(100, Math.max(8, (rxVal / maxRxTx) * 100));
            const txHeight = Math.min(100, Math.max(8, (txVal / maxRxTx) * 100));

            return (
              <div key={idx} className="flex-1 flex items-end justify-center space-x-0.5 h-full group relative">
                {/* RX Bar */}
                <div
                  style={{ height: `${rxHeight}%` }}
                  className="w-full bg-emerald-500/80 group-hover:bg-emerald-400 transition-all rounded-t-sm"
                />
                {/* TX Bar */}
                <div
                  style={{ height: `${txHeight}%` }}
                  className="w-full bg-sky-500/80 group-hover:bg-sky-400 transition-all rounded-t-sm"
                />

                {/* Hover Tooltip */}
                <div className="hidden group-hover:block absolute bottom-full mb-1 bg-slate-900 border border-slate-700 text-[10px] text-slate-200 p-1.5 rounded shadow-xl z-20 whitespace-nowrap">
                  <div>RX: {formatSpeed(rxVal * 1024 * 1024)}</div>
                  <div>TX: {formatSpeed(txVal * 1024 * 1024)}</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 7 OSI Model Layers Stack */}
      <div className={`p-3 rounded border ${theme.border} ${theme.cardBg} space-y-3`}>
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div className="flex items-center space-x-2 font-bold tracking-wide">
            <Layers className={`h-4 w-4 ${theme.accent}`} />
            <span>OSI 7-LAYER PROTOCOL STACK & ACTIVE SPEED BREAKDOWN</span>
          </div>
          <span className="text-[11px] opacity-60">Click layer to open full header packet inspection</span>
        </div>

        {/* Stack list from L7 (top) to L1 (bottom) */}
        <div className="space-y-2">
          {[...layers].reverse().map((layer) => {
            const totalLayerSpeed = layer.rxSpeed + layer.txSpeed;

            return (
              <div
                key={layer.layer}
                onClick={() => onSelectLayer(layer.layer)}
                className={`p-2.5 rounded border ${theme.border} bg-slate-950/60 hover:bg-slate-900/90 transition cursor-pointer group space-y-2 relative overflow-hidden`}
              >
                {/* Layer row top info */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center space-x-2.5">
                    {/* Layer Badge */}
                    <div className={`px-2 py-0.5 rounded text-xs font-bold ${layer.badgeBg} ${layer.badgeText}`}>
                      Layer {layer.layer}: {layer.name}
                    </div>

                    {/* PDU */}
                    <span className="text-[10px] text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                      PDU: {layer.pdu}
                    </span>

                    {/* Protocol Badges */}
                    <div className="hidden md:flex items-center space-x-1">
                      {layer.protocols.slice(0, 5).map((p) => (
                        <span key={p} className="text-[10px] bg-slate-800/80 text-slate-300 px-1.5 py-0.2 rounded">
                          {p}
                        </span>
                      ))}
                      {layer.protocols.length > 5 && (
                        <span className="text-[10px] text-slate-500">+{layer.protocols.length - 5}</span>
                      )}
                    </div>
                  </div>

                  {/* Speeds & Packet Rate */}
                  <div className="flex items-center space-x-4 text-[11px]">
                    <div className="text-right">
                      <span className="text-emerald-400 font-bold">↓ {formatSpeed(layer.rxSpeed)}</span>
                      <span className="opacity-40 mx-1">|</span>
                      <span className="text-sky-400 font-bold">↑ {formatSpeed(layer.txSpeed)}</span>
                    </div>

                    <div className="hidden sm:block text-slate-400 text-[10px] w-24 text-right">
                      {(layer.rxPacketsPerSec + layer.txPacketsPerSec).toLocaleString()} pps
                    </div>

                    <ChevronRight className={`h-4 w-4 ${theme.accent} opacity-0 group-hover:opacity-100 transition transform group-hover:translate-x-1`} />
                  </div>
                </div>

                {/* Sub-row: Primary Metric & Sparkline */}
                <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/60">
                  <div className="flex items-center space-x-3">
                    <span>
                      <strong className="text-slate-300">{layer.details.primaryMetric}:</strong> {layer.details.primaryValue}
                    </span>
                    <span className="hidden lg:inline opacity-40">|</span>
                    <span className="hidden lg:inline">
                      <strong className="text-slate-300">{layer.details.secondaryMetric}:</strong> {layer.details.secondaryValue}
                    </span>
                  </div>

                  {/* Mini Sparkline Bar Chart */}
                  <div className="flex items-end space-x-0.5 h-4 w-28 bg-black/40 p-0.5 rounded">
                    {layer.sparkline.map((val, i) => (
                      <div
                        key={i}
                        style={{ height: `${Math.min(100, (val / 150) * 100)}%` }}
                        className={`w-full ${layer.layer === 7 ? 'bg-emerald-500' : layer.layer === 4 ? 'bg-amber-500' : 'bg-indigo-500'} opacity-80`}
                      />
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
