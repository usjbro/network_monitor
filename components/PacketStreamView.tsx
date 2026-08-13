'use client';

import React, { useState } from 'react';
import {
  Activity,
  Code,
  FileText,
  Filter,
  Layers,
  Pause,
  Play,
  Search,
  Shield,
  Trash2,
} from 'lucide-react';
import { PacketFrame, ThemeConfig, OSILayerNumber } from '@/lib/types';

interface PacketStreamViewProps {
  packets: PacketFrame[];
  theme: ThemeConfig;
  onClearPackets: () => void;
}

export const PacketStreamView: React.FC<PacketStreamViewProps> = ({
  packets,
  theme,
  onClearPackets,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [isFrozen, setIsFrozen] = useState(false);
  const [layerFilter, setLayerFilter] = useState<number>(0); // 0 = all
  const [selectedPacket, setSelectedPacket] = useState<PacketFrame | null>(packets[0] || null);

  const displayedPackets = packets.filter((pkt) => {
    const matchesSearch =
      pkt.protocol.toLowerCase().includes(searchTerm.toLowerCase()) ||
      pkt.src.includes(searchTerm) ||
      pkt.dst.includes(searchTerm) ||
      pkt.summary.toLowerCase().includes(searchTerm.toLowerCase());

    if (layerFilter === 0) return matchesSearch;
    return matchesSearch && pkt.layer === layerFilter;
  });

  return (
    <div className="space-y-3 font-mono text-xs p-3">
      {/* Top Controls Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 bg-slate-950 p-2.5 rounded border border-slate-800">
        <div className="flex items-center space-x-2 flex-1 min-w-[240px]">
          <Search className="h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filter live pcap stream by keyword, IP, port, or protocol..."
            className="w-full bg-transparent text-slate-200 placeholder-slate-600 focus:outline-none text-xs"
          />
        </div>

        {/* Layer Filter Buttons */}
        <div className="flex items-center space-x-1">
          <button
            onClick={() => setLayerFilter(0)}
            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              layerFilter === 0
                ? `${theme.highlight}`
                : 'bg-slate-900 border border-slate-800 text-slate-400'
            }`}
          >
            All Layers
          </button>
          {[7, 6, 5, 4, 3, 2, 1].map((l) => (
            <button
              key={l}
              onClick={() => setLayerFilter(l)}
              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                layerFilter === l
                  ? `${theme.highlight}`
                  : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              L{l}
            </button>
          ))}
        </div>

        {/* Freeze & Clear Controls */}
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setIsFrozen(!isFrozen)}
            className={`flex items-center space-x-1 px-2 py-1 rounded text-[10px] font-bold border ${
              isFrozen
                ? 'bg-amber-950 text-amber-300 border-amber-600'
                : 'bg-slate-800 border-slate-700 text-slate-300'
            }`}
          >
            {isFrozen ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
            <span>{isFrozen ? 'RESUME STREAM' : 'FREEZE'}</span>
          </button>

          <button
            onClick={onClearPackets}
            className="p-1 rounded bg-slate-800 border border-slate-700 text-slate-400 hover:text-rose-400 transition"
            title="Clear Stream Buffer"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Main Packet Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {/* Left Column: Live Packet Log Stream (2 cols) */}
        <div className={`lg:col-span-2 rounded border ${theme.border} ${theme.cardBg} overflow-hidden flex flex-col h-[480px]`}>
          <div className="bg-slate-950 px-3 py-2 border-b border-slate-800 flex justify-between items-center text-[10px] text-slate-400 font-bold">
            <span>PACKET CAPTURE FEED ({displayedPackets.length} FRAMES)</span>
            <span>{isFrozen ? '[STREAM PAUSED]' : '[LIVE CAPTURING]'}</span>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-slate-800/80">
            {displayedPackets.map((pkt) => {
              const isSelected = selectedPacket?.id === pkt.id;

              return (
                <div
                  key={pkt.id}
                  onClick={() => setSelectedPacket(pkt)}
                  className={`p-2 hover:bg-slate-900/90 transition cursor-pointer flex items-start space-x-2 text-[11px] ${
                    isSelected ? 'bg-slate-900 border-l-2 border-emerald-400 font-semibold' : ''
                  }`}
                >
                  {/* Timestamp */}
                  <span className="text-slate-500 text-[10px] whitespace-nowrap">{pkt.timestamp}</span>

                  {/* Layer Badge */}
                  <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-slate-800 text-slate-300 whitespace-nowrap">
                    L{pkt.layer}
                  </span>

                  {/* Protocol Badge */}
                  <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800/60 whitespace-nowrap">
                    {pkt.protocol}
                  </span>

                  {/* Packet summary */}
                  <div className="flex-1 min-w-0 truncate text-slate-200">
                    <span className="text-slate-400">{pkt.src} â†’ {pkt.dst}:</span> {pkt.summary}
                  </div>

                  {/* Length */}
                  <span className="text-[10px] text-slate-500">{pkt.length}B</span>
                </div>
              );
            })}

            {displayedPackets.length === 0 && (
              <div className="p-8 text-center text-slate-500">
                No packet frames in capture buffer matching current filter.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Selected Packet Frame Inspector */}
        <div className={`rounded border ${theme.border} ${theme.cardBg} p-3 space-y-3 overflow-y-auto h-[480px]`}>
          {selectedPacket ? (
            <>
              <div className="border-b border-slate-800 pb-2">
                <div className="text-xs font-bold text-slate-100 flex items-center justify-between">
                  <span>PACKET HEADER INSPECTOR</span>
                  <span className="text-[10px] text-emerald-400 font-mono">ID: {selectedPacket.id}</span>
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5">
                  Protocol: {selectedPacket.protocol} | Length: {selectedPacket.length} Bytes
                </div>
              </div>

              {/* Layer Header Decomposition */}
              <div className="space-y-2 text-[11px]">
                {/* Layer 7 */}
                {selectedPacket.headerBreakdown.layer7 && (
                  <div className="p-2 rounded bg-slate-950 border border-emerald-800/60 space-y-1">
                    <div className="font-bold text-emerald-400 text-[10px]">â–¶ Layer 7 (Application): {selectedPacket.headerBreakdown.layer7.app}</div>
                    <div className="text-[10px] text-slate-300">
                      Method: {selectedPacket.headerBreakdown.layer7.methodOrType} | Path: {selectedPacket.headerBreakdown.layer7.pathOrQuery}
                    </div>
                  </div>
                )}

                {/* Layer 6 */}
                {selectedPacket.headerBreakdown.layer6 && (
                  <div className="p-2 rounded bg-slate-950 border border-cyan-800/60 space-y-1">
                    <div className="font-bold text-cyan-400 text-[10px]">â–¶ Layer 6 (Presentation): {selectedPacket.headerBreakdown.layer6.tlsVersion}</div>
                    <div className="text-[10px] text-slate-300">
                      Cipher: {selectedPacket.headerBreakdown.layer6.cipherSuite}
                    </div>
                  </div>
                )}

                {/* Layer 4 */}
                {selectedPacket.headerBreakdown.layer4 && (
                  <div className="p-2 rounded bg-slate-950 border border-amber-800/60 space-y-1">
                    <div className="font-bold text-amber-400 text-[10px]">â–¶ Layer 4 (Transport): {selectedPacket.headerBreakdown.layer4.transport}</div>
                    <div className="text-[10px] text-slate-300">
                      Ports: {selectedPacket.headerBreakdown.layer4.srcPort} â†’ {selectedPacket.headerBreakdown.layer4.dstPort} | Flags: {selectedPacket.headerBreakdown.layer4.flags}
                    </div>
                  </div>
                )}

                {/* Layer 3 */}
                {selectedPacket.headerBreakdown.layer3 && (
                  <div className="p-2 rounded bg-slate-950 border border-rose-800/60 space-y-1">
                    <div className="font-bold text-rose-400 text-[10px]">â–¶ Layer 3 (Network): {selectedPacket.headerBreakdown.layer3.ipVersion}</div>
                    <div className="text-[10px] text-slate-300">
                      Src IP: {selectedPacket.headerBreakdown.layer3.srcIp} | Dst IP: {selectedPacket.headerBreakdown.layer3.dstIp} | TTL: {selectedPacket.headerBreakdown.layer3.ttl}
                    </div>
                  </div>
                )}

                {/* Layer 2 */}
                {selectedPacket.headerBreakdown.layer2 && (
                  <div className="p-2 rounded bg-slate-950 border border-purple-800/60 space-y-1">
                    <div className="font-bold text-purple-400 text-[10px]">â–¶ Layer 2 (Data Link): Ethernet II</div>
                    <div className="text-[10px] text-slate-300">
                      MAC: {selectedPacket.headerBreakdown.layer2.srcMac} â†’ {selectedPacket.headerBreakdown.layer2.dstMac}
                    </div>
                  </div>
                )}
              </div>

              {/* Raw Hex Dump Box */}
              <div className="space-y-1">
                <div className="text-[10px] font-bold text-slate-400 flex items-center space-x-1">
                  <Code className="h-3 w-3 inline" />
                  <span>RAW HEX PAYLOAD DUMP</span>
                </div>
                <pre className="p-2 bg-black text-emerald-400 text-[10px] rounded border border-slate-800 leading-tight overflow-x-auto select-all">
                  {selectedPacket.hexDump}
                </pre>
              </div>
            </>
          ) : (
            <div className="p-8 text-center text-slate-500">
              Select any packet frame from the left log stream to inspect header fields.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
