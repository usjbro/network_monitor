'use client';

import React, { useState } from 'react';
import {
  Code,
  Download,
  Pause,
  Play,
  Search,
  Trash2,
} from 'lucide-react';
import { DecryptedPayloadSegment, PacketFrame, ThemeConfig, OSILayerNumber } from '@/lib/types';
// Only packetsToJson is imported here. decryptedSegments is deliberately
// never passed to it — see lib/export.ts's header and
// lib/__tests__/decrypted-export-exclusion.test.ts.
import { downloadBlob, packetsToJson } from '@/lib/export';

interface PacketStreamViewProps {
  packets: PacketFrame[];
  theme: ThemeConfig;
  onClearPackets: () => void;
  // Tier B (opt-in decrypted TLS content) — optional so this component
  // stays backward compatible with call sites that never pass it.
  decryptedSegments?: DecryptedPayloadSegment[];
  // The "showing N of M observed" horizon (JAM-6/GitHub #73): every packet
  // the agent has reported this session, from capture_stats' `received`.
  // Optional — omitted (or before the first capture_stats tick) the view
  // says nothing about a horizon rather than claiming one it can't
  // substantiate.
  totalObserved?: number;
  // The current client-side retention cap (`buffer packets <n>`), shown so
  // the horizon text explains WHY only N are listed.
  bufferLimit?: number;
}

export const PacketStreamView: React.FC<PacketStreamViewProps> = ({
  packets,
  theme,
  onClearPackets,
  decryptedSegments = [],
  totalObserved,
  bufferLimit,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [isFrozen, setIsFrozen] = useState(false);
  const [layerFilter, setLayerFilter] = useState<number>(0); // 0 = all
  const [selectedPacket, setSelectedPacket] = useState<PacketFrame | null>(packets[0] || null);
  // Transient feedback for the hex-dump copy button: a clipboard write can
  // legitimately fail (no permission, or no navigator.clipboard at all on a
  // non-secure origin), and silently doing nothing would read as a broken
  // button.
  const [hexCopyState, setHexCopyState] = useState<'idle' | 'copied' | 'failed'>('idle');

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

          {/* Export (JAM-7/GitHub #74) — the displayed packets only, and
              never decryptedSegments, which packetsToJson cannot accept. */}
          <button
            onClick={() => downloadBlob(packetsToJson(displayedPackets), `packets-${Date.now()}.json`, 'application/json')}
            disabled={displayedPackets.length === 0}
            title="Download the frames currently shown as JSON"
            className="flex items-center space-x-1 px-2 py-1 rounded text-[10px] font-bold border bg-slate-800 border-slate-700 text-slate-300 hover:text-emerald-300 disabled:opacity-40 disabled:hover:text-slate-300 transition"
          >
            <Download className="h-3 w-3" />
            <span>EXPORT JSON</span>
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

          {/* Honest horizon (JAM-6/GitHub #73). This buffer holds the most
              recent `bufferLimit` frames; `totalObserved` is every frame
              the agent reported this session. Saying so explicitly is the
              point of the issue — a 100-row list silently standing in for
              400,000 observed frames is the dishonesty being fixed.

              The `>= packets.length` guard matters: `totalObserved` comes
              from capture_stats' `received`, which is libpcap's own
              `pcap::Stat` and is therefore 0 for a REPLAYED file (there's
              no live capture handle to ask). Printing "showing last 25 of
              0 observed" there would be its own dishonesty, so when the
              counter can't support the claim the total is simply omitted
              rather than shown as a number known to be wrong. */}
          {(totalObserved !== undefined || bufferLimit !== undefined) && (
            <div className="bg-slate-950/60 px-3 py-1 border-b border-slate-800 text-[10px] text-slate-500">
              showing last {packets.length}
              {totalObserved !== undefined && totalObserved >= packets.length && ` of ${totalObserved} observed`}
              {bufferLimit !== undefined && ` — this tab keeps ${bufferLimit} (\`buffer packets <n>\` to change)`}
            </div>
          )}

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
                    <span className="text-slate-400">{pkt.src} → {pkt.dst}:</span> {pkt.summary}
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
                    <div className="font-bold text-emerald-400 text-[10px]">▶ Layer 7 (Application): {selectedPacket.headerBreakdown.layer7.app}</div>
                    <div className="text-[10px] text-slate-300">
                      Method: {selectedPacket.headerBreakdown.layer7.methodOrType} | Path: {selectedPacket.headerBreakdown.layer7.pathOrQuery}
                    </div>
                    {selectedPacket.headerBreakdown.layer7.statusOrCode && (
                      <div className="text-[10px] text-slate-300">
                        Status: {selectedPacket.headerBreakdown.layer7.statusOrCode}
                      </div>
                    )}
                  </div>
                )}

                {/* Layer 6 */}
                {selectedPacket.headerBreakdown.layer6 && (
                  <div className="p-2 rounded bg-slate-950 border border-cyan-800/60 space-y-1">
                    <div className="font-bold text-cyan-400 text-[10px]">▶ Layer 6 (Presentation): {selectedPacket.headerBreakdown.layer6.tlsVersion}</div>
                    <div className="text-[10px] text-slate-300">
                      Cipher: {selectedPacket.headerBreakdown.layer6.cipherSuite}
                    </div>
                  </div>
                )}

                {/* Layer 4 */}
                {selectedPacket.headerBreakdown.layer4 && (
                  <div className="p-2 rounded bg-slate-950 border border-amber-800/60 space-y-1">
                    <div className="font-bold text-amber-400 text-[10px]">▶ Layer 4 (Transport): {selectedPacket.headerBreakdown.layer4.transport}</div>
                    <div className="text-[10px] text-slate-300">
                      Ports: {selectedPacket.headerBreakdown.layer4.srcPort} → {selectedPacket.headerBreakdown.layer4.dstPort} | Flags: {selectedPacket.headerBreakdown.layer4.flags}
                    </div>
                  </div>
                )}

                {/* Layer 3 */}
                {selectedPacket.headerBreakdown.layer3 && (
                  <div className="p-2 rounded bg-slate-950 border border-rose-800/60 space-y-1">
                    <div className="font-bold text-rose-400 text-[10px]">▶ Layer 3 (Network): {selectedPacket.headerBreakdown.layer3.ipVersion}</div>
                    <div className="text-[10px] text-slate-300">
                      Src IP: {selectedPacket.headerBreakdown.layer3.srcIp} | Dst IP: {selectedPacket.headerBreakdown.layer3.dstIp} | TTL: {selectedPacket.headerBreakdown.layer3.ttl}
                    </div>
                  </div>
                )}

                {/* Layer 2 */}
                {selectedPacket.headerBreakdown.layer2 && (
                  <div className="p-2 rounded bg-slate-950 border border-purple-800/60 space-y-1">
                    <div className="font-bold text-purple-400 text-[10px]">▶ Layer 2 (Data Link): Ethernet II</div>
                    <div className="text-[10px] text-slate-300">
                      MAC: {selectedPacket.headerBreakdown.layer2.srcMac} → {selectedPacket.headerBreakdown.layer2.dstMac}
                    </div>
                    {selectedPacket.headerBreakdown.layer2.vlanTag && (
                      <div className="text-[10px] text-slate-300">
                        802.1Q VLAN: {selectedPacket.headerBreakdown.layer2.vlanTag}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Raw Hex Dump Box */}
              <div className="space-y-1">
                <div className="text-[10px] font-bold text-slate-400 flex items-center justify-between">
                  <span className="flex items-center space-x-1">
                    <Code className="h-3 w-3 inline" />
                    <span>RAW HEX PAYLOAD DUMP</span>
                  </span>
                  {/* Copy the single selected frame's hex dump (JAM-7/GitHub
                      #74's third export form). navigator.clipboard is absent
                      on a non-secure origin other than localhost, so the
                      button reports failure rather than appearing to work. */}
                  <button
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(selectedPacket.hexDump);
                        setHexCopyState('copied');
                      } catch {
                        setHexCopyState('failed');
                      }
                      setTimeout(() => setHexCopyState('idle'), 2000);
                    }}
                    title="Copy this frame's hex dump to the clipboard"
                    className="px-2 py-0.5 rounded text-[10px] font-bold border bg-slate-800 border-slate-700 text-slate-300 hover:text-emerald-300 transition"
                  >
                    {hexCopyState === 'copied' ? 'COPIED' : hexCopyState === 'failed' ? 'COPY FAILED' : 'COPY HEX'}
                  </button>
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

      {/* Tier B: Decrypted TLS Content Pane — additive to the ciphertext
          view above, never replacing it. Only rendered at all when at
          least one decrypted segment has been seen, so this stays
          invisible (and the "never ambient" requirement holds) for anyone
          not running osi-inspect. */}
      {decryptedSegments.length > 0 && (
        <div className={`rounded border ${theme.border} ${theme.cardBg} overflow-hidden`}>
          <div className="bg-slate-950 px-3 py-2 border-b border-slate-800 flex justify-between items-center text-[10px] text-slate-400 font-bold">
            <span>DECRYPTED CONTENT ({decryptedSegments.length} SEGMENTS)</span>
            <span className="text-amber-400">[TIER B — OPT-IN]</span>
          </div>
          <div className="max-h-64 overflow-y-auto divide-y divide-slate-800/80">
            {decryptedSegments.map((seg, idx) => (
              <div key={`${seg.connectionId}-${seg.streamId ?? 'x'}-${idx}`} className="p-2 text-[11px] space-y-1">
                <div className="flex items-center space-x-2 text-[10px] text-slate-500">
                  <span className="px-1.5 py-0.2 rounded font-bold bg-amber-950 text-amber-400 border border-amber-800/60">
                    Decrypted
                  </span>
                  <span>{seg.connectionId}</span>
                  {seg.streamId !== undefined && <span>stream {seg.streamId}</span>}
                </div>
                <pre
                  className={`p-2 rounded border border-slate-800 overflow-x-auto whitespace-pre-wrap break-all ${
                    seg.redacted ? 'redacted italic opacity-70 text-slate-500 bg-black/40' : 'text-emerald-300 bg-black'
                  }`}
                >
                  {seg.text}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
