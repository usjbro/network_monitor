'use client';

import React, { useState } from 'react';
import {
  Filter,
  Lock,
  Network,
  Search,
} from 'lucide-react';
import { NetworkConnection, ThemeConfig } from '@/lib/types';
import { formatSpeed, formatBytes } from '@/lib/osi-engine';

interface ConnectionsViewProps {
  connections: NetworkConnection[];
  theme: ThemeConfig;
  enrichmentMode?: 'off' | 'on-demand' | 'background'; // default 'off' if omitted
  onRequestLookup?: (connectionId: string, remoteAddr: string) => void;
  // Driven from app/page.tsx: a connection's id is present while a lookup
  // is in flight for it (cleared on the matching connection_enrichment
  // event or a timeout), or present after a lookup completed without
  // producing a usable enrichment object within a reasonable window.
  lookingUpIds?: Set<string>;
  unavailableIds?: Set<string>;
}

export const ConnectionsView: React.FC<ConnectionsViewProps> = ({
  connections,
  theme,
  enrichmentMode,
  onRequestLookup,
  lookingUpIds,
  unavailableIds,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [selectedConnId, setSelectedConnId] = useState<string | null>(connections[0]?.id || null);

  const filtered = connections.filter((conn) => {
    const matchesSearch =
      conn.protocol.toLowerCase().includes(searchTerm.toLowerCase()) ||
      conn.processName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      conn.remoteAddr.includes(searchTerm) ||
      (conn.remoteHostname && conn.remoteHostname.toLowerCase().includes(searchTerm.toLowerCase())) ||
      conn.localAddr.includes(searchTerm);

    if (protocolFilter === 'ALL') return matchesSearch;
    if (protocolFilter === 'TCP') return matchesSearch && conn.transportProtocol === 'TCP';
    if (protocolFilter === 'UDP') return matchesSearch && conn.transportProtocol === 'UDP';
    if (protocolFilter === 'QUIC') return matchesSearch && conn.transportProtocol === 'QUIC';
    return matchesSearch && conn.appLayerProtocol.toUpperCase().includes(protocolFilter);
  });

  const selectedConn = connections.find((c) => c.id === selectedConnId) || connections[0];

  return (
    <div className="space-y-3 font-mono text-xs p-3">
      {/* Top Search & Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 bg-slate-950 p-2.5 rounded border border-slate-800">
        <div className="flex items-center space-x-2 flex-1 min-w-[240px]">
          <Search className="h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filter sockets by IP, process name, port, or protocol (e.g., chrome, 443, DNS)..."
            className="w-full bg-transparent text-slate-200 placeholder-slate-600 focus:outline-none text-xs"
          />
        </div>

        {/* Protocol Filter Tabs */}
        <div className="flex items-center space-x-1">
          <Filter className="h-3.5 w-3.5 opacity-50 mr-1" />
          {['ALL', 'TCP', 'UDP', 'QUIC', 'HTTPS', 'DNS'].map((proto) => (
            <button
              key={proto}
              onClick={() => setProtocolFilter(proto)}
              className={`px-2 py-0.5 rounded text-[11px] font-bold transition ${
                protocolFilter === proto
                  ? `${theme.highlight}`
                  : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {proto}
            </button>
          ))}
        </div>
      </div>

      {/* Connection Table */}
      <div className={`rounded border ${theme.border} ${theme.cardBg} overflow-x-auto`}>
        <table className="w-full text-left border-collapse min-w-[760px]">
          <thead>
            <tr className="bg-slate-950/80 text-slate-400 border-b border-slate-800 text-[10px] uppercase">
              <th className="p-2.5">Protocol & App</th>
              <th className="p-2.5">Process (PID)</th>
              <th className="p-2.5">Local Socket</th>
              <th className="p-2.5">Remote Host / Socket</th>
              <th className="p-2.5 text-right">RX Speed</th>
              <th className="p-2.5 text-right">TX Speed</th>
              <th className="p-2.5 text-center">Latency</th>
              <th className="p-2.5 text-center">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filtered.map((conn) => {
              const isSelected = conn.id === selectedConnId;

              return (
                <tr
                  key={conn.id}
                  onClick={() => setSelectedConnId(conn.id)}
                  className={`hover:bg-slate-900/80 transition cursor-pointer ${
                    isSelected ? 'bg-slate-900/90 font-semibold' : ''
                  }`}
                >
                  {/* Protocol */}
                  <td className="p-2.5">
                    <div className="flex items-center space-x-2">
                      <span className={`w-2 h-2 rounded-full ${isSelected ? 'bg-emerald-400' : 'bg-slate-600'}`}></span>
                      <div>
                        <div className="text-slate-200 font-bold">{conn.protocol}</div>
                        <div className="text-[10px] text-slate-400">{conn.encryption}</div>
                      </div>
                    </div>
                  </td>

                  {/* Process */}
                  <td className="p-2.5 text-slate-300">
                    <div className="font-bold">{conn.processName}</div>
                    <div className="text-[10px] text-slate-500">PID: {conn.pid}</div>
                  </td>

                  {/* Local Socket */}
                  <td className="p-2.5 text-slate-300">
                    <div>{conn.localAddr}</div>
                    <div className="text-[10px] text-slate-500">Port {conn.localPort}</div>
                  </td>

                  {/* Remote Socket */}
                  <td className="p-2.5 text-slate-300">
                    <div className="font-bold text-slate-200">{conn.remoteHostname || conn.remoteAddr}</div>
                    <div className="text-[10px] text-slate-500">{conn.remoteAddr}:{conn.remotePort}</div>
                  </td>

                  {/* RX Speed */}
                  <td className="p-2.5 text-right font-bold text-emerald-400">
                    {formatSpeed(conn.rxSpeed)}
                  </td>

                  {/* TX Speed */}
                  <td className="p-2.5 text-right font-bold text-sky-400">
                    {formatSpeed(conn.txSpeed)}
                  </td>

                  {/* Latency */}
                  <td className="p-2.5 text-center text-slate-300">
                    <div>{conn.latencyMs} ms</div>
                    <div className="text-[10px] text-slate-500">{conn.packetLoss.toFixed(2)}% loss</div>
                  </td>

                  {/* Status */}
                  <td className="p-2.5 text-center">
                    <span className="bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold px-2 py-0.5 rounded">
                      {conn.status}
                    </span>
                  </td>
                </tr>
              );
            })}

            {filtered.length === 0 && (
              <tr>
                <td colSpan={8} className="p-8 text-center text-slate-500">
                  No active sockets matching current search criteria.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Selected Connection OSI Layer Stack Inspector */}
      {selectedConn && (
        <div className={`p-3.5 rounded border ${theme.border} ${theme.cardBg} space-y-2`}>
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center space-x-2 font-bold text-slate-200">
              <Network className={`h-4 w-4 ${theme.accent}`} />
              <span>OSI LAYER ENCAPSULATION STACK FOR SOCKET [{selectedConn.processName}:{selectedConn.pid}]</span>
            </div>

            <div className="flex items-center space-x-2 text-[11px] text-slate-400">
              <Lock className="h-3 w-3 text-emerald-400 inline" />
              <span>{selectedConn.encryption}</span>
            </div>
          </div>

          {/* OSI Stack Path */}
          <div className="p-2 bg-black/60 rounded border border-slate-800 font-mono text-[11px] text-emerald-300 break-all">
            {selectedConn.osiStack}
          </div>

          {/* Ownership section — spec Components §7 five-state display */}
          <div className="pt-2 border-t border-slate-800 space-y-1.5">
            <div className="text-[11px] font-bold text-slate-400 uppercase">Ownership</div>
            {(!enrichmentMode || enrichmentMode === 'off') ? (
              <div className="text-slate-500">Enrichment disabled — enable with <code>enrich on</code> in the command bar.</div>
            ) : lookingUpIds?.has(selectedConn.id) ? (
              <div className="text-slate-400">Looking up…</div>
            ) : unavailableIds?.has(selectedConn.id) ? (
              <div className="text-slate-500">Unavailable — no ownership data returned for this address.</div>
            ) : !selectedConn.enrichment ? (
              <button
                onClick={() => onRequestLookup?.(selectedConn.id, selectedConn.remoteAddr)}
                className="px-2 py-1 rounded text-[11px] font-bold bg-slate-800 hover:bg-slate-700 text-slate-200"
              >
                Not yet looked up — click to look up
              </button>
            ) : (
              <div className="text-slate-300">
                {/* Org/registrant are wrapped in their own <span> (rather than
                    left as bare sibling text nodes) so each renders as a
                    single, individually-addressable text element — both so
                    a hostile/adversarial registry string can't visually run
                    together with the surrounding "Org: "/" · ASN: " labels,
                    and so it's independently queryable in tests without
                    picking up neighboring label text. */}
                Org: <span>{selectedConn.enrichment.org ?? '—'}</span> · ASN: {selectedConn.enrichment.asn ?? '—'}
                {selectedConn.enrichment.registrant && <> · Registrant: <span>{selectedConn.enrichment.registrant}</span></>}
                <span className="text-slate-500"> · as of {selectedConn.enrichment.fetchedAt}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
