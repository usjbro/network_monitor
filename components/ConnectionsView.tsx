'use client';

import React, { useState } from 'react';
import {
  Download,
  Filter,
  Lock,
  Network,
  Route,
  Search,
} from 'lucide-react';
import { NetworkConnection, ThemeConfig, TracerouteHop } from '@/lib/types';
import { formatSpeed, formatBytes } from '@/lib/osi-engine';
import { connectionsToCsv, downloadBlob } from '@/lib/export';
import type { CompiledDisplayFilter } from '@/lib/display-filter';

function downloadConnectionsCsv(connections: NetworkConnection[], totalObserved: number): void {
  downloadBlob(
    connectionsToCsv(connections, totalObserved),
    `connections-${Date.now()}.csv`,
    'text/csv',
  );
}

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
  traceroute?: Record<string, TracerouteHop[]>;
  traceInFlight?: Record<string, boolean>;
  onTraceRoute?: (connectionId: string, remoteAddr: string) => void;
  // True when the agent's capture_stats event (issue #61) reports nonzero
  // kernel/driver drops or relay lag — the per-connection loss % below is
  // retransmit-derived and only trustworthy when this is false.
  captureDegraded?: boolean;
  // The "showing N of M observed" horizon (JAM-6/GitHub #73), from
  // capture_stats: `totalObserved` is every distinct flow the agent has
  // seen this session, `capacityEvictions` the subset dropped because the
  // agent's own flow table hit its `MAX_FLOWS` ceiling. The two are
  // surfaced separately on purpose — ordinary idle turnover is expected,
  // capacity eviction means the table may be missing recent activity.
  totalObserved?: number;
  capacityEvictions?: number;
  // The current client-side retention cap (`buffer connections <n>`).
  bufferLimit?: number;
  displayFilter?: CompiledDisplayFilter;
  displayFilterExpression?: string;
}

export const ConnectionsView: React.FC<ConnectionsViewProps> = ({
  connections,
  theme,
  enrichmentMode,
  onRequestLookup,
  lookingUpIds,
  unavailableIds,
  traceroute,
  traceInFlight,
  onTraceRoute,
  captureDegraded,
  totalObserved,
  capacityEvictions,
  bufferLimit,
  displayFilter,
  displayFilterExpression,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [selectedConnId, setSelectedConnId] = useState<string | null>(connections[0]?.id || null);

  const sharedMatches = displayFilter ? connections.filter((connection) => displayFilter({ kind: 'connection', connection })) : connections;
  const filtered = sharedMatches.filter((conn) => {
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

  const selectedConn = filtered.find((c) => c.id === selectedConnId) ?? filtered[0];

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

        {/* Export (JAM-7/GitHub #74). Exports `filtered` — exactly the rows
            the table below is showing — not the unfiltered `connections`
            prop, per the spec's "the current filtered table" requirement.
            Purely client-side: no request, nothing written server-side. */}
        <button
          onClick={() => downloadConnectionsCsv(filtered, totalObserved ?? filtered.length)}
          disabled={filtered.length === 0}
          title="Download the rows currently shown as CSV"
          className="flex items-center space-x-1 px-2 py-1 rounded text-[10px] font-bold border bg-slate-800 border-slate-700 text-slate-300 hover:text-emerald-300 disabled:opacity-40 disabled:hover:text-slate-300 transition"
        >
          <Download className="h-3 w-3" />
          <span>EXPORT CSV</span>
        </button>
      </div>

      {displayFilter && (
        <div className="text-[11px] text-slate-400" role="status">
          Display filter{displayFilterExpression ? ` (${displayFilterExpression})` : ''}: {sharedMatches.length} of {connections.length} buffered connections match; hidden connections remain buffered.
        </div>
      )}

      {/* Honest horizon (JAM-6/GitHub #73) — see the props' own comment
          for why capacity eviction is called out separately from the
          plain "showing N of M" line. */}
      {(totalObserved !== undefined || bufferLimit !== undefined) && (
        <div className="text-[11px] text-slate-500">
          showing {connections.length}
          {/* Same "don't claim a total the counter can't support" guard as
              PacketStreamView — see its comment. `totalConnectionsObserved`
              is agent-maintained (not libpcap's) so it is trustworthy in
              replay too, but the guard costs nothing and keeps the two
              views' honesty rule identical. */}
          {totalObserved !== undefined && totalObserved >= connections.length && ` of ${totalObserved} observed`}
          {bufferLimit !== undefined && ` — this tab keeps ${bufferLimit} (\`buffer connections <n>\` to change)`}
        </div>
      )}
      {capacityEvictions !== undefined && capacityEvictions > 0 && (
        <div className="text-[11px] text-amber-500">
          {capacityEvictions} connection(s) evicted for capacity — the agent&apos;s flow table hit its ceiling, so it may
          be missing recent activity (a port scan or a burst can do this). Raise it with the agent&apos;s{' '}
          <code>MAX_FLOWS</code> environment variable.
        </div>
      )}

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
              const isSelected = conn.id === selectedConn?.id;

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
                    <div className={`text-[10px] ${captureDegraded ? 'text-amber-500' : 'text-slate-500'}`}>
                      {conn.packetLoss.toFixed(2)}% loss
                      {captureDegraded && <span title="Capture is dropping frames — this figure may under-report actual loss">*</span>}
                    </div>
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

          {/* TLS Client Fingerprint (JA3) */}
          <div className="mt-2 text-slate-300">
            <span className="text-slate-400">JA3</span>{' '}
            {selectedConn.ja3Fingerprint ? (
              <>
                <span className="font-mono">{selectedConn.ja3Fingerprint}</span>
                {selectedConn.ja3Label && (
                  <span className="ml-2 text-slate-500">{selectedConn.ja3Label}</span>
                )}
              </>
            ) : (
              <span className="text-slate-500">no TLS handshake observed for this connection</span>
            )}
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
            ) : !selectedConn.enrichment.org && !selectedConn.enrichment.asn && !selectedConn.enrichment.registrant ? (
              // Task 15's fifth state: a lookup genuinely completed (the
              // connection_enrichment event arrived — this is NOT the
              // in-flight-timeout `unavailableIds` case above) but produced
              // no ownership data at all. Deliberately distinct from the
              // normal render path below, where a blank ASN alongside a
              // present org is expected and shown as "—", not an error.
              <div className="text-slate-500">Unavailable — no ownership data returned for this address.</div>
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

          {/* Trace Route: on-demand only, never triggered automatically */}
          {onTraceRoute && (
            <div className="pt-2 border-t border-slate-800">
              <button
                onClick={() => onTraceRoute(selectedConn.id, selectedConn.remoteAddr)}
                disabled={traceInFlight?.[selectedConn.id]}
                className="flex items-center space-x-1 px-2.5 py-1 rounded border text-[11px] transition bg-slate-800/80 border-slate-700 hover:border-slate-500 text-slate-300 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:border-slate-700"
              >
                <Route className="h-3 w-3" />
                <span>Trace Route</span>
              </button>

              {traceroute?.[selectedConn.id] && (
                <table className="mt-2 w-full text-left text-[11px]">
                  <thead>
                    <tr className="text-slate-500 uppercase text-[10px]">
                      <th className="py-1 pr-2">#</th>
                      <th className="py-1 pr-2">IP</th>
                      <th className="py-1 pr-2">RTT</th>
                      <th className="py-1 pr-2">Location</th>
                    </tr>
                  </thead>
                  <tbody>
                    {traceroute[selectedConn.id].map((hop) => (
                      <tr key={hop.hopNumber} className="text-slate-300">
                        <td className="py-0.5 pr-2">{hop.hopNumber}</td>
                        <td className="py-0.5 pr-2 font-mono">{hop.hopIp ?? '* * *'}</td>
                        <td className="py-0.5 pr-2">{hop.rttMs != null ? `${hop.rttMs.toFixed(1)}ms` : '-'}</td>
                        <td className="py-0.5 pr-2 text-slate-400">
                          {hop.hopIp
                            ? hop.location?.city
                              ? `${hop.location.city}, ${hop.location.country}`
                              : 'location unavailable'
                            : ''}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
