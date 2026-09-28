'use client';

import React, { useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, Users } from 'lucide-react';
import { Conversation, Endpoint, ThemeConfig } from '@/lib/types';
import { formatBytes, formatSpeed } from '@/lib/osi-engine';

type SortKey =
  | 'name'
  | 'process'
  | 'bytes'
  | 'packets'
  | 'rate'
  | 'flowCount'
  | 'firstSeen'
  | 'lastSeen'
  | 'duration';
type SortDir = 'asc' | 'desc';

// Shared shape both Endpoints and Conversations reduce to for sorting/
// rendering — JAM-14's acceptance criteria treats them as the same table
// with a different identity column, not two unrelated views.
interface Row {
  key: string;
  name: React.ReactNode;
  searchText: string;
  rxBytesTotal: number;
  txBytesTotal: number;
  rxPacketsTotal: number;
  txPacketsTotal: number;
  rxSpeed: number;
  txSpeed: number;
  flowCount: number;
  firstSeenMs: number;
  lastSeenMs: number;
  durationMs?: number;
  processName: string;
  pid: number;
  ja3Label?: string;
  host: string; // the address enrichment lookups key on (always the remote side)
  enrichment?: Endpoint['enrichment'];
}

function endpointToRow(e: Endpoint): Row {
  return {
    key: e.host,
    name: (
      <span>
        <span className="font-bold text-slate-200">{e.host}</span>
        {e.remoteHostname && <span className="block text-[10px] text-slate-500">{e.remoteHostname}</span>}
      </span>
    ),
    searchText: `${e.host} ${e.remoteHostname ?? ''} ${e.processName}`,
    rxBytesTotal: e.rxBytesTotal,
    txBytesTotal: e.txBytesTotal,
    rxPacketsTotal: e.rxPacketsTotal,
    txPacketsTotal: e.txPacketsTotal,
    rxSpeed: e.rxSpeed,
    txSpeed: e.txSpeed,
    flowCount: e.flowCount,
    firstSeenMs: e.firstSeenMs,
    lastSeenMs: e.lastSeenMs,
    processName: e.processName,
    pid: e.pid,
    ja3Label: e.ja3Label,
    host: e.host,
    enrichment: e.enrichment,
  };
}

function conversationToRow(c: Conversation): Row {
  return {
    key: `${c.localAddr}|${c.remoteAddr}`,
    name: (
      <span>
        <span className="text-slate-400">{c.localAddr}</span>
        <span className="text-slate-600"> ↔ </span>
        <span className="font-bold text-slate-200">{c.remoteAddr}</span>
        {c.remoteHostname && <span className="block text-[10px] text-slate-500">{c.remoteHostname}</span>}
      </span>
    ),
    searchText: `${c.localAddr} ${c.remoteAddr} ${c.remoteHostname ?? ''} ${c.processName}`,
    rxBytesTotal: c.rxBytesTotal,
    txBytesTotal: c.txBytesTotal,
    rxPacketsTotal: c.rxPacketsTotal,
    txPacketsTotal: c.txPacketsTotal,
    rxSpeed: c.rxSpeed,
    txSpeed: c.txSpeed,
    flowCount: c.flowCount,
    firstSeenMs: c.firstSeenMs,
    lastSeenMs: c.lastSeenMs,
    durationMs: c.durationMs,
    processName: c.processName,
    pid: c.pid,
    ja3Label: c.ja3Label,
    host: c.remoteAddr,
    enrichment: c.enrichment,
  };
}

function sortValue(row: Row, key: SortKey): number | string {
  switch (key) {
    case 'name':
      return row.key;
    case 'process':
      return `${row.processName.toLowerCase()}\0${row.pid.toString().padStart(10, '0')}`;
    case 'bytes':
      return row.rxBytesTotal + row.txBytesTotal;
    case 'packets':
      return row.rxPacketsTotal + row.txPacketsTotal;
    case 'rate':
      // RX/TX is one paired column, so sort by its combined throughput.
      return row.rxSpeed + row.txSpeed;
    case 'flowCount':
      return row.flowCount;
    case 'firstSeen':
      return row.firstSeenMs;
    case 'lastSeen':
      return row.lastSeenMs;
    case 'duration':
      return row.durationMs ?? 0;
  }
}

interface SortHeaderProps {
  label: string;
  ownKey: SortKey;
  sortKey: SortKey;
  sortDir: SortDir;
  onSort: (key: SortKey) => void;
  align?: 'left' | 'right';
}

const SortHeader: React.FC<SortHeaderProps> = ({ label, ownKey, sortKey, sortDir, onSort, align = 'left' }) => (
  <th
    className={`p-2.5 cursor-pointer select-none hover:text-slate-200 ${align === 'right' ? 'text-right' : 'text-left'}`}
    onClick={() => onSort(ownKey)}
  >
    <span className="inline-flex items-center gap-1">
      {label}
      {sortKey === ownKey && (sortDir === 'desc' ? <ArrowDown className="h-3 w-3" /> : <ArrowUp className="h-3 w-3" />)}
    </span>
  </th>
);

interface EndpointsViewProps {
  endpoints: Endpoint[];
  conversations: Conversation[];
  theme: ThemeConfig;
  enrichmentMode?: 'off' | 'on-demand' | 'background';
  onRequestLookup?: (host: string) => void;
  lookingUpIds?: Set<string>;
  unavailableIds?: Set<string>;
}

export const EndpointsView: React.FC<EndpointsViewProps> = ({
  endpoints,
  conversations,
  theme,
  enrichmentMode,
  onRequestLookup,
  lookingUpIds,
  unavailableIds,
}) => {
  const [mode, setMode] = useState<'endpoints' | 'conversations'>('endpoints');
  // Default sort: bytes descending — "what people actually scan for" per
  // the acceptance criteria.
  const [sortKey, setSortKey] = useState<SortKey>('bytes');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const rows = useMemo(
    () => (mode === 'endpoints' ? endpoints.map(endpointToRow) : conversations.map(conversationToRow)),
    [mode, endpoints, conversations],
  );

  const filtered = useMemo(
    () => rows.filter((row) => row.searchText.toLowerCase().includes(searchTerm.toLowerCase())),
    [rows, searchTerm],
  );

  const sorted = useMemo(() => {
    const copy = [...filtered];
    copy.sort((a, b) => {
      const av = sortValue(a, sortKey);
      const bv = sortValue(b, sortKey);
      const cmp = typeof av === 'string' ? av.localeCompare(bv as string) : av - (bv as number);
      return sortDir === 'desc' ? -cmp : cmp;
    });
    return copy;
  }, [filtered, sortKey, sortDir]);

  const handleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortDir((prev) => (prev === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  };

  const selected = sorted.find((row) => row.key === selectedKey) ?? null;

  return (
    <div className="space-y-3 font-mono text-xs p-3">
      <div className="flex flex-wrap items-center justify-between gap-2 bg-slate-950 p-2.5 rounded border border-slate-800">
        <div className="flex items-center space-x-1">
          <Users className="h-3.5 w-3.5 opacity-50 mr-1" />
          {(['endpoints', 'conversations'] as const).map((m) => (
            <button
              key={m}
              onClick={() => {
                setMode(m);
                setSelectedKey(null);
              }}
              className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase transition ${
                mode === m ? theme.highlight : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {m}
            </button>
          ))}
        </div>
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder={mode === 'endpoints' ? 'Filter by host or process...' : 'Filter by address or process...'}
          className="flex-1 min-w-[200px] bg-transparent text-slate-200 placeholder-slate-600 focus:outline-none text-xs border-l border-slate-800 pl-2"
        />
      </div>

      <div className="text-[11px] text-slate-500">
        {mode === 'endpoints'
          ? `${sorted.length} host(s) — totals aggregated in the agent, surviving flow eviction`
          : `${sorted.length} conversation(s) between a local and remote host`}
      </div>

      <div className={`rounded border ${theme.border} ${theme.cardBg} overflow-x-auto`}>
        <table className="w-full text-left border-collapse min-w-[820px]">
          <thead>
            <tr className="bg-slate-950/80 text-slate-400 border-b border-slate-800 text-[10px] uppercase">
              <SortHeader label={mode === 'endpoints' ? 'Host' : 'Local ↔ Remote'} ownKey="name" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
              <SortHeader label="Process (PID)" ownKey="process" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
              <SortHeader label="Bytes (RX/TX)" ownKey="bytes" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} align="right" />
              <SortHeader label="Packets" ownKey="packets" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} align="right" />
              <SortHeader label="Rate (RX/TX)" ownKey="rate" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} align="right" />
              <SortHeader label="Flows" ownKey="flowCount" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} align="right" />
              <SortHeader label="First Seen" ownKey="firstSeen" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} align="right" />
              <SortHeader label="Last Seen" ownKey="lastSeen" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} align="right" />
              {mode === 'conversations' && (
                <SortHeader label="Duration" ownKey="duration" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} align="right" />
              )}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {sorted.map((row) => (
              <tr
                key={row.key}
                onClick={() => setSelectedKey(row.key)}
                className={`hover:bg-slate-900/80 transition cursor-pointer ${
                  selectedKey === row.key ? 'bg-slate-900/90 font-semibold' : ''
                }`}
              >
                <td className="p-2.5">{row.name}</td>
                <td className="p-2.5 text-slate-300">
                  <div className="font-bold">{row.processName}</div>
                  <div className="text-[10px] text-slate-500">PID: {row.pid}</div>
                </td>
                <td className="p-2.5 text-right text-slate-300">
                  <div>{formatBytes(row.rxBytesTotal)} / {formatBytes(row.txBytesTotal)}</div>
                </td>
                <td className="p-2.5 text-right text-slate-300">
                  {row.rxPacketsTotal.toLocaleString()} / {row.txPacketsTotal.toLocaleString()}
                </td>
                <td className="p-2.5 text-right">
                  <div className="text-emerald-400 font-bold">{formatSpeed(row.rxSpeed)}</div>
                  <div className="text-sky-400 font-bold">{formatSpeed(row.txSpeed)}</div>
                </td>
                <td className="p-2.5 text-right text-slate-300">{row.flowCount}</td>
                <td className="p-2.5 text-right text-slate-500 text-[10px]">{row.firstSeenMs.toLocaleString()} ms</td>
                <td className="p-2.5 text-right text-slate-500 text-[10px]">{row.lastSeenMs.toLocaleString()} ms</td>
                {mode === 'conversations' && (
                  <td className="p-2.5 text-right text-slate-500 text-[10px]">{(row.durationMs ?? 0).toLocaleString()} ms</td>
                )}
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr>
                <td colSpan={mode === 'conversations' ? 9 : 8} className="p-8 text-center text-slate-500">
                  No {mode} observed yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Ownership section — one lookup per host, shown once here rather
          than once per flow (JAM-14's enrichment scope item). Same
          five-state discipline as ConnectionsView's own Ownership panel,
          minus GeoIP: there's no existing general per-host geoIP lookup to
          reuse (lib/geoip.ts is wired only to traceroute hops today), so
          it's deliberately not included here. */}
      {selected && (
        <div className={`p-3.5 rounded border ${theme.border} ${theme.cardBg} space-y-2`}>
          <div className="flex items-center justify-between border-b border-slate-800 pb-2 font-bold text-slate-200">
            <span>OWNERSHIP FOR {selected.host}</span>
            {selected.ja3Label && <span className="text-[11px] text-slate-500 font-normal">JA3: {selected.ja3Label}</span>}
          </div>
          <div className="pt-1">
            {(!enrichmentMode || enrichmentMode === 'off') ? (
              <div className="text-slate-500">Enrichment disabled — enable with <code>enrich on</code> in the command bar.</div>
            ) : lookingUpIds?.has(selected.host) ? (
              <div className="text-slate-400">Looking up…</div>
            ) : unavailableIds?.has(selected.host) ? (
              <div className="text-slate-500">Unavailable — no ownership data returned for this address.</div>
            ) : !selected.enrichment ? (
              <button
                onClick={() => onRequestLookup?.(selected.host)}
                className="px-2 py-1 rounded text-[11px] font-bold bg-slate-800 hover:bg-slate-700 text-slate-200"
              >
                Not yet looked up — click to look up
              </button>
            ) : !selected.enrichment.org && !selected.enrichment.asn && !selected.enrichment.registrant ? (
              <div className="text-slate-500">Unavailable — no ownership data returned for this address.</div>
            ) : (
              <div className="text-slate-300">
                Org: <span>{selected.enrichment.org ?? '—'}</span> · ASN: {selected.enrichment.asn ?? '—'}
                {selected.enrichment.registrant && <> · Registrant: <span>{selected.enrichment.registrant}</span></>}
                <span className="text-slate-500"> · as of {selected.enrichment.fetchedAt}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
