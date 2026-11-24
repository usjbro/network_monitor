'use client';

import React, { useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, Users } from 'lucide-react';
import { Conversation, Endpoint, RollupState, ThemeConfig } from '@/lib/types';
import { formatBytes, formatSpeed } from '@/lib/osi-engine';
import { RollupRanking, rankRows, rankValue } from '@/lib/rollup-rank';

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
  historyComplete: boolean;
}

const fmt = (n: number) => n.toLocaleString('en-US');

// The Rank by choices, and the column each one sorts (P6).
const RANKINGS: RollupRanking[] = ['bytes', 'packets', 'rate', 'recent'];
const RANK_COLUMN: Record<RollupRanking, SortKey> = {
  bytes: 'bytes',
  packets: 'packets',
  rate: 'rate',
  recent: 'lastSeen',
};

const EARLIER_HISTORY_TIP =
  'Earlier history may have been evicted. The rate can be low in the second this row returned.';

// Marks a total that may be missing earlier history. Rates never carry it.
const AtLeast: React.FC<{ show: boolean }> = ({ show }) =>
  show ? (
    <span title={EARLIER_HISTORY_TIP} className="mr-0.5 text-amber-400 cursor-help">
      ≥
    </span>
  ) : null;

function endpointToRow(e: Endpoint): Row {
  // Names are attacker-controlled packet content: rendered only as React text.
  // The PTR line is dropped when it repeats the observed name.
  const showPtr = e.remoteHostname && e.remoteHostname.toLowerCase() !== e.observedName?.toLowerCase();
  return {
    key: e.host,
    name: (
      <span>
        <span className="font-bold text-slate-200">{e.host}</span>
        {e.observedName && (
          <span className="block break-all text-[10px] text-slate-500" title="Learned from observed DNS">
            <span
              className="mr-1 rounded border border-slate-600 px-1 text-[9px] font-semibold uppercase text-slate-400"
              title="Learned from observed DNS"
            >
              DNS
            </span>
            {e.observedName}
          </span>
        )}
        {showPtr && <span className="block break-all text-[10px] text-slate-500">{e.remoteHostname}</span>}
      </span>
    ),
    searchText: `${e.host} ${e.observedName ?? ''} ${e.remoteHostname ?? ''} ${e.processName}`,
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
    historyComplete: e.historyComplete,
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
        {c.remoteHostname && <span className="block break-all text-[10px] text-slate-500">{c.remoteHostname}</span>}
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
    historyComplete: c.historyComplete,
  };
}

function sortValue(row: Row, key: SortKey): number | string {
  switch (key) {
    case 'name':
      return row.key;
    case 'process':
      return `${row.processName.toLowerCase()}\0${row.pid.toString().padStart(10, '0')}`;
    case 'bytes':
    case 'packets':
    case 'rate':
      // RX/TX is one paired column, so each sorts by its sum, as Rank by does.
      return rankValue(row, key);
    case 'flowCount':
      return row.flowCount;
    case 'firstSeen':
      return row.firstSeenMs;
    case 'lastSeen':
      return rankValue(row, 'recent');
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

// What an empty table says. Undefined: rows are tracked, none is displayed.
function emptyText(table: RollupState<unknown>, mode: 'endpoints' | 'conversations'): string | undefined {
  switch (table.status) {
    case 'waiting':
      return 'Waiting for the first update.';
    case 'agent-too-old':
      return 'The running capture agent is older than this page. Restart the agent.';
    case 'unreadable':
      return "This table's data could not be read.";
    case 'ready':
      return table.bounds.tracked === 0 ? `No ${mode} observed yet.` : undefined;
  }
}

interface EndpointsViewProps {
  endpoints: RollupState<Endpoint>;
  conversations: RollupState<Conversation>;
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
  // Rank by and the column sort are per table and not persisted. Default is
  // bytes descending: "what people actually scan for" per the acceptance
  // criteria. Rank by sets the matching column sort (P6); clicking a column
  // never changes Rank by.
  const [views, setViews] = useState<Record<typeof mode, { rankBy: RollupRanking; sortKey: SortKey; sortDir: SortDir }>>({
    endpoints: { rankBy: 'bytes', sortKey: 'bytes', sortDir: 'desc' },
    conversations: { rankBy: 'bytes', sortKey: 'bytes', sortDir: 'desc' },
  });
  const { rankBy, sortKey, sortDir } = views[mode];
  const updateView = (patch: Partial<(typeof views)[typeof mode]>) =>
    setViews((prev) => ({ ...prev, [mode]: { ...prev[mode], ...patch } }));
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const table = mode === 'endpoints' ? endpoints : conversations;
  const noun = mode === 'endpoints' ? 'hosts' : 'conversations';

  // Every row the agent sent for this table.
  const received = useMemo(() => {
    if (mode === 'endpoints') return endpoints.status === 'ready' ? endpoints.rows.map(endpointToRow) : [];
    return conversations.status === 'ready' ? conversations.rows.map(conversationToRow) : [];
  }, [mode, endpoints, conversations]);

  const hasSearch = searchTerm !== '';
  const topN = table.status === 'ready' ? table.bounds.topN : 0;

  // With a search term: every received row that matches. Without: the first
  // topN by Rank by. The column sort then reorders only what is displayed.
  const chosen = useMemo(() => {
    if (hasSearch) {
      const term = searchTerm.toLowerCase();
      return received.filter((row) => row.searchText.toLowerCase().includes(term));
    }
    return rankRows(received, rankBy).slice(0, topN);
  }, [received, hasSearch, searchTerm, rankBy, topN]);

  const sorted = useMemo(() => {
    // Array.prototype.sort is stable: ties keep the order chosen above.
    const copy = [...chosen];
    copy.sort((a, b) => {
      const av = sortValue(a, sortKey);
      const bv = sortValue(b, sortKey);
      const cmp = typeof av === 'string' ? av.localeCompare(bv as string) : av - (bv as number);
      return sortDir === 'desc' ? -cmp : cmp;
    });
    return copy;
  }, [chosen, sortKey, sortDir]);

  const handleSort = (key: SortKey) => {
    if (key === sortKey) {
      updateView({ sortDir: sortDir === 'desc' ? 'asc' : 'desc' });
    } else {
      updateView({ sortKey: key, sortDir: 'desc' });
    }
  };

  const handleRankBy = (ranking: RollupRanking) => updateView({ rankBy: ranking, sortKey: RANK_COLUMN[ranking], sortDir: 'desc' });

  const empty = emptyText(table, mode);

  // Looked up among all received rows (P7), not the displayed ones.
  const selected = selectedKey === null ? null : (received.find((row) => row.key === selectedKey) ?? null);
  const selectedGone = selectedKey !== null && selected === null && table.status === 'ready';

  let countsLine: string | undefined;
  let sortNote: string | undefined;
  let noMatch: string | undefined;
  if (table.status === 'ready') {
    const b = table.bounds;
    const tracked = `${fmt(b.tracked)} ${noun} tracked${b.sinceMs === null ? '' : ` since ${fmt(b.sinceMs)} ms`}.`;
    countsLine = hasSearch
      ? `${fmt(sorted.length)} matches in ${fmt(received.length)} received; ${tracked}`
      : `Showing ${fmt(sorted.length)} of ${fmt(received.length)} received; ${tracked}`;
    if (hasSearch) {
      sortNote = 'sorted within matching received rows';
      const unsent = b.tracked - received.length;
      noMatch = `No match among the ${fmt(received.length)} rows received${unsent > 0 ? `; ${fmt(unsent)} more are tracked but not sent` : ''}.`;
    } else if (!(sortKey === RANK_COLUMN[rankBy] && sortDir === 'desc')) {
      sortNote = `sorted within the top ${fmt(b.topN)} by ${rankBy}`;
    }
  }
  const emptyMessage = hasSearch && noMatch ? noMatch : empty;
  const readyBounds = table.status === 'ready' ? table.bounds : null;
  const capitalNoun = noun.charAt(0).toUpperCase() + noun.slice(1);

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
          placeholder="Search received rows…"
          className="flex-1 min-w-[200px] bg-transparent text-slate-200 placeholder-slate-600 focus:outline-none text-xs border-l border-slate-800 pl-2"
        />
      </div>

      {readyBounds && (
        <div className="space-y-1 text-[11px] text-slate-500">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <div>{countsLine}</div>
            <label className="flex items-center gap-1">
              <span>Rank by</span>
              <select
                aria-label="Rank by"
                value={rankBy}
                onChange={(e) => handleRankBy(e.target.value as RollupRanking)}
                className="rounded border border-slate-800 bg-slate-900 px-1 py-0.5 text-slate-200"
              >
                {RANKINGS.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            {sortNote && <div>{sortNote}</div>}
          </div>
          {readyBounds.evictions > 0 && (
            <div className="text-amber-400">
              {`${fmt(readyBounds.evictions)} evictions (cap ${fmt(readyBounds.cap)}): least recently active ${noun} were dropped; their totals (${formatBytes(readyBounds.evicted.rxBytes + readyBounds.evicted.txBytes)}) are not in any row.`}
            </div>
          )}
          {readyBounds.horizonMs !== null && (
            <div className="text-amber-400">{`${capitalNoun} last active at or before ${fmt(readyBounds.horizonMs)} ms may be missing.`}</div>
          )}
          {readyBounds.unkeyed > 0 && (
            <div className="text-amber-400">{`${fmt(readyBounds.unkeyed)} packets had an unreadable address and are not counted.`}</div>
          )}
        </div>
      )}

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
                <td className="p-2.5 max-w-xs">{row.name}</td>
                <td className="p-2.5 text-slate-300">
                  <div className="font-bold">{row.processName}</div>
                  <div className="text-[10px] text-slate-500">PID: {row.pid}</div>
                </td>
                <td className="p-2.5 text-right text-slate-300">
                  <div>
                    <AtLeast show={!row.historyComplete} />
                    {formatBytes(row.rxBytesTotal)} / {formatBytes(row.txBytesTotal)}
                  </div>
                </td>
                <td className="p-2.5 text-right text-slate-300">
                  <AtLeast show={!row.historyComplete} />
                  {fmt(row.rxPacketsTotal)} / {fmt(row.txPacketsTotal)}
                </td>
                <td className="p-2.5 text-right">
                  <div className="text-emerald-400 font-bold">{formatSpeed(row.rxSpeed)}</div>
                  <div className="text-sky-400 font-bold">{formatSpeed(row.txSpeed)}</div>
                </td>
                <td className="p-2.5 text-right text-slate-300">
                  <AtLeast show={!row.historyComplete} />
                  {fmt(row.flowCount)}
                </td>
                <td className="p-2.5 text-right text-slate-500 text-[10px]">
                  {fmt(row.firstSeenMs)} ms
                  {!row.historyComplete && <span className="block">may be earlier</span>}
                </td>
                <td className="p-2.5 text-right text-slate-500 text-[10px]">{fmt(row.lastSeenMs)} ms</td>
                {mode === 'conversations' && (
                  <td className="p-2.5 text-right text-slate-500 text-[10px]">
                    <AtLeast show={!row.historyComplete} />
                    {fmt(row.durationMs ?? 0)} ms
                  </td>
                )}
              </tr>
            ))}
            {sorted.length === 0 && emptyMessage && (
              <tr>
                <td colSpan={mode === 'conversations' ? 9 : 8} className="p-8 text-center text-slate-500">
                  {emptyMessage}
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
      {selectedGone && (
        <div className={`p-3.5 rounded border ${theme.border} ${theme.cardBg} text-slate-500`}>
          <div>No longer among the received rows</div>
          <div className="break-all text-slate-300">{selectedKey}</div>
        </div>
      )}
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
