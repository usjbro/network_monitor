'use client';

// KAN-130 flow ladder (spec docs/superpowers/specs/2026-11-20-flow-sequence-diagram-design.md
// D6; plan Task 4). One row per entry of lib/flow-ladder.ts's buildLadder:
// time down the page, the local host's lifeline on the left and the remote
// host's on the right, one arrow per retained TCP segment. Rows are DOM
// elements so the view is keyboard driven and needs no charting library.
// Label text is rendered as React text only, never as markup.

import React, { useMemo, useRef, useState } from 'react';
import { buildLadder, linkSamples, type LadderRow } from '@/lib/flow-ladder';
import { STATIC_LAYER_INFO } from '@/lib/osi-engine';
import type { TcpGraphState } from '@/lib/tcp-graphs';
import { clock } from '@/lib/time-axis';
import { TCP_SAMPLE_FLAG as F, TCP_SAMPLE_MARK as M, type NetworkConnection, type PacketFrame, type ThemeConfig } from '@/lib/types';

interface FlowLadderViewProps {
  state: TcpGraphState;
  /** The flow's connection, for the lifeline labels and the packet-view match. */
  connection?: NetworkConnection;
  /** The packet view's buffered frames (sampled packet events). */
  packets: PacketFrame[];
  /** `buffer packets <n>`, quoted when an arrow is not in the packet view. */
  bufferLimit: number;
  theme: ThemeConfig;
  /** Opens a frame in the packet view; returns why it could not, or null on success. */
  onOpenFrame: (packetId: string) => string | null;
  /** For tests: the time zone the horizon is shown in. */
  timeZone?: string;
}

type Arrow = Extract<LadderRow, { kind: 'arrow' }>;

const count = (n: number) => n.toLocaleString('en-US');

function bytes(n: number): string {
  if (n < 1000) return `${n} B`;
  if (n < 1e6) return `${(n / 1e3).toFixed(2)} kB`;
  if (n < 1e9) return `${(n / 1e6).toFixed(2)} MB`;
  return `${(n / 1e9).toFixed(2)} GB`;
}

function sideText(arrow: string, side: { data: number; bytes: number; acks: number }): string | null {
  const parts: string[] = [];
  if (side.data > 0) parts.push(`${count(side.data)} data, ${bytes(side.bytes)}`);
  if (side.acks > 0) parts.push(`${count(side.acks)} ACK${side.acks === 1 ? '' : 's'}`);
  return parts.length > 0 ? `${arrow} ${parts.join(', ')}` : null;
}

function rowText(row: Exclude<LadderRow, Arrow>): string {
  switch (row.kind) {
    case 'run':
      return [
        `${count(row.segments)} segments over ${(row.spanUs / 1e6).toFixed(3)} s`,
        sideText('→', row.out),
        sideText('←', row.in),
      ].filter(Boolean).join(' · ');
    case 'gap':
      return `${count(row.missing)} segment${row.missing === 1 ? '' : 's'} not retained`;
    case 'elided':
      return `${count(row.rows)} rows not shown (${count(row.segments)} segments)`;
  }
}

function colourOf(row: Arrow): string {
  const s = row.sample;
  if ((s.mark & M.RETRANSMIT) !== 0 || (s.flags & F.RST) !== 0) return 'text-red-400';
  if (row.label?.kind.startsWith('tls_')) return STATIC_LAYER_INFO[6].color;
  if (row.label?.kind.startsWith('http_')) return STATIC_LAYER_INFO[7].color;
  return STATIC_LAYER_INFO[4].color;
}

const RELATIVE_TO: Record<string, string> = {
  isn: 'sequence relative to ISN',
  firstSeen: 'sequence relative to first seen segment',
};

export const FlowLadderView: React.FC<FlowLadderViewProps> = ({ state, connection, packets, bufferLimit, theme, onOpenFrame, timeZone }) => {
  const rows = useMemo(() => buildLadder(state), [state]);
  const links = useMemo(() => (connection ? linkSamples(state, packets, connection) : new Map<number, string>()), [state, packets, connection]);
  const [selected, setSelected] = useState<number | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);

  const first = state.head[0] ?? state.samples[0];
  const t0 = first?.tUs ?? 0;
  const held = state.head.length + state.samples.length;
  const selectedArrow = rows.find((r): r is Arrow => r.kind === 'arrow' && r.index === selected) ?? null;

  function activate(row: Arrow) {
    setSelected(row.index);
    const id = links.get(row.index);
    setNotice(id ? onOpenFrame(id) : null);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    const all = Array.from(listRef.current?.querySelectorAll<HTMLElement>('[data-ladder-row]') ?? []);
    const at = all.indexOf(document.activeElement as HTMLElement);
    let next: number | null = null;
    if (e.key === 'ArrowDown') next = Math.min(all.length - 1, at + 1);
    else if (e.key === 'ArrowUp') next = Math.max(0, at - 1);
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = all.length - 1;
    else if (e.key === 'Enter' && at >= 0) {
      const row = rows.find((r): r is Arrow => r.kind === 'arrow' && String(r.index) === all[at].dataset.index);
      if (row) {
        e.preventDefault();
        activate(row);
      }
      return;
    } else return;
    e.preventDefault();
    if (next !== null && next >= 0) all[next]?.focus();
  }

  const status =
    state.found === false
      ? held > 0 ? 'The agent no longer tracks this flow; showing the segments already fetched.' : 'No segment history for this flow.'
      : held === 0 ? (state.found === null ? 'Loading segments…' : 'No segments yet for this flow.') : null;
  const local = connection ? `${connection.localAddr}:${connection.localPort}` : 'local';
  const remote = connection ? `${connection.remoteAddr}:${connection.remotePort}` : 'remote';

  return (
    <div data-testid="flow-ladder" className="space-y-2 min-w-0 font-mono">
      <div data-testid="ladder-header" className="text-[11px] text-slate-400 space-y-0.5">
        <div className="truncate">{state.connectionId}</div>
        <div>
          {RELATIVE_TO[state.meta?.relativeTo ?? ''] ?? 'sequence base unknown'}
          {first && <> · segments since {clock(t0 / 1000, timeZone)}.{String(Math.floor(t0 / 1000) % 1000).padStart(3, '0')}</>}
        </div>
        <div className="text-slate-500">complete within the retained window; not sampled</div>
      </div>
      {status && <div data-testid="ladder-status" className="text-[11px] text-slate-400">{status}</div>}
      {notice && <div data-testid="ladder-notice" role="status" className="text-[11px] text-amber-400">{notice}</div>}

      {rows.length > 0 && (
        <>
          <div className="flex text-[10px] text-slate-400 min-w-0">
            <span className="w-[11ch] shrink-0" />
            <div className="flex flex-1 min-w-0 justify-between gap-2">
              <span data-testid="ladder-local" className="truncate">{local}</span>
              <span data-testid="ladder-remote" className="truncate text-right">{remote}</span>
            </div>
          </div>
          <div ref={listRef} role="list" aria-label="Flow ladder: arrow keys move, Enter opens a frame in the packet view" onKeyDown={onKeyDown} className="min-w-0">
            {rows.map((row, position) => {
              // Roving focus: only the first row is in the tab order.
              const tabIndex = position === 0 ? 0 : -1;
              if (row.kind !== 'arrow') {
                return (
                  <div
                    key={`${row.kind}-${row.kind === 'run' ? row.firstIndex : row.kind === 'gap' ? row.afterIndex : 'elided'}`}
                    role="listitem"
                    tabIndex={tabIndex}
                    data-ladder-row
                    data-testid={`ladder-row-${row.kind}`}
                    className="flex min-w-0 text-[10px] text-slate-500 outline-none focus:bg-slate-800/60"
                  >
                    <span className="w-[11ch] shrink-0" />
                    <span className="flex-1 min-w-0 border-x border-dashed border-slate-700 px-2 py-0.5 italic truncate" title={rowText(row)}>
                      {rowText(row)}
                    </span>
                  </div>
                );
              }
              const linked = links.has(row.index);
              const out = row.sample.outbound;
              return (
                <div key={`arrow-${row.index}`} role="listitem" className="min-w-0">
                <button
                  type="button"
                  tabIndex={tabIndex}
                  data-ladder-row
                  data-index={row.index}
                  data-testid="ladder-row-arrow"
                  data-direction={out ? 'out' : 'in'}
                  aria-label={`${out ? 'outbound' : 'inbound'}: ${row.text}${linked ? ' (in packet view)' : ''}`}
                  onClick={() => activate(row)}
                  className={`flex w-full min-w-0 text-left outline-none focus:bg-slate-800/60 hover:bg-slate-900 ${selected === row.index ? 'bg-slate-900' : ''}`}
                >
                  <span data-testid="ladder-time" className="w-[11ch] shrink-0 text-[10px] text-slate-500 pt-0.5">
                    +{((row.sample.tUs - t0) / 1000).toFixed(3)} ms
                  </span>
                  <span className="flex-1 min-w-0 border-x border-slate-600 px-1">
                    <span className={`flex items-center gap-1 min-w-0 ${out ? '' : 'flex-row-reverse'}`}>
                      <span data-testid="ladder-text" title={row.text} className={`truncate text-[11px] ${colourOf(row)}`}>{row.text}</span>
                      {linked && <span data-testid="ladder-linked" title="in packet view" className={`shrink-0 text-[9px] ${theme.accent}`}>↗</span>}
                    </span>
                    <span className={`flex items-center ${colourOf(row)}`} aria-hidden="true">
                      {out ? <><span className="flex-1 border-t border-current" /><span className="text-[9px] leading-none">▶</span></>
                        : <><span className="text-[9px] leading-none">◀</span><span className="flex-1 border-t border-current" /></>}
                    </span>
                  </span>
                </button>
                </div>
              );
            })}
          </div>
        </>
      )}

      {selectedArrow && (
        <div data-testid="ladder-details" className="text-[10px] text-slate-400 border-t border-slate-800 pt-1 space-y-0.5 break-words">
          <div>
            +{((selectedArrow.sample.tUs - t0) / 1000).toFixed(3)} ms · {selectedArrow.sample.outbound ? 'outbound' : 'inbound'} · {selectedArrow.text} ·
            seq {selectedArrow.sample.seq} · ack {selectedArrow.sample.ack} · win {selectedArrow.sample.win} · len {selectedArrow.sample.len}
          </div>
          {!links.has(selectedArrow.index) && (
            <div>Not in the packet view: packet events are sampled at 100 per second and the view keeps the newest {bufferLimit}.</div>
          )}
        </div>
      )}
    </div>
  );
};
