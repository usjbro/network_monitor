'use client';

import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  BarChart2,
  Globe,
  Layers,
  Network,
  Radio,
} from 'lucide-react';
import {
  OSILayerInfo,
  NetworkConnection,
  PacketFrame,
  SystemStats,
  TerminalTheme,
  ThemeConfig,
  OSILayerNumber,
} from '@/lib/types';
import { THEMES } from '@/lib/osi-engine';
import { mapConnectionClosedEvent, mapConnectionEvent, mapPacketEvent, mergeLayerStats } from '@/lib/agent-mapping';
import { applyEnrichmentEvent } from '@/lib/enrichment-mapping';
import { HeaderBar } from '@/components/HeaderBar';
import { DashboardView } from '@/components/DashboardView';
import { LayerDetailView } from '@/components/LayerDetailView';
import { ConnectionsView } from '@/components/ConnectionsView';
import { PacketStreamView } from '@/components/PacketStreamView';
import { ProtocolMatrixView } from '@/components/ProtocolMatrixView';
import { InstallModal } from '@/components/InstallModal';
import { CommandLineBar } from '@/components/CommandLineBar';

export default function TerminalApp() {
  // Application State
  const [activeTab, setActiveTab] = useState<'dashboard' | 'layer' | 'connections' | 'packets' | 'topology'>('dashboard');
  const [selectedLayerNum, setSelectedLayerNum] = useState<OSILayerNumber>(7);
  const [selectedTheme, setSelectedTheme] = useState<TerminalTheme>('sophisticated');
  const [isPaused, setIsPaused] = useState(false);
  const [crtEnabled, setCrtEnabled] = useState(false);
  const [isInstallOpen, setIsInstallOpen] = useState(false);
  const [agentConnected, setAgentConnected] = useState(false);
  const [liveLayers, setLiveLayers] = useState<Record<OSILayerNumber, Partial<OSILayerInfo>>>({} as never);
  const layers = useMemo(() => mergeLayerStats(liveLayers), [liveLayers]);

  // System Stats State
  const [stats, setStats] = useState<SystemStats>({
    hostname: 'osi-gw-01',
    interfaceName: 'eth0',
    interfaceSpeedMbps: 10000,
    duplexMode: 'Full Duplex',
    ipAddress: '192.168.1.104',
    macAddress: 'a4:83:e7:21:9b:10',
    cpuUsagePct: 14.2,
    memUsagePct: 38.5,
    uptimeSeconds: 84920,
    // No wire event currently carries system-level throughput stats (that's
    // tracked separately as future work) — seed at zero rather than
    // fabricating a "live" number.
    rxTotalMbps: 0,
    txTotalMbps: 0,
    rxPpsTotal: 1480,
    txPpsTotal: 740,
    totalPacketsCaptured: 184200,
  });

  // Connections & Packets State (populated from the live capture stream)
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [packets, setPackets] = useState<PacketFrame[]>([]);
  const [historyRx, setHistoryRx] = useState<number[]>([]);
  const [historyTx, setHistoryTx] = useState<number[]>([]);

  // Ownership enrichment state (spec Components §7's five-state Ownership
  // display, and §1's opt-in disclosure). `enrichmentMode` mirrors the
  // server-side EnrichmentClient's mode (kept in sync via the
  // /api/enrichment/control responses below, not read back from the
  // server); `disclosureText` drives a dismissible banner shown on every
  // enable per spec §1 ("re-shown on every enable").
  const [enrichmentMode, setEnrichmentMode] = useState<'off' | 'on-demand' | 'background'>('off');
  const [disclosureText, setDisclosureText] = useState<string | null>(null);
  const [lookingUpIds, setLookingUpIds] = useState<Set<string>>(new Set());
  const [unavailableIds, setUnavailableIds] = useState<Set<string>>(new Set());
  // Per-connectionId lookup timers, keyed outside React state since they're
  // an implementation detail (not rendered) and need synchronous
  // set/clear access from both requestLookup and the SSE handler below.
  const lookupTimers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  // Live Capture Stream — replaces the old simulation loop
  useEffect(() => {
    const source = new EventSource('/api/stream');

    source.onmessage = (event) => {
      // A single malformed/unexpected event (e.g. an agent binary built
      // before this UI, sending a payload missing a field the mappers now
      // require) must not take down the whole SSE handler — without this
      // guard, one throw here silently and permanently stops all future
      // events from ever being processed, since EventSource keeps calling
      // the same onmessage handler.
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'connection_status') {
          setAgentConnected(data.connected);
          return;
        }
        if (data.type === 'connection_update') {
          const connection = mapConnectionEvent(data.connection);
          setConnections((prev) => {
            const idx = prev.findIndex((c) => c.id === connection.id);
            if (idx === -1) return [connection, ...prev].slice(0, 200);
            const next = [...prev];
            next[idx] = connection;
            return next;
          });
        }
        if (data.type === 'connection_closed') {
          const id = mapConnectionClosedEvent(data);
          setConnections((prev) => prev.filter((c) => c.id !== id));
        }
        if (data.type === 'packet') {
          const packet = mapPacketEvent(data.packet);
          setPackets((prev) => [packet, ...prev.slice(0, 100)]);
        }
        if (data.type === 'layer_update') {
          setLiveLayers((prev) => {
            const next = { ...prev };
            for (const layer of data.layers) {
              next[layer.layer as OSILayerNumber] = layer;
            }
            return next;
          });
        }
        if (data.type === 'connection_enrichment') {
          setConnections((prev) => applyEnrichmentEvent(prev, data));
          // A result arrived for this connectionId — it's no longer "in
          // flight," and if it had previously timed out into "unavailable"
          // (e.g. a slow background-mode lookup that finished late), a real
          // result should supersede that state rather than leave it stuck.
          const timer = lookupTimers.current.get(data.connectionId);
          if (timer) {
            clearTimeout(timer);
            lookupTimers.current.delete(data.connectionId);
          }
          setLookingUpIds((prev) => {
            if (!prev.has(data.connectionId)) return prev;
            const next = new Set(prev);
            next.delete(data.connectionId);
            return next;
          });
          setUnavailableIds((prev) => {
            if (!prev.has(data.connectionId)) return prev;
            const next = new Set(prev);
            next.delete(data.connectionId);
            return next;
          });
        }
      } catch (err) {
        console.error('capture-agent: failed to process stream event', err, event.data);
      }
    };

    return () => source.close();
  }, []);

  // Sends a pause/resume control message to the capture agent via the relay.
  const sendControl = (type: 'pause' | 'resume') => {
    fetch('/api/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type }),
    });
  };

  // Toggles ownership enrichment mode via /api/enrichment/control (Task 9's
  // route, backed by Task 8's EnrichmentClient). Re-shows the disclosure
  // banner on every enable (on-demand or background), per spec §1.
  const enrichmentControl = async (action: string) => {
    const res = await fetch('/api/enrichment/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });
    const body = await res.json();
    if (body.disclosureText) setDisclosureText(body.disclosureText); // re-shown on every enable, per spec §1
    if (action === 'enable') setEnrichmentMode('on-demand');
    if (action === 'enable_background') setEnrichmentMode('background');
    if (action === 'disable') setEnrichmentMode('off');
    if (action === 'disable_background') setEnrichmentMode('on-demand');
    if (action === 'clear') {
      setEnrichmentMode('off');
      // Wipe any in-flight/unavailable bookkeeping along with the
      // server-side cache+log clear — a stale "Looking up…" or
      // "Unavailable" badge left over from before the clear would be
      // misleading once enrichment is off and the cache is gone.
      for (const timer of lookupTimers.current.values()) clearTimeout(timer);
      lookupTimers.current.clear();
      setLookingUpIds(new Set());
      setUnavailableIds(new Set());
    }
  };

  // How long to wait for a connection_enrichment event before treating a
  // lookup as "Unavailable" rather than leaving it on "Looking up…"
  // forever. Generous on purpose: RequestQueue can hold a lookup for up to
  // ~10s of jittered spacing (lib/enrichment/request-queue.ts) before even
  // dispatching it, on top of RdapClient's own 10s request timeout
  // (lib/enrichment/rdap-client.ts) — 25s covers both with margin.
  const LOOKUP_TIMEOUT_MS = 25_000;

  const requestLookup = (connectionId: string, remoteAddr: string) => {
    setLookingUpIds((prev) => new Set(prev).add(connectionId));
    setUnavailableIds((prev) => {
      if (!prev.has(connectionId)) return prev;
      const next = new Set(prev);
      next.delete(connectionId);
      return next;
    });

    const existing = lookupTimers.current.get(connectionId);
    if (existing) clearTimeout(existing);
    const timer = setTimeout(() => {
      lookupTimers.current.delete(connectionId);
      setLookingUpIds((prev) => {
        if (!prev.has(connectionId)) return prev;
        const next = new Set(prev);
        next.delete(connectionId);
        return next;
      });
      setUnavailableIds((prev) => new Set(prev).add(connectionId));
    }, LOOKUP_TIMEOUT_MS);
    lookupTimers.current.set(connectionId, timer);

    fetch('/api/enrichment/lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ connectionId, remoteAddr }),
    });
  };

  // Command Line Handler
  const handleExecuteCommand = (cmdStr: string) => {
    const parts = cmdStr.toLowerCase().split(' ');
    const mainCmd = parts[0];
    const arg1 = parts[1];

    if (mainCmd === 'dash' || mainCmd === 'dashboard') {
      setActiveTab('dashboard');
    } else if (mainCmd === 'layer' && arg1) {
      const num = parseInt(arg1, 10) as OSILayerNumber;
      if (num >= 1 && num <= 7) {
        setSelectedLayerNum(num);
        setActiveTab('layer');
      }
    } else if (mainCmd === 'conn' || mainCmd === 'sockets' || mainCmd === 'connections') {
      setActiveTab('connections');
    } else if (mainCmd === 'pcap' || mainCmd === 'packets') {
      setActiveTab('packets');
    } else if (mainCmd === 'matrix' || mainCmd === 'topology') {
      setActiveTab('topology');
    } else if (mainCmd === 'theme' && arg1) {
      if (THEMES[arg1 as TerminalTheme]) {
        setSelectedTheme(arg1 as TerminalTheme);
      }
    } else if (mainCmd === 'pause') {
      sendControl('pause');
    } else if (mainCmd === 'resume') {
      sendControl('resume');
    } else if (mainCmd === 'reset') {
      setConnections([]);
      setPackets([]);
    } else if (['install', 'macos', 'brew', 'curl', 'sw_vers'].includes(mainCmd)) {
      setIsInstallOpen(true);
    } else if (mainCmd === 'enrich' && arg1 === 'on') {
      enrichmentControl('enable');
    } else if (mainCmd === 'enrich' && arg1 === 'off') {
      enrichmentControl('disable');
    } else if (mainCmd === 'enrich' && arg1 === 'background' && parts[2] === 'on') {
      // `parts` comes from cmdStr.toLowerCase().split(' ') above, so this
      // three-token form is reachable — a two-token-only mainCmd/arg1 check
      // would silently drop the "on"/"off" token here.
      enrichmentControl('enable_background');
    } else if (mainCmd === 'enrich' && arg1 === 'background' && parts[2] === 'off') {
      enrichmentControl('disable_background');
    } else if (mainCmd === 'enrich' && arg1 === 'clear') {
      enrichmentControl('clear');
    }
  };

  const themeConfig = THEMES[selectedTheme];
  const activeLayer = layers.find((l) => l.layer === selectedLayerNum) || layers[0];

  return (
    <div className={`min-h-screen ${themeConfig.bg} ${themeConfig.text} font-mono flex flex-col justify-between overflow-x-hidden relative select-none transition-colors duration-300`}>
      {!agentConnected && (
        <div className="w-full bg-red-900/40 border-b border-red-700 text-red-200 text-sm px-4 py-2">
          capture agent not connected — run <code>./capture-agent</code> in <code>capture-agent/</code> (see capture-agent/README.md)
        </div>
      )}

      {/* Ownership enrichment disclosure — re-shown on every "enrich on" /
          "enrich background on", per spec §1. Simple dismissible banner,
          consistent with the "agent not connected" banner's styling above,
          not a full modal. */}
      {disclosureText && (
        <div className="w-full bg-amber-900/40 border-b border-amber-700 text-amber-100 text-sm px-4 py-2 flex items-start justify-between gap-3">
          <span>{disclosureText}</span>
          <button
            onClick={() => setDisclosureText(null)}
            className="shrink-0 text-amber-200 hover:text-white font-bold"
            aria-label="Dismiss disclosure"
          >
            [CLOSE]
          </button>
        </div>
      )}

      {/* CRT Scanline Overlay Effect */}
      {crtEnabled && <div className="pointer-events-none fixed inset-0 z-50 crt-scanlines opacity-40"></div>}

      <div className="flex-1 flex flex-col">
        {/* Header Navigation Bar */}
        <HeaderBar
          stats={stats}
          theme={themeConfig}
          onSelectTheme={setSelectedTheme}
          isPaused={isPaused}
          onTogglePause={() => {
            const next = !isPaused;
            setIsPaused(next);
            sendControl(next ? 'pause' : 'resume');
          }}
          onReset={() => {
            setConnections([]);
            setPackets([]);
          }}
          crtEnabled={crtEnabled}
          onToggleCrt={() => setCrtEnabled(!crtEnabled)}
          onOpenInstall={() => setIsInstallOpen(true)}
        />

        {/* View Navigation Tabs Bar (F1-F6) */}
        <nav className={`bg-slate-950 border-b ${themeConfig.border} px-3 py-1.5 flex items-center space-x-1 overflow-x-auto text-xs`}>
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'dashboard'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <BarChart2 className="h-3.5 w-3.5" />
            <span>F1: DASHBOARD</span>
          </button>

          <button
            onClick={() => setActiveTab('layer')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'layer'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            <span>F2: LAYER {selectedLayerNum} INSPECTOR</span>
          </button>

          <button
            onClick={() => setActiveTab('connections')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'connections'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Network className="h-3.5 w-3.5" />
            <span>F3: SOCKETS ({connections.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('packets')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'packets'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Radio className="h-3.5 w-3.5" />
            <span>F4: LIVE PCAP ({packets.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('topology')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'topology'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Globe className="h-3.5 w-3.5" />
            <span>F5: TOPOLOGY</span>
          </button>

        </nav>

        {/* Active View Container */}
        <main className="flex-1 max-w-7xl w-full mx-auto">
          {activeTab === 'dashboard' && (
            <DashboardView
              layers={layers}
              stats={stats}
              theme={themeConfig}
              onSelectLayer={(num) => {
                setSelectedLayerNum(num);
                setActiveTab('layer');
              }}
              historyRx={historyRx}
              historyTx={historyTx}
            />
          )}

          {activeTab === 'layer' && (
            <LayerDetailView
              layer={activeLayer}
              theme={themeConfig}
              onBack={() => setActiveTab('dashboard')}
              onSelectLayer={(num) => setSelectedLayerNum(num)}
            />
          )}

          {activeTab === 'connections' && (
            <ConnectionsView
              connections={connections}
              theme={themeConfig}
              enrichmentMode={enrichmentMode}
              onRequestLookup={requestLookup}
              lookingUpIds={lookingUpIds}
              unavailableIds={unavailableIds}
            />
          )}

          {activeTab === 'packets' && (
            <PacketStreamView
              packets={packets}
              theme={themeConfig}
              onClearPackets={() => setPackets([])}
            />
          )}

          {activeTab === 'topology' && (
            <ProtocolMatrixView
              layers={layers}
              theme={themeConfig}
              onSelectLayer={(num) => {
                setSelectedLayerNum(num);
                setActiveTab('layer');
              }}
            />
          )}
        </main>
      </div>

      {/* macOS Terminal & App Installer Modal */}
      <InstallModal
        isOpen={isInstallOpen}
        onClose={() => setIsInstallOpen(false)}
        theme={themeConfig}
      />

      {/* Interactive Bottom CLI Command Bar */}
      <CommandLineBar theme={themeConfig} onExecuteCommand={handleExecuteCommand} />
    </div>
  );
}
