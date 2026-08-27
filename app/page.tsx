'use client';

import React, { useState, useEffect, useMemo } from 'react';
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
import { mapConnectionEvent, mapPacketEvent, mergeLayerStats } from '@/lib/agent-mapping';
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

  // Live Capture Stream — replaces the old simulation loop
  useEffect(() => {
    const source = new EventSource('/api/stream');

    source.onmessage = (event) => {
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
    };

    return () => source.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sends a pause/resume control message to the capture agent via the relay.
  const sendControl = (type: 'pause' | 'resume') => {
    fetch('/api/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type }),
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
            <ConnectionsView connections={connections} theme={themeConfig} />
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
