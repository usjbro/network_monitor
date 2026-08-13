'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  Activity,
  BarChart2,
  Globe,
  Layers,
  Network,
  Radio,
  Server,
  Terminal,
  Tv,
  Zap,
} from 'lucide-react';
import {
  OSILayerInfo,
  NetworkConnection,
  PacketFrame,
  SystemStats,
  TerminalTheme,
  ThemeConfig,
  TrafficScenario,
  OSILayerNumber,
} from '@/lib/types';
import {
  THEMES,
  INITIAL_OSI_LAYERS,
  INITIAL_CONNECTIONS,
  generateRandomPacket,
} from '@/lib/osi-engine';
import { HeaderBar } from '@/components/HeaderBar';
import { DashboardView } from '@/components/DashboardView';
import { LayerDetailView } from '@/components/LayerDetailView';
import { ConnectionsView } from '@/components/ConnectionsView';
import { PacketStreamView } from '@/components/PacketStreamView';
import { ProtocolMatrixView } from '@/components/ProtocolMatrixView';
import { ScenarioLabView } from '@/components/ScenarioLabView';
import { InstallModal } from '@/components/InstallModal';
import { CommandLineBar } from '@/components/CommandLineBar';

export default function TerminalApp() {
  // Application State
  const [activeTab, setActiveTab] = useState<'dashboard' | 'layer' | 'connections' | 'packets' | 'topology' | 'scenario'>('dashboard');
  const [selectedLayerNum, setSelectedLayerNum] = useState<OSILayerNumber>(7);
  const [selectedTheme, setSelectedTheme] = useState<TerminalTheme>('sophisticated');
  const [scenario, setScenario] = useState<TrafficScenario>('normal');
  const [isPaused, setIsPaused] = useState(false);
  const [crtEnabled, setCrtEnabled] = useState(false);
  const [speedMultiplier, setSpeedMultiplier] = useState(1);
  const [isInstallOpen, setIsInstallOpen] = useState(false);

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
    rxTotalMbps: 480.5,
    txTotalMbps: 210.2,
    rxPpsTotal: 1480,
    txPpsTotal: 740,
    totalPacketsCaptured: 184200,
  });

  // Layers & Connections State
  const [layers, setLayers] = useState<OSILayerInfo[]>(INITIAL_OSI_LAYERS);
  const [connections, setConnections] = useState<NetworkConnection[]>(INITIAL_CONNECTIONS);
  const [packets, setPackets] = useState<PacketFrame[]>(() => {
    const seed: PacketFrame[] = [];
    for (let i = 0; i < 20; i++) {
      seed.push(generateRandomPacket(i, 'normal'));
    }
    return seed;
  });
  const [historyRx, setHistoryRx] = useState<number[]>(Array(30).fill(480));
  const [historyTx, setHistoryTx] = useState<number[]>(Array(30).fill(210));

  const packetCounterRef = useRef(100);

  // Main High-Frequency Real-time Network Simulation Loop
  useEffect(() => {
    if (isPaused) return;

    const intervalMs = Math.max(100, 600 / speedMultiplier);

    const timer = setInterval(() => {
      packetCounterRef.current += 1;

      // Calculate scenario multipliers
      let rxMult = 1;
      let txMult = 1;
      let errorBoost = 0;

      if (scenario === 'web_heavy') {
        rxMult = 2.4;
        txMult = 1.8;
      } else if (scenario === 'video_stream') {
        rxMult = 4.8;
        txMult = 1.2;
      } else if (scenario === 'syn_flood') {
        rxMult = 8.5;
        txMult = 6.2;
        errorBoost = 12.4; // spike in drops / retransmits
      } else if (scenario === 'iot_mesh') {
        rxMult = 0.8;
        txMult = 2.2;
      } else if (scenario === 'dns_storm') {
        rxMult = 3.2;
        txMult = 3.2;
        errorBoost = 4.2;
      }

      // Update System Stats
      setStats((prev) => {
        const cpuBase = scenario === 'syn_flood' ? 78 : 15;
        const newCpu = Math.min(99, Math.max(5, cpuBase + (Math.random() * 12 - 6)));
        const newMem = Math.min(95, Math.max(20, prev.memUsagePct + (Math.random() * 0.4 - 0.2)));
        const newRx = Math.max(10, (480 + (Math.random() * 80 - 40)) * rxMult);
        const newTx = Math.max(10, (210 + (Math.random() * 40 - 20)) * txMult);

        return {
          ...prev,
          cpuUsagePct: newCpu,
          memUsagePct: newMem,
          uptimeSeconds: prev.uptimeSeconds + 1,
          rxTotalMbps: newRx,
          txTotalMbps: newTx,
          rxPpsTotal: Math.floor(newRx * 3.1),
          txPpsTotal: Math.floor(newTx * 3.1),
          totalPacketsCaptured: prev.totalPacketsCaptured + 1,
        };
      });

      // Update History Arrays
      setHistoryRx((prev) => [...prev.slice(1), Math.max(10, (480 + (Math.random() * 80 - 40)) * rxMult)]);
      setHistoryTx((prev) => [...prev.slice(1), Math.max(10, (210 + (Math.random() * 40 - 20)) * txMult)]);

      // Update OSI Layers
      setLayers((prevLayers) =>
        prevLayers.map((l) => {
          const deltaRx = Math.max(1000, (l.rxSpeed + (Math.random() * 40000 - 20000)) * rxMult);
          const deltaTx = Math.max(1000, (l.txSpeed + (Math.random() * 20000 - 10000)) * txMult);
          const newSparkline = [...l.sparkline.slice(1), Math.floor((deltaRx + deltaTx) / 10000)];

          return {
            ...l,
            rxSpeed: deltaRx,
            txSpeed: deltaTx,
            totalBytes: l.totalBytes + deltaRx + deltaTx,
            errorRate: Math.min(100, Math.max(0, l.errorRate + (Math.random() * 0.04 - 0.02) + errorBoost)),
            sparkline: newSparkline,
          };
        })
      );

      // Update Connections Speeds
      setConnections((prevConns) =>
        prevConns.map((c) => {
          const newRx = Math.max(100, c.rxSpeed + (Math.random() * 10000 - 5000) * rxMult);
          const newTx = Math.max(100, c.txSpeed + (Math.random() * 4000 - 2000) * txMult);

          return {
            ...c,
            rxSpeed: newRx,
            txSpeed: newTx,
            rxBytesTotal: c.rxBytesTotal + newRx,
            txBytesTotal: c.txBytesTotal + newTx,
            latencyMs: Math.min(500, Math.max(1, c.latencyMs + (Math.random() * 2 - 1))),
          };
        })
      );

      // Append new random packet
      const newPkt = generateRandomPacket(packetCounterRef.current, scenario);
      setPackets((prev) => [newPkt, ...prev.slice(0, 100)]);
    }, intervalMs);

    return () => clearInterval(timer);
  }, [isPaused, scenario, speedMultiplier]);

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
    } else if (mainCmd === 'lab' || mainCmd === 'scenario') {
      setActiveTab('scenario');
      if (arg1 && ['normal', 'web_heavy', 'video_stream', 'syn_flood', 'iot_mesh', 'dns_storm'].includes(arg1)) {
        setScenario(arg1 as TrafficScenario);
      }
    } else if (mainCmd === 'theme' && arg1) {
      if (THEMES[arg1 as TerminalTheme]) {
        setSelectedTheme(arg1 as TerminalTheme);
      }
    } else if (mainCmd === 'pause') {
      setIsPaused(true);
    } else if (mainCmd === 'resume') {
      setIsPaused(false);
    } else if (mainCmd === 'reset') {
      setStats((prev) => ({ ...prev, totalPacketsCaptured: 0 }));
      setPackets([]);
    } else if (['install', 'macos', 'brew', 'curl', 'sw_vers'].includes(mainCmd)) {
      setIsInstallOpen(true);
    }
  };

  const themeConfig = THEMES[selectedTheme];
  const activeLayer = layers.find((l) => l.layer === selectedLayerNum) || layers[0];

  return (
    <div className={`min-h-screen ${themeConfig.bg} ${themeConfig.text} font-mono flex flex-col justify-between overflow-x-hidden relative select-none transition-colors duration-300`}>
      {/* CRT Scanline Overlay Effect */}
      {crtEnabled && <div className="pointer-events-none fixed inset-0 z-50 crt-scanlines opacity-40"></div>}

      <div className="flex-1 flex flex-col">
        {/* Header Navigation Bar */}
        <HeaderBar
          stats={stats}
          theme={themeConfig}
          onSelectTheme={setSelectedTheme}
          isPaused={isPaused}
          onTogglePause={() => setIsPaused(!isPaused)}
          onReset={() => {
            setStats((prev) => ({ ...prev, totalPacketsCaptured: 0 }));
            setPackets([]);
          }}
          scenario={scenario}
          onSelectScenario={setScenario}
          crtEnabled={crtEnabled}
          onToggleCrt={() => setCrtEnabled(!crtEnabled)}
          onOpenInstall={() => setIsInstallOpen(true)}
          speedMultiplier={speedMultiplier}
          onChangeSpeedMultiplier={setSpeedMultiplier}
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

          <button
            onClick={() => setActiveTab('scenario')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'scenario'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Zap className="h-3.5 w-3.5" />
            <span>F6: SIMULATOR LAB</span>
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

          {activeTab === 'scenario' && (
            <ScenarioLabView
              currentScenario={scenario}
              onSelectScenario={setScenario}
              theme={themeConfig}
              onInjectPacket={(proto) => {
                const pkt = generateRandomPacket(packetCounterRef.current++, scenario);
                pkt.protocol = proto;
                pkt.summary = `MANUAL INJECTION: ${proto} frame burst injected into stack`;
                setPackets((prev) => [pkt, ...prev]);
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
