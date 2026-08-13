'use client';

import React from 'react';
import {
  Activity,
  Cpu,
  HardDrive,
  Pause,
  Play,
  RotateCcw,
  Terminal,
  Tv,
  Globe,
  Apple,
} from 'lucide-react';
import { SystemStats, TerminalTheme, ThemeConfig, TrafficScenario } from '@/lib/types';
import { THEMES, formatSpeed } from '@/lib/osi-engine';

interface HeaderBarProps {
  stats: SystemStats;
  theme: ThemeConfig;
  onSelectTheme: (themeKey: TerminalTheme) => void;
  isPaused: boolean;
  onTogglePause: () => void;
  onReset: () => void;
  scenario: TrafficScenario;
  onSelectScenario: (scen: TrafficScenario) => void;
  crtEnabled: boolean;
  onToggleCrt: () => void;
  onOpenInstall: () => void;
  speedMultiplier: number;
  onChangeSpeedMultiplier: (mult: number) => void;
}

export const HeaderBar: React.FC<HeaderBarProps> = ({
  stats,
  theme,
  onSelectTheme,
  isPaused,
  onTogglePause,
  onReset,
  scenario,
  onSelectScenario,
  crtEnabled,
  onToggleCrt,
  onOpenInstall,
  speedMultiplier,
  onChangeSpeedMultiplier,
}) => {
  const formatUptime = (sec: number) => {
    const hrs = Math.floor(sec / 3600);
    const mins = Math.floor((sec % 3600) / 60);
    const secs = sec % 60;
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <header className={`border-b ${theme.border} ${theme.cardBg} px-3 py-2 text-xs font-mono select-none`}>
      {/* Top Banner Row */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        {/* Left: Brand & Host info */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5 font-bold tracking-wider">
            <Terminal className={`h-4 w-4 ${theme.accent}`} />
            <span className={`${theme.accent} text-sm uppercase`}>OSI-MON</span>
            <span className="opacity-60">v3.8.4</span>
          </div>

          <div className="hidden sm:flex items-center space-x-2 border-l border-slate-700/60 pl-3">
            <span className={theme.promptUser}>sysadmin</span>
            <span className="opacity-40">@</span>
            <span className={theme.promptHost}>{stats.hostname}</span>
            <span className="opacity-40">:</span>
            <span className="bg-slate-800/80 px-1.5 py-0.5 rounded text-[10px] text-slate-300 font-semibold border border-slate-700">
              {stats.interfaceName} [{stats.interfaceSpeedMbps >= 1000 ? `${stats.interfaceSpeedMbps / 1000}G` : `${stats.interfaceSpeedMbps}M`}]
            </span>
          </div>
        </div>

        {/* Center: Live Stats Badges */}
        <div className="hidden md:flex items-center space-x-4">
          <div className="flex items-center space-x-1">
            <Activity className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
            <span className="opacity-70">RX:</span>
            <span className="font-bold text-emerald-400">{formatSpeed(stats.rxTotalMbps * 1024 * 1024)}</span>
          </div>

          <div className="flex items-center space-x-1">
            <Activity className="h-3.5 w-3.5 text-sky-400 animate-pulse" />
            <span className="opacity-70">TX:</span>
            <span className="font-bold text-sky-400">{formatSpeed(stats.txTotalMbps * 1024 * 1024)}</span>
          </div>

          <div className="flex items-center space-x-1">
            <Cpu className="h-3.5 w-3.5 text-amber-400" />
            <span className="opacity-70">CPU:</span>
            <span className="font-bold">{stats.cpuUsagePct.toFixed(1)}%</span>
          </div>

          <div className="flex items-center space-x-1">
            <HardDrive className="h-3.5 w-3.5 text-indigo-400" />
            <span className="opacity-70">MEM:</span>
            <span className="font-bold">{stats.memUsagePct.toFixed(1)}%</span>
          </div>

          <div className="hidden lg:block text-slate-400">
            <span className="opacity-70">UPTIME:</span> {formatUptime(stats.uptimeSeconds)}
          </div>
        </div>

        {/* Right: Controls & Actions */}
        <div className="flex items-center space-x-2">
          {/* Pause / Play */}
          <button
            onClick={onTogglePause}
            className={`flex items-center space-x-1 px-2.5 py-1 rounded border text-[11px] transition ${
              isPaused
                ? 'bg-amber-950/80 border-amber-600 text-amber-300 font-bold'
                : 'bg-slate-800/80 border-slate-700 hover:border-slate-500'
            }`}
            title="Pause/Resume Realtime Monitor"
          >
            {isPaused ? <Play className="h-3 w-3 fill-amber-300" /> : <Pause className="h-3 w-3" />}
            <span className="hidden sm:inline">{isPaused ? 'RESUMED' : 'PAUSE'}</span>
          </button>

          {/* Reset */}
          <button
            onClick={onReset}
            className="p-1.5 rounded border border-slate-700 bg-slate-800/80 hover:border-slate-500 text-slate-300 transition"
            title="Reset Traffic Counters"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>

          {/* Speed Multiplier */}
          <select
            value={speedMultiplier}
            onChange={(e) => onChangeSpeedMultiplier(Number(e.target.value))}
            className="bg-slate-900 border border-slate-700 text-slate-200 text-[11px] rounded px-1.5 py-1 focus:outline-none"
            title="Traffic Tick Speed"
          >
            <option value={0.5}>0.5x Tick</option>
            <option value={1}>1.0x Normal</option>
            <option value={2}>2.0x Fast</option>
            <option value={5}>5.0x Turbo</option>
          </select>

          {/* Traffic Scenario Picker */}
          <div className="hidden sm:flex items-center space-x-1 bg-slate-900/90 border border-slate-700 rounded px-2 py-0.5">
            <Globe className="h-3 w-3 opacity-60" />
            <select
              value={scenario}
              onChange={(e) => onSelectScenario(e.target.value as TrafficScenario)}
              className="bg-transparent text-slate-200 text-[11px] focus:outline-none font-mono"
            >
              <option value="normal" className="bg-slate-900">Scenario: Normal Mix</option>
              <option value="web_heavy" className="bg-slate-900">Scenario: Web Browsing</option>
              <option value="video_stream" className="bg-slate-900">Scenario: Video Streaming</option>
              <option value="syn_flood" className="bg-slate-900 text-rose-400 font-bold">Scenario: SYN Flood (DDoS)</option>
              <option value="iot_mesh" className="bg-slate-900">Scenario: IoT Swarm</option>
              <option value="dns_storm" className="bg-slate-900">Scenario: DNS Query Storm</option>
            </select>
          </div>

          {/* CRT Toggle */}
          <button
            onClick={onToggleCrt}
            className={`p-1.5 rounded border transition ${
              crtEnabled
                ? 'bg-emerald-950 border-emerald-500 text-emerald-300'
                : 'border-slate-700 bg-slate-800/80 text-slate-400 hover:text-slate-200'
            }`}
            title="Toggle CRT Scanline Overlay"
          >
            <Tv className="h-3.5 w-3.5" />
          </button>

          {/* Theme Selector */}
          <select
            value={theme.id}
            onChange={(e) => onSelectTheme(e.target.value as TerminalTheme)}
            className="bg-slate-900 border border-slate-700 text-slate-200 text-[11px] rounded px-2 py-1 focus:outline-none font-mono"
          >
            {Object.values(THEMES).map((th) => (
              <option key={th.id} value={th.id} className="bg-slate-900">
                Theme: {th.name}
              </option>
            ))}
          </select>

          {/* macOS / Install CLI Button */}
          <button
            onClick={onOpenInstall}
            className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-600 text-emerald-400 font-bold transition shadow"
            title="Install CLI or macOS Desktop App"
          >
            <Apple className="h-3.5 w-3.5 text-slate-200" />
            <span className="hidden sm:inline">INSTALL</span>
          </button>
        </div>
      </div>
    </header>
  );
};
