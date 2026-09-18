'use client';

import React from 'react';
import {
  Activity,
  Pause,
  Play,
  RotateCcw,
  Terminal,
  Tv,
  Apple,
} from 'lucide-react';
import { CaptureConfig, SystemStats, TerminalTheme, ThemeConfig } from '@/lib/types';
import { THEMES, formatSpeed } from '@/lib/osi-engine';

interface HeaderBarProps {
  // `null` until the agent's first `system_stats` tick arrives (issue #64)
  // — distinct from "zero throughput so far," a real, healthy state once
  // at least one tick has been received. Every field this component reads
  // from `stats` is a live measurement; nothing here is a placeholder.
  stats: SystemStats | null;
  // `null` until the agent's first `capture_config` tick arrives (issue
  // #68) — same "no placeholder" discipline as `stats` above. An operator
  // must never be unsure whether they're seeing everything, so this is
  // always rendered once known, not tucked behind a menu.
  captureConfig: CaptureConfig | null;
  theme: ThemeConfig;
  onSelectTheme: (themeKey: TerminalTheme) => void;
  isPaused: boolean;
  onTogglePause: () => void;
  onReset: () => void;
  crtEnabled: boolean;
  onToggleCrt: () => void;
  onOpenInstall: () => void;
}

export const HeaderBar: React.FC<HeaderBarProps> = ({
  stats,
  captureConfig,
  theme,
  onSelectTheme,
  isPaused,
  onTogglePause,
  onReset,
  crtEnabled,
  onToggleCrt,
  onOpenInstall,
}) => {
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
            <span className={theme.promptHost}>{stats?.hostname || '—'}</span>
            <span className="opacity-40">:</span>
            <span className="bg-slate-800/80 px-1.5 py-0.5 rounded text-[10px] text-slate-300 font-semibold border border-slate-700">
              {stats?.interfaceName || '—'}
            </span>
          </div>

          {/* Active capture filter/snap length (issue #68) — always
              visible, never tucked behind a menu, so an operator can never
              be unsure whether they're seeing everything. */}
          <div className="hidden lg:flex items-center space-x-2 border-l border-slate-700/60 pl-3">
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                captureConfig?.filter
                  ? 'bg-amber-950/60 border-amber-700 text-amber-300'
                  : 'bg-slate-800/80 border-slate-700 text-slate-400'
              }`}
              title={captureConfig?.filter ? `Capture filter: ${captureConfig.filter}` : 'No capture filter active'}
            >
              filter: {captureConfig?.filter || 'none'}
            </span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                captureConfig && captureConfig.snaplen < 65535
                  ? 'bg-amber-950/60 border-amber-700 text-amber-300'
                  : 'bg-slate-800/80 border-slate-700 text-slate-400'
              }`}
              title="Capture snap length — bytes retained per frame before the kernel truncates the rest"
            >
              snaplen: {captureConfig ? `${captureConfig.snaplen}B` : '—'}
            </span>
          </div>
        </div>

        {/* Center: Live Stats Badges */}
        <div className="hidden md:flex items-center space-x-4">
          <div className="flex items-center space-x-1">
            <Activity className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
            <span className="opacity-70">RX:</span>
            <span className="font-bold text-emerald-400">
              {stats ? formatSpeed(stats.rxTotalMbps * 1024 * 1024) : '—'}
            </span>
          </div>

          <div className="flex items-center space-x-1">
            <Activity className="h-3.5 w-3.5 text-sky-400 animate-pulse" />
            <span className="opacity-70">TX:</span>
            <span className="font-bold text-sky-400">
              {stats ? formatSpeed(stats.txTotalMbps * 1024 * 1024) : '—'}
            </span>
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
