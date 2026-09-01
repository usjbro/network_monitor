'use client';

import React, { useState } from 'react';
import { Terminal, Send, HelpCircle } from 'lucide-react';
import { ThemeConfig, TerminalTheme } from '@/lib/types';

interface CommandLineBarProps {
  theme: ThemeConfig;
  onExecuteCommand: (cmd: string) => void;
}

export const CommandLineBar: React.FC<CommandLineBarProps> = ({
  theme,
  onExecuteCommand,
}) => {
  const [command, setCommand] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [showHelp, setShowHelp] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!command.trim()) return;

    const trimmed = command.trim();
    if (trimmed.toLowerCase() === 'help') {
      setShowHelp(true);
    } else {
      onExecuteCommand(trimmed);
    }

    setHistory((prev) => [...prev, trimmed]);
    setHistoryIndex(-1);
    setCommand('');
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length === 0) return;
      const nextIdx = historyIndex === -1 ? history.length - 1 : Math.max(0, historyIndex - 1);
      setHistoryIndex(nextIdx);
      setCommand(history[nextIdx] || '');
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex === -1) return;
      const nextIdx = historyIndex + 1;
      if (nextIdx >= history.length) {
        setHistoryIndex(-1);
        setCommand('');
      } else {
        setHistoryIndex(nextIdx);
        setCommand(history[nextIdx] || '');
      }
    }
  };

  return (
    <div className="relative font-mono text-xs select-none">
      {/* Help Modal Popup if user typed 'help' or clicked ? */}
      {showHelp && (
        <div className="absolute bottom-full mb-2 left-3 right-3 bg-slate-950 border border-slate-700 text-slate-200 p-3.5 rounded shadow-2xl z-30 space-y-2">
          <div className="flex justify-between items-center border-b border-slate-800 pb-1.5 font-bold text-emerald-400">
            <span>AVAILABLE CLI COMMANDS</span>
            <button onClick={() => setShowHelp(false)} className="text-slate-400 hover:text-white">
              [CLOSE]
            </button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-slate-300">
            <div><strong className="text-emerald-400">dash / dashboard</strong>: View main OSI stack dashboard</div>
            <div><strong className="text-emerald-400">layer [1-7]</strong>: Open Layer 1 through Layer 7 details</div>
            <div><strong className="text-emerald-400">conn / sockets</strong>: Open active connections table</div>
            <div><strong className="text-emerald-400">pcap / packets</strong>: View live Wireshark-style packet capture</div>
            <div><strong className="text-emerald-400">matrix / topology</strong>: Open 7-Layer OSI data flow topology</div>
            <div><strong className="text-emerald-400">install / macos / brew</strong>: Open macOS Terminal installer & PWA</div>
            <div><strong className="text-emerald-400">theme [sophisticated|macos_pro|matrix]</strong>: Switch visual theme</div>
            <div><strong className="text-emerald-400">pause / resume</strong>: Pause or resume the capture agent</div>
            <div><strong className="text-emerald-400">enrich on / off</strong>: Toggle on-demand ownership lookups (RDAP)</div>
            <div><strong className="text-emerald-400">enrich background on / off</strong>: Toggle whole-table background lookups</div>
            <div><strong className="text-emerald-400">enrich clear</strong>: Wipe enrichment cache + query log, disable</div>
          </div>
        </div>
      )}

      {/* Command Line Input Bar */}
      <form
        onSubmit={handleSubmit}
        className={`flex items-center space-x-2 bg-slate-950 border-t ${theme.border} px-3 py-2`}
      >
        <div className="flex items-center space-x-1.5 font-bold">
          <Terminal className={`h-3.5 w-3.5 ${theme.accent}`} />
          <span className={theme.promptUser}>sysadmin</span>
          <span className="opacity-40">@</span>
          <span className={theme.promptHost}>osi-gw</span>
          <span className="opacity-40">&gt;</span>
        </div>

        <input
          type="text"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Type CLI command (e.g. 'layer 4', 'conn', 'pause', 'theme matrix', 'help')..."
          className="flex-1 bg-transparent text-slate-100 placeholder-slate-600 focus:outline-none text-xs font-mono"
        />

        <button
          type="button"
          onClick={() => setShowHelp(!showHelp)}
          className="p-1 text-slate-400 hover:text-slate-200 transition"
          title="CLI Help"
        >
          <HelpCircle className="h-3.5 w-3.5" />
        </button>

        <button
          type="submit"
          className={`px-2 py-1 rounded text-[11px] font-bold ${theme.highlight} transition`}
        >
          EXEC
        </button>
      </form>
    </div>
  );
};
