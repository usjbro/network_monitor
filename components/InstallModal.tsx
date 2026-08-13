'use client';

import React, { useState, useEffect } from 'react';
import {
  Terminal,
  Download,
  Copy,
  Check,
  X,
  Apple,
  Monitor,
  Laptop,
  CheckCircle2,
  ExternalLink,
  ShieldCheck,
} from 'lucide-react';
import { ThemeConfig } from '@/lib/types';

interface InstallModalProps {
  isOpen: boolean;
  onClose: () => void;
  theme: ThemeConfig;
}

export const InstallModal: React.FC<InstallModalProps> = ({ isOpen, onClose, theme }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'cli' | 'pwa'>('cli');
  const [deferredPrompt, setDeferredPrompt] = useState<any>(null);
  const [isInstalled, setIsInstalled] = useState(() => {
    if (typeof window !== 'undefined') {
      return window.matchMedia('(display-mode: standalone)').matches;
    }
    return false;
  });
  const [hostUrl] = useState(() => {
    if (typeof window !== 'undefined') {
      return window.location.origin;
    }
    return 'https://localhost:3000';
  });

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const handleBeforeInstall = (e: Event) => {
        e.preventDefault();
        setDeferredPrompt(e);
      };

      window.addEventListener('beforeinstallprompt', handleBeforeInstall);

      return () => {
        window.removeEventListener('beforeinstallprompt', handleBeforeInstall);
      };
    }
  }, []);

  if (!isOpen) return null;

  const installScriptUrl = `${hostUrl}/api/install`;

  const commands = [
    {
      title: 'macOS Terminal One-Liner (cURL)',
      desc: 'Installs osi-mon binary to ~/.local/bin in seconds',
      code: `curl -sSL ${installScriptUrl} | bash`,
    },
    {
      title: 'macOS Zsh / Bash Shell Alias',
      desc: 'Add alias to ~/.zshrc or ~/.bashrc',
      code: `echo "alias osi-mon='curl -sSL ${installScriptUrl} | bash'" >> ~/.zshrc && source ~/.zshrc`,
    },
  ];

  const handleCopy = (code: string, index: number) => {
    navigator.clipboard.writeText(code);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleDownloadCommandFile = () => {
    const fileContent = `#!/bin/bash
# OSI NetStriker macOS Terminal Launcher
echo -e "\\033[1;32mStarting OSI NetStriker Monitor...\\033[0m"
curl -sSL ${installScriptUrl} | bash
exec $SHELL
`;
    const blob = new Blob([fileContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'osi-mon-macos.command';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handlePwaInstall = async () => {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      if (outcome === 'accepted') {
        setIsInstalled(true);
      }
      setDeferredPrompt(null);
    } else {
      alert(
        'To install on macOS:\n' +
          '• Safari: Click Share button -> "Add to Dock"\n' +
          '• Chrome / Edge: Click Install button in the address bar'
      );
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 font-mono">
      <div
        className={`w-full max-w-2xl rounded-lg border ${theme.border} ${theme.cardBg} shadow-2xl flex flex-col max-h-[90vh] overflow-hidden`}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3 bg-slate-900/90">
          <div className="flex items-center space-x-2">
            <Apple className="h-5 w-5 text-slate-200" />
            <Terminal className="h-4 w-4 text-emerald-400" />
            <h2 className="text-sm font-bold tracking-wide uppercase text-slate-100">
              macOS Terminal & App Installer
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-100 transition p-1 rounded hover:bg-slate-800"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 bg-slate-950/60 px-4 pt-2 gap-2 text-xs">
          <button
            onClick={() => setActiveTab('cli')}
            className={`flex items-center space-x-1.5 px-3 py-2 rounded-t border-t border-x transition ${
              activeTab === 'cli'
                ? 'bg-slate-900 border-slate-700 text-emerald-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="h-3.5 w-3.5" />
            <span>macOS CLI (Terminal.app)</span>
          </button>
          <button
            onClick={() => setActiveTab('pwa')}
            className={`flex items-center space-x-1.5 px-3 py-2 rounded-t border-t border-x transition ${
              activeTab === 'pwa'
                ? 'bg-slate-900 border-slate-700 text-sky-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Laptop className="h-3.5 w-3.5" />
            <span>macOS Desktop App (PWA)</span>
          </button>
        </div>

        {/* Body Content */}
        <div className="p-5 overflow-y-auto space-y-5 text-xs">
          {activeTab === 'cli' && (
            <div className="space-y-4">
              <div className="p-3 rounded bg-emerald-950/40 border border-emerald-800/80 text-emerald-200 flex items-start space-x-3">
                <ShieldCheck className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-sm text-emerald-300">Native macOS Terminal Executable</h4>
                  <p className="text-emerald-400/90 text-[11px] mt-0.5">
                    Run OSI NetStriker in standard macOS <code className="bg-emerald-900/60 px-1 rounded">Terminal.app</code>, <code className="bg-emerald-900/60 px-1 rounded">iTerm2</code>, or Warp with full ANSI colors.
                  </p>
                </div>
              </div>

              {/* Download Executable Command file button */}
              <div className="flex items-center justify-between bg-slate-900 border border-slate-700 p-3 rounded">
                <div>
                  <div className="font-bold text-slate-200 text-xs">Download macOS Executable Launcher</div>
                  <div className="text-[11px] text-slate-400">Double-click <code className="text-amber-300">osi-mon-macos.command</code> to open directly in macOS Terminal.</div>
                </div>
                <button
                  onClick={handleDownloadCommandFile}
                  className="flex items-center space-x-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold px-3 py-1.5 rounded transition shadow"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>Download .command</span>
                </button>
              </div>

              {/* Commands List */}
              <div className="space-y-3">
                {commands.map((cmd, idx) => (
                  <div key={idx} className="bg-slate-950/80 border border-slate-800 rounded p-3 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200">{cmd.title}</span>
                      <span className="text-[10px] text-slate-400">{cmd.desc}</span>
                    </div>
                    <div className="flex items-center justify-between bg-slate-900 rounded border border-slate-800 px-3 py-2 text-slate-200 font-mono text-[11px] overflow-x-auto">
                      <code className="text-emerald-400 select-all">{cmd.code}</code>
                      <button
                        onClick={() => handleCopy(cmd.code, idx)}
                        className="ml-2 text-slate-400 hover:text-slate-100 p-1 rounded transition shrink-0"
                        title="Copy command"
                      >
                        {copiedIndex === idx ? (
                          <Check className="h-4 w-4 text-emerald-400" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'pwa' && (
            <div className="space-y-4">
              <div className="p-3 rounded bg-sky-950/40 border border-sky-800/80 text-sky-200 flex items-start space-x-3">
                <Laptop className="h-5 w-5 text-sky-400 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-sm text-sky-300">Install as macOS Desktop Application</h4>
                  <p className="text-sky-300/80 text-[11px] mt-0.5">
                    Pin OSI NetStriker to your macOS Dock, Launchpad, and Application menu with window controls and offline launch.
                  </p>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-4 rounded text-center space-y-3">
                <div className="flex items-center justify-center space-x-2 text-slate-300">
                  <Monitor className="h-6 w-6 text-sky-400" />
                  <span className="text-sm font-bold">macOS Web App Status:</span>
                  {isInstalled ? (
                    <span className="flex items-center text-emerald-400 font-bold space-x-1">
                      <CheckCircle2 className="h-4 w-4" />
                      <span>INSTALLED TO DOCK</span>
                    </span>
                  ) : (
                    <span className="text-amber-400 font-bold">READY TO INSTALL</span>
                  )}
                </div>

                <button
                  onClick={handlePwaInstall}
                  disabled={isInstalled}
                  className={`px-5 py-2 rounded font-bold text-xs flex items-center justify-center space-x-2 mx-auto transition ${
                    isInstalled
                      ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                      : 'bg-sky-600 hover:bg-sky-500 text-white shadow-lg'
                  }`}
                >
                  <Apple className="h-4 w-4" />
                  <span>{isInstalled ? 'App Installed in macOS' : 'Add OSI NetStriker to macOS Dock'}</span>
                </button>
              </div>

              <div className="bg-slate-950/80 border border-slate-800 rounded p-3 space-y-2">
                <h5 className="font-bold text-slate-200 text-xs">Manual macOS Installation Instructions:</h5>
                <ul className="list-disc list-inside text-slate-400 space-y-1 text-[11px]">
                  <li>
                    <strong className="text-slate-200">Safari on macOS Sonoma+:</strong> Click <span className="text-sky-400">File &gt; Add to Dock</span> in Safari top menu bar.
                  </li>
                  <li>
                    <strong className="text-slate-200">Google Chrome / Brave:</strong> Click the <span className="text-sky-400">Install App icon</span> on the right side of the URL address bar.
                  </li>
                  <li>
                    <strong className="text-slate-200">Arc Browser:</strong> Open command bar (<kbd className="bg-slate-800 px-1 rounded">⌘T</kbd>) and type <span className="text-sky-400">Save as App</span>.
                  </li>
                </ul>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-800 px-4 py-3 bg-slate-900/90 text-[11px]">
          <span className="text-slate-400">macOS Target: Darwin x86_64 / arm64 (Apple Silicon M1/M2/M3/M4)</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
