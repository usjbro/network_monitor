import {
  OSILayerInfo,
  NetworkConnection,
  PacketFrame,
  SystemStats,
  ThemeConfig,
  TerminalTheme,
  OSILayerNumber,
} from './types';

// Terminal Themes Definition
export const THEMES: Record<TerminalTheme, ThemeConfig> = {
  sophisticated: {
    id: 'sophisticated',
    name: 'Sophisticated Dark',
    bg: 'bg-[#0a0a0b]',
    text: 'text-[#e2e2e2]',
    border: 'border-[#2d2d2d]',
    accent: 'text-[#4ade80]',
    secondaryAccent: 'text-[#6b7280]',
    highlight: 'bg-[#1a1a1c] text-[#4ade80] border-[#2d2d2d]',
    cardBg: 'bg-[#111113]',
    promptUser: 'text-[#4ade80]',
    promptHost: 'text-[#e2e2e2]',
    promptPath: 'text-[#6b7280]',
  },
  macos_pro: {
    id: 'macos_pro',
    name: 'macOS Terminal Pro',
    bg: 'bg-[#000000]',
    text: 'text-[#f2f2f2]',
    border: 'border-[#333333]',
    accent: 'text-[#00ff66]',
    secondaryAccent: 'text-[#888888]',
    highlight: 'bg-[#1c1c1e] text-[#00ff66] border-[#444444]',
    cardBg: 'bg-[#121212]',
    promptUser: 'text-[#00ff66]',
    promptHost: 'text-[#ffffff]',
    promptPath: 'text-[#888888]',
  },
  macos_homebrew: {
    id: 'macos_homebrew',
    name: 'macOS Homebrew',
    bg: 'bg-[#000000]',
    text: 'text-[#00ff00]',
    border: 'border-[#004400]',
    accent: 'text-[#33ff33]',
    secondaryAccent: 'text-[#00aa00]',
    highlight: 'bg-[#051a05] text-[#33ff33] border-[#00aa00]',
    cardBg: 'bg-[#020d02]',
    promptUser: 'text-[#33ff33]',
    promptHost: 'text-[#00ff00]',
    promptPath: 'text-[#00aa00]',
  },
  iterm_snazzy: {
    id: 'iterm_snazzy',
    name: 'iTerm2 Snazzy',
    bg: 'bg-[#282a36]',
    text: 'text-[#eff0eb]',
    border: 'border-[#44475a]',
    accent: 'text-[#50fa7b]',
    secondaryAccent: 'text-[#ff79c6]',
    highlight: 'bg-[#383a59] text-[#50fa7b] border-[#ff79c6]',
    cardBg: 'bg-[#1e1f29]',
    promptUser: 'text-[#ff79c6]',
    promptHost: 'text-[#8be9fd]',
    promptPath: 'text-[#bd93f9]',
  },
  matrix: {
    id: 'matrix',
    name: 'Matrix Green',
    bg: 'bg-black',
    text: 'text-emerald-400',
    border: 'border-emerald-800/60',
    accent: 'text-emerald-300',
    secondaryAccent: 'text-green-500',
    highlight: 'bg-emerald-950/80 text-emerald-200 border-emerald-600',
    cardBg: 'bg-emerald-950/20',
    promptUser: 'text-emerald-500',
    promptHost: 'text-green-400',
    promptPath: 'text-emerald-300',
  },
  amber: {
    id: 'amber',
    name: 'Amber CRT',
    bg: 'bg-amber-950/90',
    text: 'text-amber-400',
    border: 'border-amber-800/60',
    accent: 'text-amber-300',
    secondaryAccent: 'text-yellow-500',
    highlight: 'bg-amber-900/40 text-amber-200 border-amber-500',
    cardBg: 'bg-amber-950/30',
    promptUser: 'text-amber-500',
    promptHost: 'text-amber-400',
    promptPath: 'text-yellow-400',
  },
  dracula: {
    id: 'dracula',
    name: 'Dracula Purple',
    bg: 'bg-[#181825]',
    text: 'text-[#cdd6f4]',
    border: 'border-[#45475a]',
    accent: 'text-[#cba6f7]',
    secondaryAccent: 'text-[#f5c2e7]',
    highlight: 'bg-[#313244] text-[#f5e0dc] border-[#cba6f7]',
    cardBg: 'bg-[#1e1e2e]/90',
    promptUser: 'text-[#f38ba8]',
    promptHost: 'text-[#89b4fa]',
    promptPath: 'text-[#a6e3a1]',
  },
  catppuccin: {
    id: 'catppuccin',
    name: 'Catppuccin Mocha',
    bg: 'bg-[#11111b]',
    text: 'text-[#a6adc8]',
    border: 'border-[#313244]',
    accent: 'text-[#89b4fa]',
    secondaryAccent: 'text-[#94e2d5]',
    highlight: 'bg-[#1e1e2e] text-[#89b4fa] border-[#89b4fa]',
    cardBg: 'bg-[#181825]',
    promptUser: 'text-[#fab387]',
    promptHost: 'text-[#a6e3a1]',
    promptPath: 'text-[#89b4fa]',
  },
  cyberpunk: {
    id: 'cyberpunk',
    name: 'Cyberpunk Neon',
    bg: 'bg-[#090a0f]',
    text: 'text-[#00f0ff]',
    border: 'border-[#ff0055]/50',
    accent: 'text-[#ff0055]',
    secondaryAccent: 'text-[#ffe600]',
    highlight: 'bg-[#161a29] text-[#ffe600] border-[#00f0ff]',
    cardBg: 'bg-[#0d111d]',
    promptUser: 'text-[#ff0055]',
    promptHost: 'text-[#00f0ff]',
    promptPath: 'text-[#ffe600]',
  },
  nord: {
    id: 'nord',
    name: 'Nord Frost',
    bg: 'bg-[#2e3440]',
    text: 'text-[#eceff4]',
    border: 'border-[#4c566a]',
    accent: 'text-[#88c0d0]',
    secondaryAccent: 'text-[#81a1c1]',
    highlight: 'bg-[#3b4252] text-[#88c0d0] border-[#88c0d0]',
    cardBg: 'bg-[#2e3440]/80',
    promptUser: 'text-[#ebcb8b]',
    promptHost: 'text-[#a3be8c]',
    promptPath: 'text-[#88c0d0]',
  },
};

// Static OSI Layers template with descriptive fields only
export const STATIC_LAYER_INFO: Record<OSILayerNumber, Pick<OSILayerInfo,
  'layer' | 'name' | 'shortName' | 'pdu' | 'protocols' | 'color' | 'badgeBg' | 'badgeText'>> = {
  7: { layer: 7, name: 'Application', shortName: 'APP', pdu: 'Data', protocols: ['HTTP', 'DNS', 'TLS'], color: 'text-emerald-400', badgeBg: 'bg-emerald-500/10', badgeText: 'text-emerald-400' },
  6: { layer: 6, name: 'Presentation', shortName: 'PRES', pdu: 'Data', protocols: ['TLS', 'SSL'], color: 'text-teal-400', badgeBg: 'bg-teal-500/10', badgeText: 'text-teal-400' },
  5: { layer: 5, name: 'Session', shortName: 'SESS', pdu: 'Data', protocols: ['QUIC', 'NetBIOS'], color: 'text-cyan-400', badgeBg: 'bg-cyan-500/10', badgeText: 'text-cyan-400' },
  4: { layer: 4, name: 'Transport', shortName: 'TRANS', pdu: 'Segment', protocols: ['TCP', 'UDP'], color: 'text-sky-400', badgeBg: 'bg-sky-500/10', badgeText: 'text-sky-400' },
  3: { layer: 3, name: 'Network', shortName: 'NET', pdu: 'Packet', protocols: ['IPv4', 'IPv6', 'ICMP'], color: 'text-blue-400', badgeBg: 'bg-blue-500/10', badgeText: 'text-blue-400' },
  2: { layer: 2, name: 'Data Link', shortName: 'LINK', pdu: 'Frame', protocols: ['Ethernet'], color: 'text-indigo-400', badgeBg: 'bg-indigo-500/10', badgeText: 'text-indigo-400' },
  1: { layer: 1, name: 'Physical', shortName: 'PHYS', pdu: 'Bit', protocols: ['Ethernet PHY'], color: 'text-violet-400', badgeBg: 'bg-violet-500/10', badgeText: 'text-violet-400' },
};

// Utility: format speeds nicely (B/s -> KB/s -> MB/s)
export function formatSpeed(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  if (bytesPerSec < 1024 * 1024 * 1024) return `${(bytesPerSec / (1024 * 1024)).toFixed(2)} MB/s`;
  return `${(bytesPerSec / (1024 * 1024 * 1024)).toFixed(2)} GB/s`;
}

// Utility: format total bytes
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
