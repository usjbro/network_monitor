import type { Metadata, Viewport } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'OSI NetStriker v3.8 // MacOS Terminal Monitor',
  description: 'Real-time OSI traffic terminal monitor compatible with macOS Terminal, Homebrew, and web desktop installation.',
  appleWebApp: {
    capable: true,
    statusBarStyle: 'black-translucent',
    title: 'OSI NetStriker',
  },
  formatDetection: {
    telephone: false,
  },
};

export const viewport: Viewport = {
  themeColor: '#0a0a0b',
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body suppressHydrationWarning className="bg-[#0a0a0b] text-[#e2e2e2] antialiased select-none font-mono">
        {children}
      </body>
    </html>
  );
}
