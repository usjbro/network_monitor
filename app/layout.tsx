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

// Nonce-based CSP (see middleware.ts) requires dynamic rendering: Next.js
// only has a per-request nonce to inject into its own framework-generated
// inline scripts when the page is server-rendered on each request. A
// statically prerendered page is built once with no request in scope, so
// its inline hydration/RSC-payload <script> tags would ship with no nonce
// at all and get blocked by this CSP's script-src in a real browser --
// confirmed via `curl` during this task: without this, none of the
// rendered <script> tags carried a nonce= attribute. This app is a live
// local dashboard (loopback-only, never meant to be cached/CDN'd), so
// forcing dynamic rendering has no real downside here.
export const dynamic = 'force-dynamic';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body suppressHydrationWarning className="bg-[#0a0a0b] text-[#e2e2e2] antialiased select-none font-mono">
        {children}
      </body>
    </html>
  );
}
