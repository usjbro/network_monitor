import { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'OSI NetStriker Terminal Monitor',
    short_name: 'OSI NetStriker',
    description: 'Real-time macOS terminal network traffic monitor across 7 OSI layers',
    start_url: '/',
    display: 'standalone',
    background_color: '#0a0a0b',
    theme_color: '#0a0a0b',
    // No real app icon exists in this repo yet — these previously pointed
    // at Picsum Photos placeholder URLs (random stock photos, a leftover
    // from the original Google AI Studio scaffold), which the CSP's
    // `img-src 'self' data:` correctly blocks anyway. Omitting `icons`
    // rather than pointing at a fabricated one; add a real local icon here
    // (e.g. via app/icon.tsx) when one exists.
  };
}
