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
    icons: [
      {
        src: 'https://picsum.photos/seed/osimon192/192/192',
        sizes: '192x192',
        type: 'image/png',
      },
      {
        src: 'https://picsum.photos/seed/osimon512/512/512',
        sizes: '512x512',
        type: 'image/png',
      },
    ],
  };
}
