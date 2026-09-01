import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  test: {
    environment: 'node',
  },
  resolve: {
    // Mirrors tsconfig.json's "@/*": ["./*"] path mapping. Needed so tests
    // can import modules (e.g. Next.js route handlers under app/) that use
    // the "@/..." alias themselves — Vite doesn't read tsconfig "paths"
    // automatically without this.
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
});
