import path from 'node:path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    // Mirrors tsconfig.json's "@/*": ["./*"] path mapping. Needed so tests
    // can import modules (e.g. Next.js route handlers under app/) that use
    // the "@/..." alias themselves — Vite doesn't read tsconfig "paths"
    // automatically without this.
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
  test: {
    environment: 'node',
    // Registers jest-dom's matchers (toBeInTheDocument, etc.) globally for
    // every test file, including ones running under the per-file
    // `// @vitest-environment jsdom` override (e.g.
    // lib/__tests__/connections-view-ownership.test.tsx) — the matchers
    // themselves are inert (no-ops on assertion setup) for node-environment
    // tests that never call them, so this is safe to load unconditionally
    // rather than needing a second, jsdom-only vitest project/config.
    setupFiles: ['./vitest.setup.ts'],
  },
});
