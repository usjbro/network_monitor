import { defineConfig, devices } from '@playwright/test';
import fs from 'node:fs';

const PORT = 3100;

// This dev sandbox pre-installs a Chromium build under a fixed path with a
// different revision than whatever @playwright/test's package.json pins
// (see this repo's own CLAUDE.md-adjacent environment notes) — when it's
// present, point Playwright straight at it instead of letting it resolve
// (and fail to find) its normally-expected revision-specific cache
// directory. A real CI runner has no such pre-installed path; there,
// `playwright install --with-deps chromium` (see .github/workflows/ci.yml)
// fetches the exact revision this pinned version expects, and Playwright's
// own default resolution finds it.
const preInstalledChromium = '/opt/pw-browsers/chromium';
const chromiumExecutablePath = fs.existsSync(preInstalledChromium) ? preInstalledChromium : undefined;

export default defineConfig({
  testDir: './e2e',
  // A single fake-agent TCP double (bound to the real capture agent's well-
  // known 127.0.0.1:9990) backs the one real Next.js server this config's
  // webServer starts — running more than one worker would mean two test
  // files racing to bind the same port. The whole suite is one smoke-test
  // file, so this costs nothing in practice.
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  // The 'html' report is only written to disk in CI, where a failure's
  // upload-artifact step (.github/workflows/ci.yml) needs playwright-report/
  // to exist — locally, `npx playwright show-report` after a `list`-only
  // run still works off the last run's trace via `--trace on-first-retry`.
  reporter: process.env.CI ? [['github'], ['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        ...(chromiumExecutablePath ? { launchOptions: { executablePath: chromiumExecutablePath } } : {}),
      },
    },
  ],
  webServer: {
    // `next dev`, matching this repo's own `npm run dev` convention (see
    // package.json/CLAUDE.md) rather than a production build — this is a
    // smoke test of real browser/SSE/DOM behavior, not a build artifact
    // check (that's `npm run build` in CI's "web" job already). Keeps the
    // loopback-only `-H 127.0.0.1` bind and `--webpack` flag CLAUDE.md
    // says not to drop.
    command: `npx next dev -H 127.0.0.1 --webpack -p ${PORT}`,
    url: `http://127.0.0.1:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
