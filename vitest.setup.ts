// vitest.setup.ts
// Registers @testing-library/jest-dom's matchers (toBeInTheDocument, etc.)
// on vitest's `expect` globally. See vitest.config.ts's `setupFiles` for why
// this loads for every test file rather than only jsdom ones.
import '@testing-library/jest-dom/vitest';

// @testing-library/react's own auto-cleanup only registers itself when it
// detects a global `afterEach` (e.g. Jest, or Vitest with `test.globals:
// true`). This repo's vitest.config.ts doesn't set `globals: true` — test
// files import `afterEach` etc. from 'vitest' explicitly instead — so that
// auto-detection never fires and unmounted trees from a prior test would
// otherwise still be in the jsdom document for the next test in the same
// file. Registering cleanup explicitly here, once, covers every test file
// (a no-op for files that never render anything).
import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

afterEach(() => {
  cleanup();
});
