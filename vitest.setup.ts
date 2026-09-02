// vitest.setup.ts
// Registers @testing-library/jest-dom's matchers (toBeInTheDocument, etc.)
// on vitest's `expect` globally. See vitest.config.ts's `setupFiles` for why
// this loads for every test file rather than only jsdom ones.
import '@testing-library/jest-dom/vitest';
