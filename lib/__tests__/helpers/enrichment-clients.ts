import type { EnrichmentClient } from '../../enrichment';

// Captured before any test can install fake timers.
const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const DRAIN_TIMEOUT_MS = 5_000;

/** Queue spacing for tests that send more than one query: production
 *  spacing is 3-10 s. */
export const FAST_QUEUE = { minDelayMs: 1, maxDelayMs: 2 };

/**
 * Tracks the clients a test file creates, so teardown can wait for their
 * lookups and file writes before removing the data folder. A cached result
 * goes out before its log entry is written (KAN-319), so a test can end with
 * a write still running; it recreates the folder, and during removal fails
 * it with ENOTEMPTY (KAN-173).
 */
export function enrichmentClients() {
  let clients: EnrichmentClient[] = [];
  return {
    track<T extends EnrichmentClient>(client: T): T {
      clients.push(client);
      return client;
    },
    /** Waits for every tracked client to go idle. Call it before restoring
     *  mocks, so leftover work runs against the mocks its test set up. Fails
     *  after 5 s, naming the cause, rather than letting the folder removal
     *  race a write still running. */
    async drain(): Promise<void> {
      const pending = clients;
      clients = [];
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<'timeout'>((resolve) => {
        timer = realSetTimeout(() => resolve('timeout'), DRAIN_TIMEOUT_MS);
      });
      const outcome = await Promise.race([Promise.all(pending.map((c) => c.idle())), timeout]);
      realClearTimeout(timer);
      if (outcome === 'timeout') {
        throw new Error(`an enrichment client was still busy ${DRAIN_TIMEOUT_MS} ms after its test ended (a lookup or write left held?)`);
      }
    },
  };
}
