// Next.js runs this once when the server starts.
//
// Creating the enrichment client starts its query-log pruning, so the 30-day
// retention does not wait for a first request (KAN-321). Nothing is looked up:
// ownership enrichment itself stays off until it is turned on. `next build`
// and the edge runtime also call this and must not touch the log.
export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    if (process.env.NEXT_PHASE === 'phase-production-build') return;
    try {
      const { getEnrichmentClient } = await import('./lib/stream-response');
      getEnrichmentClient();
    } catch (err) {
      const { code, name } = err as NodeJS.ErrnoException;
      console.error('[enrichment] could not start query-log pruning:', code ?? name);
    }
  }
}
