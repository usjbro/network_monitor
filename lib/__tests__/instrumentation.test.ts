// lib/__tests__/instrumentation.test.ts
// KAN-321: the server prunes the query log without waiting for a request.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EnrichmentClient } from '../enrichment';
import { getEnrichmentClient } from '../stream-response';
import { register } from '../../instrumentation';

describe('register', () => {
  afterEach(() => {
    global.__enrichmentClient = undefined;
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  const startPruning = () => vi.spyOn(EnrichmentClient.prototype, 'startPruning').mockResolvedValue();

  it('starts pruning on the shared client', async () => {
    const start = startPruning();
    vi.stubEnv('NEXT_RUNTIME', 'nodejs');
    await register();
    await register();
    expect(start).toHaveBeenCalledTimes(1);
    expect(start.mock.contexts[0]).toBe(getEnrichmentClient());
    expect(start).toHaveBeenCalledTimes(1);
  });

  it('is ready without waiting for the prune', async () => {
    const start = startPruning().mockReturnValue(new Promise(() => {}));
    vi.stubEnv('NEXT_RUNTIME', 'nodejs');
    await register();
    expect(start).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['the edge runtime', 'edge', ''],
    ['next build', 'nodejs', 'phase-production-build'],
  ])('does nothing in %s', async (_name, runtime, phase) => {
    const start = startPruning();
    vi.stubEnv('NEXT_RUNTIME', runtime);
    vi.stubEnv('NEXT_PHASE', phase);
    await register();
    expect(start).not.toHaveBeenCalled();
    expect(global.__enrichmentClient).toBeUndefined();
  });

  it('reports a failure by code or name only and lets the server start', async () => {
    startPruning().mockImplementation(() => { throw new TypeError('198.51.100.7', { cause: Object.assign(new Error('x'), { code: 'EACCES' }) }); });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.stubEnv('NEXT_RUNTIME', 'nodejs');
    await register();
    expect(error.mock.calls).toEqual([['[enrichment] could not start query-log pruning:', 'TypeError (EACCES)']]);
  });

  it('a first request starts pruning when the startup hook did not', () => {
    const start = startPruning();
    getEnrichmentClient();
    getEnrichmentClient();
    expect(start).toHaveBeenCalledTimes(1);
  });
});
