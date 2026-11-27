import { NextRequest, NextResponse } from 'next/server';
import { getEnrichmentClient } from '@/lib/stream-response';
import { clearFailureLabels, isClearTimeout } from '@/lib/enrichment';
import { rejectIfCrossSite } from '@/lib/same-origin';

const VALID_ACTIONS = ['enable', 'enable_background', 'disable', 'disable_background', 'clear'] as const;

export async function POST(request: NextRequest) {
  // Cross-site rejection first, before the body is even parsed — none of
  // these routes are authenticated, so a page the operator visits must not
  // be able to drive them through the operator's own browser (JAM-151).
  const crossSite = rejectIfCrossSite(request);
  if (crossSite) return crossSite;

  const body = await request.json();
  if (!VALID_ACTIONS.includes(body.action)) {
    return NextResponse.json({ error: 'invalid action' }, { status: 400 });
  }
  const client = getEnrichmentClient();
  switch (body.action) {
    case 'enable':
      return NextResponse.json({ ok: true, ...client.enable() });
    case 'enable_background':
      return NextResponse.json({ ok: true, ...client.enableBackground() });
    case 'disable':
      client.disable();
      return NextResponse.json({ ok: true });
    case 'disable_background':
      client.disableBackground();
      return NextResponse.json({ ok: true });
    case 'clear':
      try {
        await client.clear();
      } catch (err) {
        if (isClearTimeout(err)) {
          // The wipe is still queued and logs its outcome (KAN-319).
          console.error('[enrichment] clear timed out: lookups are off, and the wipe runs once the stalled write finishes');
          return NextResponse.json({ error: 'clear timed out' }, { status: 500 });
        }
        // Lookups are off even so; the path stays out of the log (KAN-317).
        console.error('[enrichment] clear failed:', clearFailureLabels(err));
        return NextResponse.json({ error: 'clear failed' }, { status: 500 });
      }
      return NextResponse.json({ ok: true });
  }
}
