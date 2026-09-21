import { NextRequest, NextResponse } from 'next/server';
import { getEnrichmentClient } from '@/lib/stream-response';
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
      await client.clear();
      return NextResponse.json({ ok: true });
  }
}
