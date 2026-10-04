import { NextRequest, NextResponse } from 'next/server';
import { getEnrichmentClient } from '@/lib/stream-response';
import { rejectIfCrossSite } from '@/lib/same-origin';

export async function POST(request: NextRequest) {
  // While enrichment is on, a lookup sends real outbound RDAP/WHOIS
  // queries — a page the operator visits must not be able to trigger them
  // through the operator's own browser (JAM-178, same guard as JAM-151).
  const crossSite = rejectIfCrossSite(request);
  if (crossSite) return crossSite;

  const body = await request.json();
  if (typeof body.connectionId !== 'string' || typeof body.remoteAddr !== 'string') {
    return NextResponse.json({ error: 'connectionId and remoteAddr are required' }, { status: 400 });
  }
  getEnrichmentClient().requestLookup(body.connectionId, body.remoteAddr);
  return NextResponse.json({ ok: true });
}
