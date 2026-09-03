import { NextRequest, NextResponse } from 'next/server';
import { getEnrichmentClient } from '@/lib/stream-response';

export async function POST(request: NextRequest) {
  const body = await request.json();
  if (typeof body.connectionId !== 'string' || typeof body.remoteAddr !== 'string') {
    return NextResponse.json({ error: 'connectionId and remoteAddr are required' }, { status: 400 });
  }
  getEnrichmentClient().requestLookup(body.connectionId, body.remoteAddr);
  return NextResponse.json({ ok: true });
}
