import { NextRequest, NextResponse } from 'next/server';
import { getGeoIpClient } from '@/lib/stream-response';
import { rejectIfCrossSite } from '@/lib/same-origin';

export async function POST(request: NextRequest) {
  // Cross-site rejection first, before the body is even parsed — none of
  // these routes are authenticated, so a page the operator visits must not
  // be able to drive them through the operator's own browser (JAM-151).
  const crossSite = rejectIfCrossSite(request);
  if (crossSite) return crossSite;

  const body = await request.json();
  if (!['enable', 'disable', 'clear'].includes(body.action)) {
    return NextResponse.json({ error: 'invalid action' }, { status: 400 });
  }
  const client = getGeoIpClient();
  if (body.action === 'enable') {
    return NextResponse.json({ ok: true, disclosure: client.enable() });
  }
  if (body.action === 'disable') {
    client.disable();
    return NextResponse.json({ ok: true });
  }
  await client.clear();
  return NextResponse.json({ ok: true });
}
