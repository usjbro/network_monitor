import { NextRequest, NextResponse } from 'next/server';
import { GeoIpClient } from '@/lib/geoip';

declare global {
  var __geoIpClient: GeoIpClient | undefined;
}

export function getGeoIpClient(): GeoIpClient {
  if (!global.__geoIpClient) {
    global.__geoIpClient = new GeoIpClient();
  }
  return global.__geoIpClient;
}

export async function POST(request: NextRequest) {
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
