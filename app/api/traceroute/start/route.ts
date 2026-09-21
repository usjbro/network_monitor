import { NextRequest, NextResponse } from 'next/server';
import { AgentClient } from '@/lib/agent-client';
import { rejectIfCrossSite } from '@/lib/same-origin';

declare global {
  var __agentClient: AgentClient | undefined;
}

// Traceroute is on-demand only — this route is the sole trigger for a trace.
// Nothing in this app calls it automatically (see the design spec's
// Explicitly out of scope section and this plan's Global Constraints).
export async function POST(request: NextRequest) {
  // Cross-site rejection first, before the body is even parsed — none of
  // these routes are authenticated, so a page the operator visits must not
  // be able to drive them through the operator's own browser (JAM-151).
  const crossSite = rejectIfCrossSite(request);
  if (crossSite) return crossSite;

  const body = await request.json();
  if (typeof body.remoteAddr !== 'string') {
    return NextResponse.json({ error: 'remoteAddr required' }, { status: 400 });
  }
  if (!global.__agentClient) {
    return NextResponse.json({ error: 'agent not connected' }, { status: 503 });
  }
  global.__agentClient.sendControl({ type: 'trace_route', targetIp: body.remoteAddr });
  return NextResponse.json({ ok: true });
}
