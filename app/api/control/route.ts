import { NextRequest, NextResponse } from 'next/server';
import { AgentClient } from '@/lib/agent-client';

declare global {
  // eslint-disable-next-line no-var
  var __agentClient: AgentClient | undefined;
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  if (body.type !== 'pause' && body.type !== 'resume') {
    return NextResponse.json({ error: 'invalid control message type' }, { status: 400 });
  }
  if (!global.__agentClient) {
    return NextResponse.json({ error: 'agent not connected' }, { status: 503 });
  }
  global.__agentClient.sendControl({ type: body.type });
  return NextResponse.json({ ok: true });
}
