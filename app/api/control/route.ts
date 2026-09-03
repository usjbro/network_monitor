import { NextRequest, NextResponse } from 'next/server';
import { AgentClient } from '@/lib/agent-client';

declare global {
  var __agentClient: AgentClient | undefined;
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const allowedTypes = ['pause', 'resume', 'register_decrypt_eligible', 'unregister_decrypt_eligible'];
  if (!allowedTypes.includes(body.type)) {
    return NextResponse.json({ error: 'invalid control message type' }, { status: 400 });
  }
  if (!global.__agentClient) {
    return NextResponse.json({ error: 'agent not connected' }, { status: 503 });
  }
  global.__agentClient.sendControl(body);
  return NextResponse.json({ ok: true });
}
