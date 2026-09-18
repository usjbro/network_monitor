import { NextRequest, NextResponse } from 'next/server';
import { AgentClient } from '@/lib/agent-client';

declare global {
  var __agentClient: AgentClient | undefined;
}

// Matches capture-agent/src/main.rs's MAX_CAPTURE_FILTER_LEN/
// MAX_INTERFACE_NAME_LEN — the agent is the authoritative enforcer (issues
// #68/#69's security considerations target it, the privileged process),
// but rejecting an oversized value here too means a bogus/hostile request
// never even reaches the agent process's control channel.
const MAX_CAPTURE_FILTER_LEN = 1024;
const MAX_INTERFACE_NAME_LEN = 256;

export async function POST(request: NextRequest) {
  const body = await request.json();
  const allowedTypes = [
    'pause',
    'resume',
    'register_decrypt_eligible',
    'unregister_decrypt_eligible',
    'set_capture_filter',
    'set_snaplen',
    'list_interfaces',
    'set_interface',
  ];
  if (!allowedTypes.includes(body.type)) {
    return NextResponse.json({ error: 'invalid control message type' }, { status: 400 });
  }
  if (body.type === 'set_capture_filter') {
    if (typeof body.filter !== 'string' || body.filter.length > MAX_CAPTURE_FILTER_LEN) {
      return NextResponse.json({ error: 'invalid capture filter' }, { status: 400 });
    }
  }
  if (body.type === 'set_snaplen') {
    if (typeof body.bytes !== 'number' || !Number.isInteger(body.bytes) || body.bytes <= 0) {
      return NextResponse.json({ error: 'invalid snap length' }, { status: 400 });
    }
  }
  if (body.type === 'set_interface') {
    if (typeof body.name !== 'string' || body.name.length === 0 || body.name.length > MAX_INTERFACE_NAME_LEN) {
      return NextResponse.json({ error: 'invalid interface name' }, { status: 400 });
    }
  }
  if (!global.__agentClient) {
    return NextResponse.json({ error: 'agent not connected' }, { status: 503 });
  }
  global.__agentClient.sendControl(body);
  return NextResponse.json({ ok: true });
}
