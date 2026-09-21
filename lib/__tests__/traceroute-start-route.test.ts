// Coverage for /api/traceroute/start — request-body validation and the
// "no agent connected" branch. The cross-site guard and the same-origin
// 200 case are already covered by lib/__tests__/same-origin.test.ts, which
// stays scoped to the cross-site policy; this file is the dedicated,
// self-contained suite for the route's own behavior.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { NextRequest } from 'next/server';
import { POST } from '@/app/api/traceroute/start/route';
import type { AgentClient } from '@/lib/agent-client';

function req(body: unknown): NextRequest {
  return {
    url: 'http://127.0.0.1:3000/api/traceroute/start',
    headers: new Headers({ 'sec-fetch-site': 'same-origin' }),
    json: async () => body,
  } as unknown as NextRequest;
}

describe('POST /api/traceroute/start', () => {
  let sendControl: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    sendControl = vi.fn();
    global.__agentClient = { sendControl } as unknown as AgentClient;
  });

  afterEach(() => {
    global.__agentClient = undefined;
  });

  it('forwards a valid remoteAddr as a trace_route control message', async () => {
    const res = await POST(req({ remoteAddr: '93.184.216.34' }));

    expect(res.status).toBe(200);
    expect(sendControl).toHaveBeenCalledWith({ type: 'trace_route', targetIp: '93.184.216.34' });
  });

  it.each([
    ['a missing remoteAddr', {}],
    ['a non-string remoteAddr', { remoteAddr: 42 }],
  ])('rejects %s with 400 without touching the agent', async (_label, body) => {
    const res = await POST(req(body));

    expect(res.status).toBe(400);
    expect(sendControl).not.toHaveBeenCalled();
  });

  it('reports 503 when no agent is connected', async () => {
    global.__agentClient = undefined;

    const res = await POST(req({ remoteAddr: '93.184.216.34' }));

    expect(res.status).toBe(503);
    expect(sendControl).not.toHaveBeenCalled();
  });
});
