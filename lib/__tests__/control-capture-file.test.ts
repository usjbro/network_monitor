// Coverage for JAM-146 (JAM-125 Task 12): /api/control's allowlist and
// validation for the capture-to-file control messages.
//
// The route is an allowlist, not a pass-through — `start_capture_file` /
// `stop_capture_file` were specified in docs/wire-protocol.md by Task 10
// but never added to it, so the command bar's POSTs would have been
// rejected with a 400 before reaching the agent. These tests pin both the
// allowlist entries and the shape checks that go with them.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { NextRequest } from 'next/server';
import { POST } from '@/app/api/control/route';
import type { AgentClient } from '@/lib/agent-client';

/** A minimal stand-in for NextRequest — the route only calls `.json()`. */
function req(body: unknown): NextRequest {
  return { json: async () => body } as NextRequest;
}

describe('POST /api/control — capture-to-file messages', () => {
  let sendControl: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    sendControl = vi.fn();
    global.__agentClient = { sendControl } as unknown as AgentClient;
  });

  afterEach(() => {
    global.__agentClient = undefined;
  });

  it('forwards a bare start_capture_file to the agent', async () => {
    const res = await POST(req({ type: 'start_capture_file', path: '/tmp/run.pcapng' }));

    expect(res.status).toBe(200);
    expect(sendControl).toHaveBeenCalledWith({ type: 'start_capture_file', path: '/tmp/run.pcapng' });
  });

  it('forwards start_capture_file with valid ring and autostop options', async () => {
    const body = {
      type: 'start_capture_file',
      path: '/tmp/run.pcapng',
      ring: { mode: 'size', threshold: 104857600 },
      autostop: { mode: 'totalSize', threshold: 1048576 },
    };
    const res = await POST(req(body));

    expect(res.status).toBe(200);
    expect(sendControl).toHaveBeenCalledWith(body);
  });

  it('forwards stop_capture_file, which carries no fields', async () => {
    const res = await POST(req({ type: 'stop_capture_file' }));

    expect(res.status).toBe(200);
    expect(sendControl).toHaveBeenCalledWith({ type: 'stop_capture_file' });
  });

  it.each([
    ['a missing path', { type: 'start_capture_file' }],
    ['a non-string path', { type: 'start_capture_file', path: 42 }],
    ['an empty path', { type: 'start_capture_file', path: '' }],
    ['a whitespace-only path', { type: 'start_capture_file', path: '   ' }],
    ['an over-long path', { type: 'start_capture_file', path: `/tmp/${'a'.repeat(4096)}` }],
  ])('rejects %s without touching the agent', async (_label, body) => {
    const res = await POST(req(body));

    expect(res.status).toBe(400);
    expect(sendControl).not.toHaveBeenCalled();
  });

  it.each([
    ['an unknown ring mode', { ring: { mode: 'bogus', threshold: 10 } }],
    ['a zero ring threshold', { ring: { mode: 'size', threshold: 0 } }],
    ['a negative ring threshold', { ring: { mode: 'size', threshold: -1 } }],
    ['a non-integer ring threshold', { ring: { mode: 'size', threshold: 1.5 } }],
    ['a ring that is not an object', { ring: 'size' }],
    // `size`/`count` are ring-only modes — autostop takes duration/totalSize.
    ['a ring-only mode used for autostop', { autostop: { mode: 'size', threshold: 10 } }],
    ['an unknown autostop mode', { autostop: { mode: 'bogus', threshold: 10 } }],
    ['a zero autostop threshold', { autostop: { mode: 'duration', threshold: 0 } }],
  ])('rejects %s without touching the agent', async (_label, extra) => {
    const res = await POST(req({ type: 'start_capture_file', path: '/tmp/run.pcapng', ...extra }));

    expect(res.status).toBe(400);
    expect(sendControl).not.toHaveBeenCalled();
  });

  it('still rejects a control message type that is not on the allowlist', async () => {
    const res = await POST(req({ type: 'rm_minus_rf', path: '/tmp/run.pcapng' }));

    expect(res.status).toBe(400);
    expect(sendControl).not.toHaveBeenCalled();
  });

  it('reports 503 rather than silently succeeding when no agent is connected', async () => {
    global.__agentClient = undefined;

    const res = await POST(req({ type: 'start_capture_file', path: '/tmp/run.pcapng' }));

    expect(res.status).toBe(503);
  });
});
