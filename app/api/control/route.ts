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
// Same rationale as the two above, for `start_capture_file`'s path. The
// agent's `validate_capture_file_path` is the authoritative check (it's the
// one that knows its own working directory and the `.data/` rule); this is
// only the cheap "obviously not a path" rejection so a hostile request
// never reaches the agent's control channel. 4096 is Linux's PATH_MAX and
// comfortably above macOS's 1024.
const MAX_CAPTURE_FILE_PATH_LEN = 4096;

// `ring.mode`/`autostop.mode` as documented in docs/wire-protocol.md's
// start_capture_file section. Mirrored here (rather than passed through as
// free-form strings) for the same reason as the lengths above — the agent
// re-validates and rejects via `capture_file_error` regardless.
const RING_MODES = ['size', 'duration', 'count'];
const AUTOSTOP_MODES = ['duration', 'totalSize'];

// Shared shape of `start_capture_file`'s two optional {mode, threshold}
// sub-objects. Absent is valid (a plain, non-rotating capture); present but
// malformed is not.
function isValidModeThreshold(value: unknown, allowedModes: string[]): boolean {
  if (value === undefined) return true;
  if (typeof value !== 'object' || value === null) return false;
  const { mode, threshold } = value as { mode?: unknown; threshold?: unknown };
  if (typeof mode !== 'string' || !allowedModes.includes(mode)) return false;
  return typeof threshold === 'number' && Number.isInteger(threshold) && threshold > 0;
}

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
    'start_capture_file',
    'stop_capture_file',
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
  if (body.type === 'start_capture_file') {
    if (
      typeof body.path !== 'string' ||
      body.path.trim().length === 0 ||
      body.path.length > MAX_CAPTURE_FILE_PATH_LEN
    ) {
      return NextResponse.json({ error: 'invalid capture file path' }, { status: 400 });
    }
    if (!isValidModeThreshold(body.ring, RING_MODES)) {
      return NextResponse.json({ error: 'invalid ring configuration' }, { status: 400 });
    }
    if (!isValidModeThreshold(body.autostop, AUTOSTOP_MODES)) {
      return NextResponse.json({ error: 'invalid autostop configuration' }, { status: 400 });
    }
  }
  // `stop_capture_file` carries no fields at all — nothing to validate; the
  // agent treats a stop with no capture active as an idempotent no-op.
  if (!global.__agentClient) {
    return NextResponse.json({ error: 'agent not connected' }, { status: 503 });
  }
  global.__agentClient.sendControl(body);
  return NextResponse.json({ ok: true });
}
