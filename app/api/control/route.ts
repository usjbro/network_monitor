import { NextRequest, NextResponse } from 'next/server';
import { AgentClient } from '@/lib/agent-client';
import { rejectIfCrossSite } from '@/lib/same-origin';

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

// JAM-18 IO graph series (docs/wire-protocol.md "set_io_series"). Not
// exported: a Next.js route module may only export route handlers. These
// bounds mirror the agent's own (capture-agent/src/io_series.rs), which
// re-validates everything; the display-filter source limit is 2048 UTF-16
// code units (JS string length), unlike BPF's MAX_CAPTURE_FILTER_LEN.
const MAX_IO_SERIES = 8;
const MAX_IO_SERIES_FILTER_LEN = 2048;
const IO_SERIES_ID = /^[a-z0-9-]{1,32}$/;
const HEX_TOKEN = /^[0-9a-f]{8,32}$/i;
// Task 5 aggregates (spec D10): the agent checks the field is a uint.
const IO_AGGREGATE_FNS = ['sum', 'min', 'max', 'avg'];
const IO_AGGREGATE_FIELD = /^[A-Za-z0-9_.]{1,64}$/;

type SetIoSeries = {
  type: 'set_io_series';
  baseEpoch: string;
  baseRevision: number;
  requestId: string;
  series: { id: string; filter: string; aggregate?: { fn: string; field: string } }[];
};

function validateSetIoSeries(body: Record<string, unknown>): SetIoSeries | null {
  const { baseEpoch, baseRevision, requestId, series } = body;
  if (typeof baseEpoch !== 'string' || !HEX_TOKEN.test(baseEpoch)) return null;
  if (typeof requestId !== 'string' || !HEX_TOKEN.test(requestId)) return null;
  if (typeof baseRevision !== 'number' || !Number.isInteger(baseRevision) || baseRevision < 0 || baseRevision > 0xffffffff) return null;
  if (!Array.isArray(series) || series.length > MAX_IO_SERIES) return null;
  const ids = new Set<string>();
  const clean: SetIoSeries['series'] = [];
  for (const entry of series) {
    if (typeof entry !== 'object' || entry === null) return null;
    const { id, filter, aggregate } = entry as Record<string, unknown>;
    if (typeof id !== 'string' || !IO_SERIES_ID.test(id) || ids.has(id)) return null;
    if (typeof filter !== 'string' || filter.length > MAX_IO_SERIES_FILTER_LEN) return null;
    ids.add(id);
    if (aggregate === undefined) {
      clean.push({ id, filter });
      continue;
    }
    if (typeof aggregate !== 'object' || aggregate === null) return null;
    const { fn, field } = aggregate as Record<string, unknown>;
    if (typeof fn !== 'string' || !IO_AGGREGATE_FNS.includes(fn)) return null;
    if (typeof field !== 'string' || !IO_AGGREGATE_FIELD.test(field)) return null;
    clean.push({ id, filter, aggregate: { fn, field } });
  }
  return { type: 'set_io_series', baseEpoch, baseRevision, requestId, series: clean };
}

export async function POST(request: NextRequest) {
  // Cross-site rejection first, before the body is even parsed — none of
  // these routes are authenticated, so a page the operator visits must not
  // be able to drive them through the operator's own browser (JAM-151).
  const crossSite = rejectIfCrossSite(request);
  if (crossSite) return crossSite;

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
    'set_io_series',
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
  if (body.type === 'set_io_series') {
    const message = validateSetIoSeries(body);
    if (!message) {
      return NextResponse.json({ error: 'invalid IO graph series' }, { status: 400 });
    }
    if (!global.__agentClient) {
      return NextResponse.json({ error: 'agent not connected' }, { status: 503 });
    }
    // Forward only the validated fields, rebuilt, never the raw body.
    global.__agentClient.sendControl(message);
    return NextResponse.json({ ok: true });
  }
  // `stop_capture_file` carries no fields at all — nothing to validate; the
  // agent treats a stop with no capture active as an idempotent no-op.
  if (!global.__agentClient) {
    return NextResponse.json({ error: 'agent not connected' }, { status: 503 });
  }
  global.__agentClient.sendControl(body);
  return NextResponse.json({ ok: true });
}
