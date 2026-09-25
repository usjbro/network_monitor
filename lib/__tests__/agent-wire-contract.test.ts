// Round-trip contract guard (JAM-150).
//
// Every other mapper test in this repo builds its own input object, which
// means it asserts the mapper agrees with *the test author's belief about*
// the wire format. That is exactly how JAM-150 shipped: the doc said
// `agent_status` was flat, the mapper was written flat to match, both test
// layers were written flat to match the mapper, and all of it was wrong
// about what capture-agent/src/wire.rs actually emits. The Rust side did
// not catch it either — wire.rs's own test asserts `line.contains(..)` on
// individual field substrings, which passes for a flat *or* nested shape.
//
// So the fixture here is NOT hand-written. Every line in
// fixtures/agent-wire-samples.jsonl was captured verbatim off a real
// capture-agent's TCP socket (127.0.0.1:9990), one representative event
// per type. If a mapper and the agent ever disagree again, this fails.
//
// To regenerate after an intentional wire change, run the agent and read
// its socket:
//
//   cd capture-agent && cargo build --release
//   REPLAY_FILE=<some.pcap> REPLAY_LOCAL_ADDRS=10.0.0.1 \
//     REPLAY_SPEED=realtime ./target/release/capture-agent &
//   python3 -c "import socket;s=socket.create_connection(('127.0.0.1',9990));\
//     import sys;[sys.stdout.write(s.recv(65536).decode()) for _ in range(20)]"
//
// then keep one line per type and scrub any machine-specific path.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  mapAgentStatusEvent,
  mapCaptureFileStatusEvent,
  mapCaptureStatsEvent,
  mapConnectionEvent,
  mapPacketEvent,
  mapSystemStatsEvent,
  mergeLayerStats,
} from '../agent-mapping';

type WireEvent = { type: string } & Record<string, unknown>;

const samples: WireEvent[] = readFileSync(
  join(__dirname, 'fixtures', 'agent-wire-samples.jsonl'),
  'utf8'
)
  .split('\n')
  .filter((l) => l.trim().length > 0)
  .map((l) => JSON.parse(l) as WireEvent);

function sample(type: string): WireEvent {
  const found = samples.find((e) => e.type === type);
  if (!found) throw new Error(`no captured sample for event type "${type}"`);
  return found;
}

describe('agent wire contract: real captured agent output maps without throwing', () => {
  it('captured every event type the relay maps', () => {
    expect(samples.map((e) => e.type).sort()).toEqual(
      [
        'agent_status',
        'capture_config',
        'capture_file_status',
        'capture_stats',
        'connection_update',
        'layer_update',
        'packet',
        'system_stats',
      ].sort()
    );
  });

  // The JAM-150 regression itself: this is the line app/page.tsx runs on
  // every tick, against bytes the agent really sent.
  it('agent_status maps from the real nested envelope', () => {
    const mapped = mapAgentStatusEvent(sample('agent_status'));
    expect(mapped.mode).toBe('replay');
    expect(mapped.replaySource).toBe('/tmp/incident.pcapng');
    expect(mapped.capturing).toBe(true);
    expect(typeof mapped.interface).toBe('string');
    expect(mapped.directionAttributionUnavailable).toBe(false);
  });

  it('capture_stats maps, including the horizon counters', () => {
    const mapped = mapCaptureStatsEvent(sample('capture_stats'));
    expect(typeof mapped.received).toBe('number');
    expect(typeof mapped.totalConnectionsObserved).toBe('number');
    expect(typeof mapped.capacityEvictions).toBe('number');
    expect(typeof mapped.idleEvictions).toBe('number');
  });

  it('system_stats maps', () => {
    const mapped = mapSystemStatsEvent(sample('system_stats'));
    expect(typeof mapped.hostname).toBe('string');
    expect(typeof mapped.interfaceName).toBe('string');
  });

  it('capture_file_status maps', () => {
    const mapped = mapCaptureFileStatusEvent(sample('capture_file_status'));
    expect(typeof mapped.writing).toBe('boolean');
    expect(typeof mapped.bytesWritten).toBe('number');
  });

  it('connection_update maps', () => {
    const evt = sample('connection_update') as unknown as { connection: unknown };
    const mapped = mapConnectionEvent(evt.connection);
    expect(typeof mapped.id).toBe('string');
    expect(typeof mapped.protocol).toBe('string');
  });

  it('packet maps', () => {
    const evt = sample('packet') as unknown as { packet: Record<string, unknown> };
    const mapped = mapPacketEvent(evt.packet);
    expect(typeof mapped.id).toBe('string');
    expect(typeof mapped.summary).toBe('string');
    expect(mapped.headerHexDump).toMatch(/^aa bb cc dd ee ff/);
    expect(mapped.fields).toContainEqual(expect.objectContaining({
      path: 'http.response.code', type: 'uint', region: 'payload', value: 200,
    }));
    expect(evt.packet).not.toHaveProperty('headerBreakdown');
  });

  it('layer_update merges', () => {
    const evt = sample('layer_update') as unknown as { layers: Array<{ layer: number }> };
    expect(Array.isArray(evt.layers)).toBe(true);
    const byLayer = Object.fromEntries(evt.layers.map((l) => [l.layer, l]));
    const merged = mergeLayerStats(byLayer as never);
    expect(merged).toHaveLength(7);
  });
});
