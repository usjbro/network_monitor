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
//   python3 - <<'PYTHON'
//   import json, os, pathlib, socket, sys
//   path = pathlib.Path(os.environ.get('AGENT_TOKEN_FILE',
//       str(pathlib.Path.home() / '.network-monitor/agent-control-token')))
//   token = path.read_text().removesuffix('\n')
//   with socket.create_connection(('127.0.0.1', 9990), timeout=10) as sock:
//       sock.sendall((json.dumps({'type': 'authenticate', 'token': token}) + '\n').encode())
//       token = ''
//       feed = sock.makefile('r')
//       assert json.loads(feed.readline()) == {'type': 'authenticated'}
//       for _ in range(20):
//           line = feed.readline()
//           if not line: break
//           sys.stdout.write(line)
//   PYTHON
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
  mapConversationRollupEvent,
  mapEndpointRollupEvent,
  mapFindingEvent,
  mapIoBucketsEvent,
  mapIoSeriesStatusEvent,
  mapPacketEvent,
  mapServiceTimeUpdateEvent,
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
    expect([...new Set(samples.map((e) => e.type))].sort()).toEqual(
      [
        'agent_status',
        'capture_config',
        'capture_file_status',
        'capture_stats',
        'connection_update',
        'conversation_rollup',
        'endpoint_rollup',
        'finding',
        'io_buckets',
        'io_series_status',
        'layer_update',
        'packet',
        'service_time_update',
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

  // JAM-18: captured from a REPLAY_WAIT_FOR_IO_SERIES=1 replay after a
  // set_io_series with one counting and one failing series.
  it('io_series_status maps, keeping a failing series with its filter and error', () => {
    const mapped = mapIoSeriesStatusEvent(sample('io_series_status'));
    expect(mapped.revision).toBe(1);
    expect(mapped.requestId).toBe('c41f09aa');
    expect(mapped.replayWaiting).toBe(false);
    expect(mapped.rejected).toBeUndefined();
    expect(mapped.series.map((s) => [s.id, s.filter, s.ok])).toEqual([
      ['all', '', true],
      ['big', 'frame.len > 1000 and ==', false],
    ]);
    expect(mapped.series[1].error).toEqual({ message: 'Unexpected token', token: '==', position: 21 });
  });

  it('io_buckets maps 100 ms buckets with on-wire byte counts', () => {
    const mapped = mapIoBucketsEvent(sample('io_buckets'));
    const status = mapIoSeriesStatusEvent(sample('io_series_status'));
    expect(mapped.epoch).toBe(status.epoch);
    expect(mapped.bucketMs).toBe(100);
    expect(mapped.coveredToMs - mapped.coveredFromMs).toBe(1000);
    const all = mapped.series.find((s) => s.id === 'all')!;
    expect(all.buckets).toHaveLength(10);
    expect(all.buckets.every(([start, packets, bytes]) => start % 100 === 0 && packets === 4 && bytes === 192)).toBe(true);
    expect(mapped.series.find((s) => s.id === 'big')!.buckets).toEqual([]);
  });

  it('capture_stats maps, including the horizon counters', () => {
    const mapped = mapCaptureStatsEvent(sample('capture_stats'));
    expect(typeof mapped.received).toBe('number');
    expect(typeof mapped.totalConnectionsObserved).toBe('number');
    expect(typeof mapped.capacityEvictions).toBe('number');
    expect(typeof mapped.idleEvictions).toBe('number');
    expect(typeof mapped.observedNameEvictions).toBe('number');
  });

  // KAN-131: both rollups captured from one replay of the capture that
  // capture-agent/tests/non_ip_replay.rs builds (documentation addresses).
  it('endpoint_rollup maps, with its bounds and a real observedName', () => {
    const { rows, bounds } = mapEndpointRollupEvent(sample('endpoint_rollup'));
    expect(rows.map((e) => [e.host, e.observedName, e.historyComplete])).toEqual([
      ['198.51.100.53', undefined, true],
      ['203.0.113.7', 'test.example', true],
      ['203.0.113.8', undefined, true],
    ]);
    expect(bounds).toMatchObject({ cap: 50_000, topN: 200, tracked: 3, evictions: 0, unkeyed: 0, sinceMs: 0, horizonMs: null });
    const sum = (pick: (e: (typeof rows)[number]) => number) => rows.reduce((total, e) => total + pick(e), 0);
    expect(bounds.totals).toEqual({
      rxBytes: sum((e) => e.rxBytesTotal), txBytes: sum((e) => e.txBytesTotal),
      rxPackets: sum((e) => e.rxPacketsTotal), txPackets: sum((e) => e.txPacketsTotal),
    });
    expect(bounds.evicted).toEqual({ rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0 });
  });

  it('conversation_rollup maps, with its bounds', () => {
    const { rows, bounds } = mapConversationRollupEvent(sample('conversation_rollup'));
    expect(rows.map((c) => [c.localAddr, c.remoteAddr])).toEqual([
      ['192.0.2.1', '198.51.100.53'], ['192.0.2.1', '203.0.113.7'], ['192.0.2.1', '203.0.113.8'],
    ]);
    expect(bounds).toMatchObject({ tracked: 3, horizonMs: null });
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
    // JAM-21: the sample's response carries the phrase and both headers.
    expect(mapped.fields).toContainEqual(expect.objectContaining({
      path: 'http.response.phrase', type: 'str', value: 'OK',
    }));
    expect(mapped.fields).toContainEqual(expect.objectContaining({
      path: 'http.content_type', type: 'str', region: 'payload', value: 'text/html',
    }));
    expect(mapped.fields).toContainEqual(expect.objectContaining({
      path: 'http.content_length', type: 'uint', region: 'payload', value: 1234,
    }));
    expect(evt.packet).not.toHaveProperty('headerBreakdown');
  });

  // JAM-21: captured from a replay of a response declaring 2^53 bytes, which a
  // JSON number can't hold exactly, so the agent sends a decimal string.
  it('packet maps a Content-Length above 2^53 - 1 as a string', () => {
    const packets = samples.filter((e) => e.type === 'packet') as unknown as { packet: unknown }[];
    expect(packets).toHaveLength(2);
    const mapped = mapPacketEvent(packets[1].packet);
    expect(mapped.fields).toContainEqual(expect.objectContaining({
      path: 'http.content_length', type: 'uint', region: 'payload', value: '9007199254740992',
    }));
  });

  // JAM-15. Captured from a replay of a DNS query left unanswered for
  // longer than the 5 s DNS timeout.
  it('finding maps an unanswered-request finding with both of its links', () => {
    const mapped = mapFindingEvent(sample('finding'));
    expect(mapped.code).toBe('unanswered-request');
    expect(mapped.summary).toBe('no DNS response to "slow.example" A within 5 s');
    expect(mapped.frameId).toMatch(/^pkt-/);
    expect(mapped.flowId).toBe('Udp-10.0.0.2:40001-10.0.0.1:53');
  });

  it('service_time_update maps both protocols', () => {
    const mapped = mapServiceTimeUpdateEvent(sample('service_time_update'));
    expect(mapped.map((s) => s.protocol)).toEqual(['DNS', 'HTTP']);
    expect(mapped[0]).toMatchObject({ answered: 2, unanswered: 1, minUs: 4000, maxUs: 12000 });
    expect(mapped[1]).toMatchObject({ answered: 1, medianUs: 80000 });
  });

  it('layer_update merges', () => {
    const evt = sample('layer_update') as unknown as { layers: Array<{ layer: number }> };
    expect(Array.isArray(evt.layers)).toBe(true);
    const byLayer = Object.fromEntries(evt.layers.map((l) => [l.layer, l]));
    const merged = mergeLayerStats(byLayer as never);
    expect(merged).toHaveLength(7);
  });
});
