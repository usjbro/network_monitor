import { describe, expect, it } from 'vitest';
import {
  mapAgentStatusEvent,
  mapCaptureConfigErrorEvent,
  mapCaptureConfigEvent,
  mapCaptureFileStatusEvent,
  mapCaptureStatsEvent,
  mapConnectionClosedEvent,
  mapConnectionEvent,
  mapInterfaceErrorEvent,
  mapInterfaceListEvent,
  mapPacketEvent,
  mapSystemStatsEvent,
  mapTracerouteHopEvent,
} from '../agent-mapping';

describe('mapConnectionEvent', () => {
  it('maps agent wire JSON to a NetworkConnection', () => {
    const wire = {
      id: 'tcp-192.168.1.10:51000-93.184.216.34:443',
      protocol: 'HTTPS/TLS',
      appLayerProtocol: 'HTTPS/TLS',
      transportProtocol: 'TCP',
      osiStack: 'L4:TCP -> L3:IP',
      localAddr: '192.168.1.10',
      localPort: 51000,
      remoteAddr: '93.184.216.34',
      remotePort: 443,
      processName: 'Safari',
      pid: 1234,
      rxSpeed: 1024,
      txSpeed: 512,
      rxBytesTotal: 4096,
      txBytesTotal: 2048,
      latencyMs: 20,
      packetLoss: 0,
      status: 'ESTABLISHED',
      encryption: 'TLS',
      sparkline: [1, 2, 3],
    };

    const connection = mapConnectionEvent(wire);

    expect(connection.id).toBe(wire.id);
    expect(connection.transportProtocol).toBe('TCP');
    expect(connection.processName).toBe('Safari');
    expect(connection.pid).toBe(1234);
    expect(connection.status).toBe('ESTABLISHED');
  });

  it('throws on a malformed event rather than silently producing garbage', () => {
    expect(() => mapConnectionEvent({ id: 'incomplete' })).toThrow();
  });

  it('carries ja3Fingerprint/ja3Label through when present', () => {
    const wire = {
      id: 'tcp-192.168.1.10:51000-93.184.216.34:443',
      protocol: 'HTTPS/TLS',
      appLayerProtocol: 'HTTPS/TLS',
      transportProtocol: 'TCP',
      osiStack: 'L4:TCP -> L3:IP',
      localAddr: '192.168.1.10',
      localPort: 51000,
      remoteAddr: '93.184.216.34',
      remotePort: 443,
      processName: 'Safari',
      pid: 1234,
      rxSpeed: 1024,
      txSpeed: 512,
      rxBytesTotal: 4096,
      txBytesTotal: 2048,
      latencyMs: 20,
      packetLoss: 0,
      status: 'ESTABLISHED',
      encryption: 'TLS',
      sparkline: [1, 2, 3],
      ja3Fingerprint: 'deadbeef',
      ja3Label: 'matches Chrome 12x',
    };

    const connection = mapConnectionEvent(wire);

    expect(connection.ja3Fingerprint).toBe('deadbeef');
    expect(connection.ja3Label).toBe('matches Chrome 12x');
  });

  it('leaves ja3Fingerprint/ja3Label undefined when absent from the wire event', () => {
    const wire = {
      id: 'tcp-192.168.1.10:51000-93.184.216.34:443',
      protocol: 'HTTPS/TLS',
      appLayerProtocol: 'HTTPS/TLS',
      transportProtocol: 'TCP',
      osiStack: 'L4:TCP -> L3:IP',
      localAddr: '192.168.1.10',
      localPort: 51000,
      remoteAddr: '93.184.216.34',
      remotePort: 443,
      processName: 'Safari',
      pid: 1234,
      rxSpeed: 1024,
      txSpeed: 512,
      rxBytesTotal: 4096,
      txBytesTotal: 2048,
      latencyMs: 20,
      packetLoss: 0,
      status: 'ESTABLISHED',
      encryption: 'TLS',
      sparkline: [1, 2, 3],
    };

    const connection = mapConnectionEvent(wire);

    expect(connection.ja3Fingerprint).toBeUndefined();
    expect(connection.ja3Label).toBeUndefined();
  });
});

describe('mapConnectionClosedEvent', () => {
  it('extracts the id of the closed connection', () => {
    const wire = { type: 'connection_closed', id: 'Tcp-192.168.1.10:51000-93.184.216.34:443' };

    expect(mapConnectionClosedEvent(wire)).toBe(wire.id);
  });

  it('throws on a malformed event rather than silently producing garbage', () => {
    expect(() => mapConnectionClosedEvent({ type: 'connection_closed' })).toThrow();
  });
});

describe('mapPacketEvent', () => {
  it('maps agent wire JSON to a PacketFrame', () => {
    const wire = {
      id: 'pkt-1',
      timestamp: '2026-08-26T00:00:00.000Z',
      relativeTimeMs: 42,
      layer: 4,
      protocol: 'TCP',
      src: '192.168.1.10:51000',
      dst: '93.184.216.34:443',
      length: 60,
      summary: 'TCP SYN',
      hexDump: '00 01 02',
      headerBreakdown: {
        layer4: {
          transport: 'TCP',
          srcPort: 51000,
          dstPort: 443,
          flags: 'SYN',
          windowSize: 65535,
          seqAck: 'seq=1000 ack=0',
        },
        layer3: {
          ipVersion: 'IPv4',
          srcIp: '192.168.1.10',
          dstIp: '93.184.216.34',
          ttl: 64,
          protocolNum: 6,
          checksum: '0xbeef',
        },
        layer2: {
          srcMac: '00:01:02:03:04:05',
          dstMac: '06:07:08:09:0a:0b',
          ethType: 'IPv4',
        },
      },
    };

    const packet = mapPacketEvent(wire);

    expect(packet.id).toBe('pkt-1');
    expect(packet.layer).toBe(4);
    expect(packet.hexDump).toBe('00 01 02');
    expect(packet.headerBreakdown.layer4?.windowSize).toBe(65535);
    expect(packet.headerBreakdown.layer7).toBeUndefined();
    // Untagged frame in this fixture — vlanTag must be absent, not a
    // fabricated value (see issue #62).
    expect(packet.headerBreakdown.layer2?.vlanTag).toBeUndefined();
  });

  it('carries the 802.1Q VLAN tag through when the frame was tagged', () => {
    const wire = {
      id: 'pkt-2',
      timestamp: '2026-08-26T00:00:00.000Z',
      relativeTimeMs: 42,
      layer: 4,
      protocol: 'TCP',
      src: '192.168.1.10:51000',
      dst: '93.184.216.34:443',
      length: 60,
      summary: 'TCP SYN',
      hexDump: '00 01 02',
      headerBreakdown: {
        layer2: {
          srcMac: '00:01:02:03:04:05',
          dstMac: '06:07:08:09:0a:0b',
          ethType: 'IPv4',
          vlanTag: '100',
        },
      },
    };

    const packet = mapPacketEvent(wire);

    expect(packet.headerBreakdown.layer2?.vlanTag).toBe('100');
  });

  it('carries statusOrCode through for an HTTP response (issue #65)', () => {
    const wire = {
      id: 'pkt-3',
      timestamp: '2026-08-26T00:00:00.000Z',
      relativeTimeMs: 42,
      layer: 4,
      protocol: 'TCP',
      src: '93.184.216.34:443',
      dst: '192.168.1.10:51000',
      length: 60,
      summary: 'TCP',
      hexDump: '00 01 02',
      headerBreakdown: {
        layer7: {
          app: 'HTTP',
          methodOrType: 'RESPONSE',
          pathOrQuery: '',
          statusOrCode: '404',
          payloadBytes: 10,
        },
      },
    };

    const packet = mapPacketEvent(wire);

    expect(packet.headerBreakdown.layer7?.statusOrCode).toBe('404');
  });

  it('throws when headerBreakdown is missing rather than defaulting to {}', () => {
    const wire = {
      id: 'pkt-1',
      timestamp: '2026-08-26T00:00:00.000Z',
      relativeTimeMs: 42,
      layer: 4,
      protocol: 'TCP',
      src: '192.168.1.10:51000',
      dst: '93.184.216.34:443',
      length: 60,
      summary: 'TCP SYN',
      hexDump: '00 01 02',
    };

    expect(() => mapPacketEvent(wire)).toThrow();
  });
});

describe('mapTracerouteHopEvent', () => {
  // Real wire shape (capture-agent/src/wire.rs's `TracerouteHop { hop:
  // Box<TracerouteHopJson> }`): fields nest under `hop`, not flat on the
  // event — see docs/wire-protocol.md. A flat fixture here is exactly what
  // let issue #46 (traceroute_hop events silently dropped) ship undetected.
  it('maps a hop with a response', () => {
    const event = { type: 'traceroute_hop', hop: { targetIp: '93.184.216.34', hopNumber: 4, hopIp: '12.122.1.1', rttMs: 18.4 } };
    const hop = mapTracerouteHopEvent(event);
    expect(hop).toEqual({ targetIp: '93.184.216.34', hopNumber: 4, hopIp: '12.122.1.1', rttMs: 18.4, location: undefined });
  });

  it('maps a no-response hop with hopIp/rttMs undefined, not throwing', () => {
    const event = { type: 'traceroute_hop', hop: { targetIp: '93.184.216.34', hopNumber: 5 } };
    const hop = mapTracerouteHopEvent(event);
    expect(hop.hopIp).toBeUndefined();
    expect(hop.rttMs).toBeUndefined();
  });

  it('throws on an event with no "hop" field at all', () => {
    const event = { type: 'traceroute_hop', targetIp: '93.184.216.34', hopNumber: 4 };
    expect(() => mapTracerouteHopEvent(event)).toThrow('missing "hop" field');
  });
});

describe('mapCaptureStatsEvent', () => {
  // Same nested-envelope shape as traceroute_hop (capture-agent/src/wire.rs's
  // `CaptureStats { stats: CaptureStatsJson }`) — see issue #61.
  it('maps capture stats with nonzero drops and lag', () => {
    const event = {
      type: 'capture_stats',
      stats: {
        received: 5000,
        dropped: 12,
        ifDropped: 3,
        relayLaggedEvents: 7,
        unparseableFrames: 2,
        totalConnectionsObserved: 42,
        capacityEvictions: 3,
        idleEvictions: 7,
      },
    };
    const stats = mapCaptureStatsEvent(event);
    expect(stats).toEqual({
      received: 5000,
      dropped: 12,
      ifDropped: 3,
      relayLaggedEvents: 7,
      unparseableFrames: 2,
      totalConnectionsObserved: 42,
      capacityEvictions: 3,
      idleEvictions: 7,
    });
  });

  it('maps healthy zero-drop stats', () => {
    const event = {
      type: 'capture_stats',
      stats: {
        received: 5000,
        dropped: 0,
        ifDropped: 0,
        relayLaggedEvents: 0,
        unparseableFrames: 0,
        totalConnectionsObserved: 5000,
        capacityEvictions: 0,
        idleEvictions: 0,
      },
    };
    const stats = mapCaptureStatsEvent(event);
    expect(stats.dropped).toBe(0);
    expect(stats.ifDropped).toBe(0);
    expect(stats.relayLaggedEvents).toBe(0);
    expect(stats.unparseableFrames).toBe(0);
    expect(stats.capacityEvictions).toBe(0);
    expect(stats.idleEvictions).toBe(0);
  });

  it('throws on an event with no "stats" field at all', () => {
    const event = { type: 'capture_stats', received: 5000 };
    expect(() => mapCaptureStatsEvent(event)).toThrow('missing "stats" field');
  });

  it('carries the three horizon/eviction counters (JAM-6/GitHub #73)', () => {
    const event = {
      type: 'capture_stats',
      stats: {
        received: 100,
        dropped: 0,
        ifDropped: 0,
        relayLaggedEvents: 0,
        unparseableFrames: 0,
        totalConnectionsObserved: 42,
        capacityEvictions: 3,
        idleEvictions: 7,
      },
    };
    const mapped = mapCaptureStatsEvent(event);
    expect(mapped.totalConnectionsObserved).toBe(42);
    expect(mapped.capacityEvictions).toBe(3);
    expect(mapped.idleEvictions).toBe(7);
  });

  it('throws when a horizon/eviction counter is missing, same as any other required field', () => {
    const event = {
      type: 'capture_stats',
      stats: { received: 100, dropped: 0, ifDropped: 0, relayLaggedEvents: 0, unparseableFrames: 0, totalConnectionsObserved: 42 },
    };
    expect(() => mapCaptureStatsEvent(event)).toThrow('missing required field "capacityEvictions"');
  });
});

describe('mapAgentStatusEvent', () => {
  // Flat (no nested envelope), revived by epic #55 — see docs/wire-protocol.md.
  it('maps a live-mode status with directionAttributionUnavailable false', () => {
    const event = { type: 'agent_status', interface: 'en0', capturing: true, mode: 'live', directionAttributionUnavailable: false };
    expect(mapAgentStatusEvent(event)).toEqual({
      interface: 'en0',
      capturing: true,
      mode: 'live',
      replaySource: undefined,
      directionAttributionUnavailable: false,
    });
  });

  it('maps a replay-mode status including replaySource', () => {
    const event = {
      type: 'agent_status',
      interface: 'unknown (replayed pcapng, no if_name recorded)',
      capturing: true,
      mode: 'replay',
      replaySource: '/tmp/x.pcapng',
      directionAttributionUnavailable: true,
    };
    const mapped = mapAgentStatusEvent(event);
    expect(mapped.mode).toBe('replay');
    expect(mapped.replaySource).toBe('/tmp/x.pcapng');
    expect(mapped.directionAttributionUnavailable).toBe(true);
  });

  it('throws on a malformed event rather than silently producing garbage', () => {
    expect(() => mapAgentStatusEvent({ type: 'agent_status', interface: 'en0' })).toThrow();
  });
});

describe('mapCaptureFileStatusEvent', () => {
  // Nested envelope under a "status" key, same shape as capture_stats/
  // system_stats — see epic #55 and docs/wire-protocol.md.
  it('maps an active-writing status including a ring file number', () => {
    const event = {
      type: 'capture_file_status',
      status: { writing: true, path: '/tmp/capture-0001.pcapng', bytesWritten: 4096, ringFile: 1, backpressureDrops: 0 },
    };
    const mapped = mapCaptureFileStatusEvent(event);
    expect(mapped.writing).toBe(true);
    expect(mapped.path).toBe('/tmp/capture-0001.pcapng');
    expect(mapped.bytesWritten).toBe(4096);
    expect(mapped.ringFile).toBe(1);
    expect(mapped.ringTotal).toBeUndefined();
    expect(mapped.autostopReason).toBeUndefined();
  });

  it('maps a stopped, never-started status with no path/ring fields', () => {
    const event = { type: 'capture_file_status', status: { writing: false, bytesWritten: 0, backpressureDrops: 0 } };
    const mapped = mapCaptureFileStatusEvent(event);
    expect(mapped.writing).toBe(false);
    expect(mapped.path).toBeUndefined();
    expect(mapped.bytesWritten).toBe(0);
  });

  it('carries an autostopReason on the one tick a run just stopped itself', () => {
    const event = {
      type: 'capture_file_status',
      status: { writing: false, path: '/tmp/capture-0003.pcapng', bytesWritten: 900000, ringFile: 3, autostopReason: 'totalSize', backpressureDrops: 0 },
    };
    const mapped = mapCaptureFileStatusEvent(event);
    expect(mapped.autostopReason).toBe('totalSize');
  });

  it('throws on a missing status field, matching every other envelope mapper', () => {
    expect(() => mapCaptureFileStatusEvent({ type: 'capture_file_status' })).toThrow('missing "status" field');
  });
});

describe('mapSystemStatsEvent', () => {
  // Same nested-envelope shape as capture_stats/traceroute_hop — see issue #64.
  it('maps a full system_stats event', () => {
    const event = {
      type: 'system_stats',
      stats: {
        hostname: 'osi-gw-01',
        interfaceName: 'en0',
        ipAddress: '192.168.1.104',
        rxTotalMbps: 4.68,
        txTotalMbps: 3.7,
        rxPpsTotal: 480,
        txPpsTotal: 220,
        totalPacketsCaptured: 184200,
      },
    };
    const stats = mapSystemStatsEvent(event);
    expect(stats).toEqual({
      hostname: 'osi-gw-01',
      interfaceName: 'en0',
      ipAddress: '192.168.1.104',
      rxTotalMbps: 4.68,
      txTotalMbps: 3.7,
      rxPpsTotal: 480,
      txPpsTotal: 220,
      totalPacketsCaptured: 184200,
    });
  });

  it('maps an all-zero (healthy, idle) system_stats event without throwing', () => {
    const event = {
      type: 'system_stats',
      stats: {
        hostname: '',
        interfaceName: 'en0',
        ipAddress: '',
        rxTotalMbps: 0,
        txTotalMbps: 0,
        rxPpsTotal: 0,
        txPpsTotal: 0,
        totalPacketsCaptured: 0,
      },
    };
    const stats = mapSystemStatsEvent(event);
    expect(stats.hostname).toBe('');
    expect(stats.rxTotalMbps).toBe(0);
  });

  it('throws on an event with no "stats" field at all', () => {
    const event = { type: 'system_stats', hostname: 'osi-gw-01' };
    expect(() => mapSystemStatsEvent(event)).toThrow('missing "stats" field');
  });
});

describe('mapCaptureConfigEvent', () => {
  // Same nested-envelope shape as mapCaptureStatsEvent/mapSystemStatsEvent
  // above — see issue #68.
  it('maps an active filter and narrowed snap length', () => {
    const event = { type: 'capture_config', config: { filter: 'tcp port 443', snaplen: 96 } };
    const config = mapCaptureConfigEvent(event);
    expect(config).toEqual({ filter: 'tcp port 443', snaplen: 96 });
  });

  it('maps an explicit null filter (no filter active) rather than throwing on it', () => {
    const event = { type: 'capture_config', config: { filter: null, snaplen: 65535 } };
    const config = mapCaptureConfigEvent(event);
    expect(config.filter).toBeNull();
    expect(config.snaplen).toBe(65535);
  });

  it('throws on an event with no "config" field at all', () => {
    const event = { type: 'capture_config', filter: 'tcp port 443' };
    expect(() => mapCaptureConfigEvent(event)).toThrow('missing "config" field');
  });
});

describe('mapCaptureConfigErrorEvent', () => {
  it('extracts the error message', () => {
    const event = { type: 'capture_config_error', message: 'invalid capture filter: syntax error' };
    expect(mapCaptureConfigErrorEvent(event)).toBe('invalid capture filter: syntax error');
  });

  it('throws on an event with no "message" field at all', () => {
    const event = { type: 'capture_config_error' };
    expect(() => mapCaptureConfigErrorEvent(event)).toThrow('missing required field "message"');
  });
});

describe('mapInterfaceListEvent', () => {
  it('maps a list of capturable interfaces with their addresses', () => {
    const event = {
      type: 'interface_list',
      interfaces: [
        { name: 'en0', addresses: ['192.168.1.104'] },
        { name: 'lo0', addresses: ['127.0.0.1', '::1'] },
      ],
    };
    const interfaces = mapInterfaceListEvent(event);
    expect(interfaces).toEqual([
      { name: 'en0', addresses: ['192.168.1.104'] },
      { name: 'lo0', addresses: ['127.0.0.1', '::1'] },
    ]);
  });

  it('maps an empty list without throwing (no capturable interfaces)', () => {
    const event = { type: 'interface_list', interfaces: [] };
    expect(mapInterfaceListEvent(event)).toEqual([]);
  });

  it('throws on an event with no "interfaces" field at all', () => {
    const event = { type: 'interface_list' };
    expect(() => mapInterfaceListEvent(event)).toThrow('missing "interfaces" field');
  });
});

describe('mapInterfaceErrorEvent', () => {
  it('extracts the error message', () => {
    const event = { type: 'interface_error', message: 'no such interface: en9' };
    expect(mapInterfaceErrorEvent(event)).toBe('no such interface: en9');
  });

  it('throws on an event with no "message" field at all', () => {
    const event = { type: 'interface_error' };
    expect(() => mapInterfaceErrorEvent(event)).toThrow('missing required field "message"');
  });
});
