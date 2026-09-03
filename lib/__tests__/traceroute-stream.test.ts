// lib/__tests__/traceroute-stream.test.ts
import { describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { buildStreamResponse, StreamAgentClient, StreamEnrichmentClient, StreamGeoIpClient } from '@/lib/stream-response';

class FakeAgentClient extends EventEmitter implements StreamAgentClient {
  isConnected(): boolean {
    return true;
  }
}

class FakeEnrichmentClient extends EventEmitter implements StreamEnrichmentClient {
  getMode(): 'off' | 'on-demand' | 'background' {
    return 'off';
  }
  notifyObservedConnections(): void {
    // not exercised by this test
  }
}

class FakeGeoIpClient extends EventEmitter implements StreamGeoIpClient {
  getMode(): 'off' | 'on' {
    return 'on';
  }
  lookup = vi.fn();
}

describe('traceroute_hop and geo_hop_update relay', () => {
  it('forwards a traceroute_hop event from the agent unmodified, and triggers a geoIP lookup for its hopIp', async () => {
    const agent = new FakeAgentClient();
    const enrichment = new FakeEnrichmentClient();
    const geoip = new FakeGeoIpClient();
    const response = buildStreamResponse({ agent, enrichment, geoip });
    const reader = response.body!.getReader();
    await reader.read(); // discard the initial connection_status event

    // Real wire shape (capture-agent/src/wire.rs's `TracerouteHop { hop:
    // Box<TracerouteHopJson> }`): fields nest under `hop`, not flat on the
    // event — a flat fixture here would silently mask a relay-side bug.
    agent.emit('event', { type: 'traceroute_hop', hop: { targetIp: '93.184.216.34', hopNumber: 4, hopIp: '12.122.1.1', rttMs: 18.4 } });
    const { value } = await reader.read();
    const text = new TextDecoder().decode(value);
    expect(text).toContain('"type":"traceroute_hop"');
    expect(geoip.lookup).toHaveBeenCalledWith('12.122.1.1');
  });

  it('forwards a geo_hop_update event once GeoIpClient emits a result', async () => {
    const agent = new FakeAgentClient();
    const enrichment = new FakeEnrichmentClient();
    const geoip = new FakeGeoIpClient();
    const response = buildStreamResponse({ agent, enrichment, geoip });
    const reader = response.body!.getReader();
    await reader.read(); // discard the initial connection_status event

    agent.emit('event', { type: 'traceroute_hop', hop: { targetIp: '93.184.216.34', hopNumber: 4, hopIp: '12.122.1.1', rttMs: 18.4 } });
    await reader.read(); // discard the traceroute_hop pass-through

    geoip.emit('result', { ip: '12.122.1.1', location: { city: 'Ashburn', country: 'US', source: 'geoip' } });
    const { value } = await reader.read();
    const text = new TextDecoder().decode(value);
    expect(text).toContain('"type":"geo_hop_update"');
    expect(text).toContain('Ashburn');
  });

  it('stops forwarding traceroute/geoip events after cancel() unregisters the listeners', async () => {
    const agent = new FakeAgentClient();
    const enrichment = new FakeEnrichmentClient();
    const geoip = new FakeGeoIpClient();
    const response = buildStreamResponse({ agent, enrichment, geoip });

    expect(agent.listenerCount('event')).toBe(2); // onEvent + onTracerouteHop
    expect(geoip.listenerCount('result')).toBe(1);

    await response.body!.cancel();
    expect(agent.listenerCount('event')).toBe(0);
    expect(geoip.listenerCount('result')).toBe(0);
  });
});
