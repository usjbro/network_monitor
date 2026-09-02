// lib/__tests__/traceroute-state.test.ts
//
// app/page.tsx's SSE handler for traceroute_hop/geo_hop_update has no
// route-level test precedent in this repo (same posture the ownership-
// enrichment plan's app/page.tsx wiring took), so per this plan's Task 9
// guidance, the state-merge logic itself is extracted into small pure
// functions here and unit tested, rather than leaving all of Task 9's
// coverage as manual-only.
import { describe, expect, it } from 'vitest';
import { isTraceComplete, mergeGeoHopUpdate, mergeTracerouteHop } from '../traceroute-state';
import { TracerouteHop } from '../types';

describe('mergeTracerouteHop', () => {
  it('appends a hop to a connection with no prior hops', () => {
    const hop: TracerouteHop = { targetIp: '93.184.216.34', hopNumber: 1, hopIp: '10.0.0.1', rttMs: 1.2 };
    const next = mergeTracerouteHop({}, 'conn-1', hop);
    expect(next).toEqual({ 'conn-1': [hop] });
  });

  it('appends a hop after existing hops for the same connection, in order', () => {
    const hop1: TracerouteHop = { targetIp: '93.184.216.34', hopNumber: 1, hopIp: '10.0.0.1', rttMs: 1.2 };
    const hop2: TracerouteHop = { targetIp: '93.184.216.34', hopNumber: 2, hopIp: '10.0.0.2', rttMs: 3.4 };
    const next = mergeTracerouteHop({ 'conn-1': [hop1] }, 'conn-1', hop2);
    expect(next['conn-1']).toEqual([hop1, hop2]);
  });

  it('does not mutate hops belonging to other connections', () => {
    const otherHop: TracerouteHop = { targetIp: '1.1.1.1', hopNumber: 1, hopIp: '1.1.1.1', rttMs: 1 };
    const newHop: TracerouteHop = { targetIp: '93.184.216.34', hopNumber: 1, hopIp: '10.0.0.1', rttMs: 1.2 };
    const next = mergeTracerouteHop({ 'conn-other': [otherHop] }, 'conn-1', newHop);
    expect(next['conn-other']).toEqual([otherHop]);
    expect(next['conn-1']).toEqual([newHop]);
  });
});

describe('mergeGeoHopUpdate', () => {
  it('attaches a location to the matching hop by hopNumber', () => {
    const hop: TracerouteHop = { targetIp: '93.184.216.34', hopNumber: 4, hopIp: '12.122.1.1', rttMs: 18.4 };
    const next = mergeGeoHopUpdate({ 'conn-1': [hop] }, 'conn-1', 4, { city: 'Ashburn', country: 'US' });
    expect(next['conn-1'][0].location).toEqual({ city: 'Ashburn', country: 'US' });
  });

  it('is a no-op when the connection has no tracked hops', () => {
    const traceroute = {};
    const next = mergeGeoHopUpdate(traceroute, 'conn-1', 4, { city: 'Ashburn', country: 'US' });
    expect(next).toBe(traceroute);
  });

  it('leaves other hops for the same connection untouched', () => {
    const hop1: TracerouteHop = { targetIp: '93.184.216.34', hopNumber: 1, hopIp: '10.0.0.1', rttMs: 1.2 };
    const hop2: TracerouteHop = { targetIp: '93.184.216.34', hopNumber: 2, hopIp: '10.0.0.2', rttMs: 3.4 };
    const next = mergeGeoHopUpdate({ 'conn-1': [hop1, hop2] }, 'conn-1', 2, { city: 'X', country: 'US' });
    expect(next['conn-1'][0].location).toBeUndefined();
    expect(next['conn-1'][1].location).toEqual({ city: 'X', country: 'US' });
  });
});

describe('isTraceComplete', () => {
  it('is complete once the hop IP matches the connection remote address', () => {
    const hop: TracerouteHop = { targetIp: '93.184.216.34', hopNumber: 9, hopIp: '93.184.216.34', rttMs: 5 };
    expect(isTraceComplete(hop, '93.184.216.34')).toBe(true);
  });

  it('is complete once the hop ceiling (30) is reached, even with no response', () => {
    const hop: TracerouteHop = { targetIp: '93.184.216.34', hopNumber: 30 };
    expect(isTraceComplete(hop, '93.184.216.34')).toBe(true);
  });

  it('is not complete for an intermediate hop that has not reached the destination', () => {
    const hop: TracerouteHop = { targetIp: '93.184.216.34', hopNumber: 4, hopIp: '12.122.1.1', rttMs: 18.4 };
    expect(isTraceComplete(hop, '93.184.216.34')).toBe(false);
  });
});
