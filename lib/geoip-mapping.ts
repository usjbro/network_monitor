// lib/geoip-mapping.ts
//
// Maps a GeoIpClient 'result' event into the relay-originated `geo_hop_update`
// SSE event. See docs/geoip-protocol.md for the full contract.
import { GeoLocation } from './geoip';

export function buildGeoHopEvent(hopIp: string, hopNumber: number, targetIp: string, location: GeoLocation | null) {
  return {
    type: 'geo_hop_update' as const,
    targetIp,
    hopNumber,
    hopIp,
    location,
  };
}
