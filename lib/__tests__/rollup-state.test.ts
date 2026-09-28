import { describe, expect, it } from 'vitest';
import {
  applyConversationEnrichment,
  applyEndpointEnrichment,
  mergeConversationSnapshot,
  mergeEndpointSnapshot,
} from '../rollup-state';
import { Conversation, Endpoint } from '../types';

const enrichment = {
  org: 'Example Org',
  source: 'rdap' as const,
  fetchedAt: '2026-09-28T00:00:00.000Z',
};

function endpoint(overrides: Partial<Endpoint> = {}): Endpoint {
  return {
    host: '93.184.216.34', rxBytesTotal: 100, txBytesTotal: 50,
    rxPacketsTotal: 2, txPacketsTotal: 1, rxSpeed: 10, txSpeed: 5,
    flowCount: 1, firstSeenMs: 0, lastSeenMs: 1000, processName: 'Safari', pid: 1234,
    ...overrides,
  };
}

function conversation(overrides: Partial<Conversation> = {}): Conversation {
  return {
    localAddr: '192.168.1.10', remoteAddr: '93.184.216.34',
    rxBytesTotal: 100, txBytesTotal: 50, rxPacketsTotal: 2, txPacketsTotal: 1,
    rxSpeed: 10, txSpeed: 5, flowCount: 1, firstSeenMs: 0, lastSeenMs: 1000,
    durationMs: 1000, processName: 'Safari', pid: 1234,
    ...overrides,
  };
}

describe('rollup state enrichment', () => {
  it('preserves ownership and PTR hostname when an endpoint snapshot replaces counters', () => {
    const old = endpoint({ enrichment, remoteHostname: 'example.com' });
    const fresh = endpoint({ rxBytesTotal: 200, remoteHostname: undefined, enrichment: undefined });

    expect(mergeEndpointSnapshot([old], [fresh])).toEqual([
      { ...fresh, enrichment, remoteHostname: 'example.com' },
    ]);
  });

  it('preserves ownership and PTR hostname when a conversation snapshot replaces counters', () => {
    const old = conversation({ enrichment, remoteHostname: 'example.com' });
    const fresh = conversation({ rxBytesTotal: 200, remoteHostname: undefined, enrichment: undefined });

    expect(mergeConversationSnapshot([old], [fresh])).toEqual([
      { ...fresh, enrichment, remoteHostname: 'example.com' },
    ]);
  });

  it('applies connection-keyed background enrichment by remote address to endpoints and conversations', () => {
    const event = {
      connectionId: 'Tcp-192.168.1.10:51000-93.184.216.34:443',
      remoteAddr: '93.184.216.34',
      remoteHostname: 'example.com',
      enrichment,
    };
    const endpoints = applyEndpointEnrichment(
      [endpoint(), endpoint({ host: '8.8.8.8' })],
      event,
    );
    const conversations = applyConversationEnrichment(
      [conversation(), conversation({ remoteAddr: '8.8.8.8' })],
      event,
    );

    expect(endpoints[0]).toMatchObject({ enrichment, remoteHostname: 'example.com' });
    expect(conversations[0]).toMatchObject({ enrichment, remoteHostname: 'example.com' });
    expect(endpoints[1].enrichment).toBeUndefined();
    expect(conversations[1].enrichment).toBeUndefined();
  });
});
