import { describe, expect, it } from 'vitest';
import { mapFindingEvent } from '@/lib/agent-mapping';

describe('mapFindingEvent', () => {
  it('maps a well-formed finding event, carrying frameId and flowId when present', () => {
    const event = {
      type: 'finding',
      finding: {
        id: 'finding-1000-1',
        timestamp: '1000',
        severity: 'warning',
        code: 'retransmission',
        summary: 'retransmitted segment',
        frameId: 'pkt-1000-1',
        flowId: 'Tcp-192.168.1.10:51000-93.184.216.34:443',
      },
    };
    const finding = mapFindingEvent(event);
    expect(finding.id).toBe('finding-1000-1');
    expect(finding.timestamp).toBe('1000');
    expect(finding.severity).toBe('warning');
    expect(finding.code).toBe('retransmission');
    expect(finding.summary).toBe('retransmitted segment');
    expect(finding.frameId).toBe('pkt-1000-1');
    expect(finding.flowId).toBe('Tcp-192.168.1.10:51000-93.184.216.34:443');
  });

  it('omits frameId and flowId when absent from the wire event, rather than defaulting them', () => {
    const event = {
      type: 'finding',
      finding: {
        id: 'finding-2000-2',
        timestamp: '2000',
        severity: 'warning',
        code: 'malformed-frame',
        summary: '58-byte frame did not decode as Ethernet framing',
      },
    };
    const finding = mapFindingEvent(event);
    expect(finding.frameId).toBeUndefined();
    expect(finding.flowId).toBeUndefined();
  });

  it('throws on a malformed event missing required fields, loudly not silently', () => {
    expect(() => mapFindingEvent({ type: 'finding', finding: {} })).toThrow();
    expect(() => mapFindingEvent({ type: 'finding', finding: { id: 'x' } })).toThrow();
  });

  it('throws when the "finding" envelope key is missing entirely', () => {
    expect(() => mapFindingEvent({ type: 'finding' })).toThrow();
  });
});
