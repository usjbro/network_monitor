import { describe, expect, it } from 'vitest';
import { mapDecryptedPayloadEvent } from '@/lib/decrypted-mapping';

describe('mapDecryptedPayloadEvent', () => {
  it('decodes base64 payload data and carries redacted/streamId through', () => {
    const event = {
      type: 'decrypted_payload',
      payload: { connectionId: 'Tcp-1-2', direction: 'server_to_client', streamId: 3, redacted: false, dataBase64: Buffer.from('hello').toString('base64') },
    };
    const seg = mapDecryptedPayloadEvent(event);
    expect(seg.connectionId).toBe('Tcp-1-2');
    expect(seg.direction).toBe('server_to_client');
    expect(seg.streamId).toBe(3);
    expect(seg.text).toBe('hello');
    expect(seg.redacted).toBe(false);
  });

  it('leaves streamId undefined when absent from the wire event', () => {
    const event = {
      type: 'decrypted_payload',
      payload: { connectionId: 'Tcp-1-2', direction: 'client_to_server', redacted: true, dataBase64: Buffer.from('[REDACTED]').toString('base64') },
    };
    const seg = mapDecryptedPayloadEvent(event);
    expect(seg.streamId).toBeUndefined();
    expect(seg.direction).toBe('client_to_server');
    expect(seg.redacted).toBe(true);
    expect(seg.text).toBe('[REDACTED]');
  });

  it('throws on a malformed event missing required fields, loudly not silently', () => {
    expect(() => mapDecryptedPayloadEvent({ type: 'decrypted_payload', payload: {} })).toThrow();
  });
});
