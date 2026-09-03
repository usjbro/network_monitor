import { DecryptedPayloadSegment } from './types';

// Kept separate from agent-mapping.ts for the same reason
// enrichment-mapping.ts was kept separate in sub-project 2: Tier B
// decrypted content has different trust/sensitivity characteristics than
// ordinary packet/connection metadata, and deserves its own small,
// independently-auditable mapper rather than being folded into the general
// wire-event mapping module.
export function mapDecryptedPayloadEvent(raw: unknown): DecryptedPayloadSegment {
  const w = raw as { payload?: Record<string, unknown> };
  const payload = w.payload;
  if (!payload || typeof payload.connectionId !== 'string' || typeof payload.dataBase64 !== 'string') {
    throw new Error('malformed decrypted_payload event: missing required fields');
  }
  return {
    connectionId: payload.connectionId,
    streamId: typeof payload.streamId === 'number' ? payload.streamId : undefined,
    text: Buffer.from(payload.dataBase64, 'base64').toString('utf8'),
    redacted: Boolean(payload.redacted),
  };
}
