// KAN-129 (spec D5): the `tcp_samples` reply type. Imported by
// lib/agent-client.ts, so every AgentClient intercepts it whichever bundle
// created the client: a reply can never fall through to the SSE feed.
//
// This checks only the envelope the relay itself relies on. The sample
// fields are the wire contract Task 3 defines (capture-agent/src/wire.rs,
// lib/types.ts, lib/agent-mapping.ts) and validates in full.
import { registerReplyType } from './agent-request';

export const TCP_SAMPLES_REPLY = 'tcp_samples';
/** Spec D5: the reply line ceiling, newline included. */
export const TCP_SAMPLES_MAX_LINE_BYTES = 256 * 1024;

export interface TcpSamplesReplyEnvelope {
  type: 'tcp_samples';
  connectionId: string;
  [field: string]: unknown;
}

registerReplyType({
  type: TCP_SAMPLES_REPLY,
  maxLineBytes: TCP_SAMPLES_MAX_LINE_BYTES,
  validate(json): TcpSamplesReplyEnvelope {
    if (typeof json !== 'object' || json === null || Array.isArray(json)) throw new Error('not an object');
    const { requestId: _requestId, ...reply } = json as Record<string, unknown>;
    if (reply.type !== TCP_SAMPLES_REPLY || typeof reply.connectionId !== 'string') throw new Error('bad envelope');
    return reply as TcpSamplesReplyEnvelope;
  },
});
