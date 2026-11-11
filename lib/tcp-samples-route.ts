// KAN-129 Task 2 (spec D5, plan P5): POST /api/tcp-samples. The behaviour
// lives here; pages/api/tcp-samples.ts only exports it, since a Pages API
// route module may export nothing but its handler and config.
//
// A Node Pages route rather than an App Router handler so the admission
// lease is released on the Node ServerResponse's finish, close or error:
// the moment the reply has left this process or the client has gone, not
// when a producer closes a web stream (Follow Stream plan P1).
//
// Guards, in order, as /api/control's: method (405), cross-site (403),
// bounded body (413), validation (400), then admission (429).
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Admission } from './agent-admission';
import { getAgentClient } from './agent-client-singleton';
import { AgentRequestError } from './agent-request';
import { isCrossSite } from './same-origin';
import { TCP_SAMPLES_MAX_LINE_BYTES, TCP_SAMPLES_REPLY, type TcpSamplesReplyEnvelope } from './tcp-samples-reply';

export const TCP_SAMPLES_MAX_IN_FLIGHT = 4;
export const TCP_SAMPLES_RESERVATION_BYTES = TCP_SAMPLES_MAX_LINE_BYTES;
export const TCP_SAMPLES_MAX_BODY_BYTES = 512;
export const TCP_SAMPLES_MAX_CONNECTION_ID = 128;
const GENERATION = /^[0-9a-f]{16}:\d{1,20}$/;

export interface TcpSamplesAgent {
  request<T>(message: Record<string, unknown>, opts: { replyType: string; signal: AbortSignal; timeoutMs?: number }): Promise<T>;
}

export interface TcpSamplesDeps {
  agent?: TcpSamplesAgent;
  admission?: Admission;
}

declare global {
  var __tcpSamplesAdmission: Admission | undefined;
}

function sharedAdmission(): Admission {
  globalThis.__tcpSamplesAdmission ??= new Admission({
    maxInFlight: TCP_SAMPLES_MAX_IN_FLIGHT,
    reservationBytes: TCP_SAMPLES_RESERVATION_BYTES,
  });
  return globalThis.__tcpSamplesAdmission;
}

/** Fixed bodies, each well under 256 bytes. Nothing from the request or the agent is echoed. */
const ERRORS = {
  400: 'invalid request',
  403: 'cross-site request rejected',
  405: 'method not allowed',
  413: 'request body too large',
  429: 'too many tcp sample requests',
  502: 'invalid agent reply',
  503: 'agent unavailable',
  504: 'agent did not reply in time',
} as const;

type ErrorStatus = keyof typeof ERRORS;

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  if (res.headersSent || res.destroyed) return;
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': String(Buffer.byteLength(payload)),
    'Cache-Control': 'no-store',
    ...extra,
  });
  res.end(payload);
}

function sendError(res: ServerResponse, status: ErrorStatus, extra: Record<string, string> = {}): void {
  sendJson(res, status, { error: ERRORS[status] }, extra);
}

function header(req: IncomingMessage, name: string): string | null {
  const value = req.headers[name];
  if (Array.isArray(value)) return value[0] ?? null;
  return value ?? null;
}

/** This request's own origin, as the browser addressed it (Host is allowlisted by middleware.ts). */
function ownUrl(req: IncomingMessage): string {
  const encrypted = (req.socket as { encrypted?: boolean }).encrypted === true;
  const forwarded = header(req, 'x-forwarded-proto') ?? '';
  const protocol = encrypted || forwarded.split(',')[0].trim() === 'https' ? 'https' : 'http';
  return `${protocol}://${header(req, 'host') ?? 'localhost'}/api/tcp-samples`;
}

/** The body, or `null` when it exceeds `limit` bytes (declared or streamed). */
function readBody(req: IncomingMessage, limit: number): Promise<Buffer | null> {
  const declared = Number(header(req, 'content-length'));
  if (Number.isFinite(declared) && declared > limit) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const onData = (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        cleanup();
        resolve(null);
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => {
      cleanup();
      resolve(Buffer.concat(chunks));
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
    };
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
  });
}

interface TcpSamplesQuery {
  connectionId: string;
  generation?: string;
  fromIndex?: number;
}

function parseQuery(body: Buffer): TcpSamplesQuery | null {
  let json: unknown;
  try {
    json = JSON.parse(body.toString('utf8'));
  } catch {
    return null;
  }
  if (typeof json !== 'object' || json === null || Array.isArray(json)) return null;
  const { connectionId, generation, fromIndex } = json as Record<string, unknown>;
  if (typeof connectionId !== 'string' || connectionId.length === 0 || connectionId.length > TCP_SAMPLES_MAX_CONNECTION_ID) {
    return null;
  }
  if (generation !== undefined && (typeof generation !== 'string' || !GENERATION.test(generation))) return null;
  if (fromIndex !== undefined && !(Number.isSafeInteger(fromIndex) && (fromIndex as number) >= 0)) return null;
  const query: TcpSamplesQuery = { connectionId };
  if (generation !== undefined) query.generation = generation as string;
  if (fromIndex !== undefined) query.fromIndex = fromIndex as number;
  return query;
}

export async function handleTcpSamples(req: IncomingMessage, res: ServerResponse, deps: TcpSamplesDeps = {}): Promise<void> {
  if (req.method !== 'POST') return sendError(res, 405, { Allow: 'POST' });
  if (isCrossSite({ get: (name) => header(req, name) }, ownUrl(req))) return sendError(res, 403);

  let body: Buffer | null;
  try {
    body = await readBody(req, TCP_SAMPLES_MAX_BODY_BYTES);
  } catch {
    return;
  }
  // Connection: close, so an oversized body still arriving is not read on.
  if (body === null) return sendError(res, 413, { Connection: 'close' });
  const query = parseQuery(body);
  if (!query) return sendError(res, 400);

  const lease = (deps.admission ?? sharedAdmission()).tryAcquire(query.connectionId);
  if (!lease) return sendError(res, 429);
  // Released when the response has left this process or the client has gone.
  res.once('finish', lease.release);
  res.once('close', lease.release);
  res.once('error', lease.release);

  const controller = new AbortController();
  res.once('close', () => {
    if (!res.writableFinished) controller.abort();
  });

  try {
    const reply = await (deps.agent ?? getAgentClient()).request<TcpSamplesReplyEnvelope>(
      { type: 'get_tcp_samples', ...query },
      { replyType: TCP_SAMPLES_REPLY, signal: controller.signal },
    );
    if (reply?.connectionId !== query.connectionId) return sendError(res, 502);
    sendJson(res, 200, reply);
  } catch (error) {
    if (!(error instanceof AgentRequestError)) return sendError(res, 502);
    if (error.status === 499) return;
    sendError(res, error.status);
  }
}
