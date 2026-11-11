// KAN-129 Task 2 (spec D5, plan P3): the relay's shared request/response
// core for agent replies that belong to one HTTP request, not the SSE feed.
// TCP stream graphs register `tcp_samples` first; Follow Stream (KAN-110)
// will register `stream_data` with its own ceiling without changing this.
//
// The registry lives on globalThis: the App Router and Pages Router are
// separate bundles, each with its own copy of this module, sharing one
// AgentClient (global.__agentClient). A per-module Map would let one
// bundle's client miss a type the other bundle registered.
import { randomBytes } from 'node:crypto';

export interface ReplyType {
  type: string;
  /** Ceiling for one reply line in UTF-8 bytes, newline included. */
  maxLineBytes: number;
  /** Returns the value the request resolves with; throws when malformed. */
  validate(json: unknown): unknown;
}

declare global {
  var __agentReplyTypes: Map<string, ReplyType> | undefined;
}

function registry(): Map<string, ReplyType> {
  globalThis.__agentReplyTypes ??= new Map();
  return globalThis.__agentReplyTypes;
}

export function registerReplyType(replyType: ReplyType): void {
  registry().set(replyType.type, replyType);
}

export function replyTypeFor(type: unknown): ReplyType | undefined {
  return typeof type === 'string' ? registry().get(type) : undefined;
}

/**
 * The registered reply type a raw line is, judged from its opening bytes.
 * The agent serializes `type` first (serde's internally tagged enums), so a
 * line can be measured against its ceiling before it is parsed, or before
 * its newline has even arrived.
 */
export function replyTypeForLine(line: string): ReplyType | undefined {
  if (!line.startsWith('{"type":"')) return undefined;
  const end = line.indexOf('"', 9);
  return end < 0 ? undefined : registry().get(line.slice(9, end));
}

const REQUEST_ID_IN_HEAD = /"requestId":"([0-9a-f]{32})"/;

/** The requestId in a reply line's first bytes, if it carries a valid one. */
export function requestIdFromHead(line: string): string | undefined {
  return REQUEST_ID_IN_HEAD.exec(line.slice(0, 512))?.[1];
}

/** 499: the caller aborted. 502: bad reply. 503: agent unavailable. 504: no reply in time. */
export type AgentRequestStatus = 499 | 502 | 503 | 504;

export class AgentRequestError extends Error {
  constructor(
    readonly status: AgentRequestStatus,
    message: string,
  ) {
    super(message);
    this.name = 'AgentRequestError';
  }
}

export const REQUEST_TIMEOUT_MS = 5000;
/** Agent socket write backlog above which a request is refused (503). */
export const MAX_AGENT_WRITE_BACKLOG = 64 * 1024;

const REQUEST_ID = /^[0-9a-f]{32}$/;
const RECENTLY_SETTLED = 256;

export function newRequestId(): string {
  return randomBytes(16).toString('hex');
}

export type DropReason = 'unknown' | 'late' | 'malformed' | 'mismatched' | 'oversized' | 'invalid';

interface Entry {
  replyType: string;
  resolve(value: unknown): void;
  reject(error: AgentRequestError): void;
  timer: NodeJS.Timeout;
  signal: AbortSignal;
  onAbort(): void;
}

/** In-flight requests on one agent connection. Every entry settles exactly once. */
export class PendingRequests {
  private entries = new Map<string, Entry>();
  private settled: string[] = [];
  private settledSet = new Set<string>();
  private counts: Record<DropReason, number> = { unknown: 0, late: 0, malformed: 0, mismatched: 0, oversized: 0, invalid: 0 };

  add(requestId: string, replyType: string, timeoutMs: number, signal: AbortSignal): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const onAbort = () => this.fail(requestId, new AgentRequestError(499, 'request aborted'));
      const timer = setTimeout(() => this.fail(requestId, new AgentRequestError(504, 'agent did not reply in time')), timeoutMs);
      this.entries.set(requestId, { replyType, resolve, reject, timer, signal, onAbort });
      signal.addEventListener('abort', onAbort, { once: true });
    });
  }

  /** A parsed line of a registered reply type. */
  deliver(reply: Record<string, unknown>, replyType: ReplyType): void {
    const requestId = reply.requestId;
    if (typeof requestId !== 'string' || !REQUEST_ID.test(requestId)) return this.drop('malformed');
    const entry = this.entries.get(requestId);
    if (!entry) return this.drop(this.settledSet.has(requestId) ? 'late' : 'unknown');
    if (entry.replyType !== replyType.type) return this.drop('mismatched');
    let value: unknown;
    try {
      value = replyType.validate(reply);
    } catch {
      this.drop('invalid');
      return this.fail(requestId, new AgentRequestError(502, 'invalid agent reply'));
    }
    this.take(requestId)?.resolve(value);
  }

  /** A reply line over its ceiling: its request (when the line named one) fails 502. */
  oversized(requestId: string | undefined): void {
    this.drop('oversized');
    if (requestId) this.fail(requestId, new AgentRequestError(502, 'agent reply too large'));
  }

  failAll(status: AgentRequestStatus, message: string): void {
    for (const requestId of [...this.entries.keys()]) this.fail(requestId, new AgentRequestError(status, message));
  }

  size(): number {
    return this.entries.size;
  }

  dropped(): Readonly<Record<DropReason, number>> {
    return { ...this.counts };
  }

  private drop(reason: DropReason): void {
    this.counts[reason] += 1;
  }

  private fail(requestId: string, error: AgentRequestError): void {
    this.take(requestId)?.reject(error);
  }

  private take(requestId: string): Entry | undefined {
    const entry = this.entries.get(requestId);
    if (!entry) return undefined;
    this.entries.delete(requestId);
    clearTimeout(entry.timer);
    entry.signal.removeEventListener('abort', entry.onAbort);
    this.settled.push(requestId);
    this.settledSet.add(requestId);
    if (this.settled.length > RECENTLY_SETTLED) this.settledSet.delete(this.settled.shift()!);
    return entry;
  }
}
