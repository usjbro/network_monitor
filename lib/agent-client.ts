import { EventEmitter } from 'node:events';
import net from 'node:net';
import { StringDecoder } from 'node:string_decoder';
import { readAgentToken, resolveAgentTokenPath } from './agent-auth';
import { isAgentAuthenticatedMessage } from './agent-mapping';
import {
  AgentRequestError,
  MAX_AGENT_WRITE_BACKLOG,
  PendingRequests,
  REQUEST_TIMEOUT_MS,
  newRequestId,
  replyTypeFor,
  replyTypeForLine,
  requestIdFromHead,
  type DropReason,
} from './agent-request';
import './tcp-samples-reply';
import type { AgentAuthenticateMessage } from './types';

const RECONNECT_DELAY_MS = 2000;

export class AgentClient extends EventEmitter {
  private host: string;
  private port: number;
  private socket: net.Socket | null = null;
  private buffer = '';
  private stopped = false;
  private reconnectTimer: NodeJS.Timeout | null = null;

  private authenticated = false;
  private authTimer: NodeJS.Timeout | null = null;
  private lastDiagnostic: 'credential' | 'handshake' | null = null;
  // JAM-18: the latest io_series_status from the agent on the current
  // connection, so a browser tab that subscribes later still learns the
  // shared IO graph series set (the agent only sends it on change and on
  // connect). One message; cleared on disconnect, so it is never stale.
  private ioSeriesStatus: unknown = undefined;
  // KAN-129: requests awaiting a correlated reply (lib/agent-request.ts).
  private requests = new PendingRequests();
  // Set while dropping the rest of an over-ceiling reply line.
  private discardingLine = false;

  constructor(host: string, port: number, private tokenPath?: string) {
    super();
    this.host = host;
    this.port = port;
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  private diagnostic(reason: 'credential' | 'handshake'): void {
    if (this.lastDiagnostic === reason) return;
    this.lastDiagnostic = reason;
    console.warn(`capture-agent: ${reason === 'credential' ? 'credential unavailable or unsafe' : 'authentication failed or timed out'}`);
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, RECONNECT_DELAY_MS);
  }

  private connect(): void {
    if (this.stopped || this.socket) return;
    let token: string;
    try { token = readAgentToken(this.tokenPath ?? resolveAgentTokenPath()); }
    catch {
      this.diagnostic('credential');
      this.emit('status', { connected: false });
      this.scheduleReconnect();
      return;
    }
    const socket = net.createConnection({ host: this.host, port: this.port });
    this.socket = socket;
    let handled = false;
    let ackBuffer = Buffer.alloc(0);
    const decoder = new StringDecoder('utf8');
    const active = () => !this.stopped && this.socket === socket && !handled;
    const disconnect = () => {
      if (!active()) return;
      handled = true;
      if (!this.authenticated) this.diagnostic('handshake');
      this.authenticated = false;
      this.ioSeriesStatus = undefined;
      this.buffer = '';
      this.discardingLine = false;
      this.requests.failAll(503, 'agent disconnected');
      ackBuffer.fill(0);
      if (this.authTimer) clearTimeout(this.authTimer);
      this.authTimer = null;
      this.socket = null;
      socket.destroy();
      this.emit('status', { connected: false });
      this.scheduleReconnect();
    };
    socket.once('connect', () => {
      if (!active()) return;
      const message: AgentAuthenticateMessage = { type: 'authenticate', token };
      socket.write(JSON.stringify(message) + '\n');
      token = '';
      this.authTimer = setTimeout(disconnect, 5000);
    });
    socket.on('data', (chunk: Buffer) => {
      if (!active()) return;
      if (!this.authenticated) {
        const newline = chunk.indexOf(10);
        const count = newline < 0 ? chunk.length : newline + 1;
        if (ackBuffer.length + count > 256) { disconnect(); return; }
        ackBuffer = Buffer.concat([ackBuffer, chunk.subarray(0, count)]);
        if (newline < 0) return;
        let ack: unknown;
        try { ack = JSON.parse(ackBuffer.toString('utf8')); }
        catch { disconnect(); return; }
        if (!isAgentAuthenticatedMessage(ack)) { disconnect(); return; }
        ackBuffer.fill(0);
        ackBuffer = Buffer.alloc(0);
        this.authenticated = true;
        if (this.authTimer) clearTimeout(this.authTimer);
        this.authTimer = null;
        this.lastDiagnostic = null;
        // A new authentication is a new agent session: nothing from before it may answer.
        this.requests.failAll(503, 'agent re-authenticated');
        this.emit('status', { connected: true });
        if (!active()) return;
        chunk = chunk.subarray(newline + 1);
      }
      this.buffer += decoder.write(chunk);
      if (this.discardingLine) {
        const end = this.buffer.indexOf('\n');
        if (end < 0) {
          this.buffer = '';
          return;
        }
        this.buffer = this.buffer.slice(end + 1);
        this.discardingLine = false;
      }
      let newlineIndex: number;
      while ((newlineIndex = this.buffer.indexOf('\n')) !== -1) {
        const line = this.buffer.slice(0, newlineIndex);
        this.buffer = this.buffer.slice(newlineIndex + 1);
        if (line.trim().length === 0) continue;
        this.handleLine(line);
        if (!active()) return;
      }
      this.guardPartialReply();
    });
    socket.on('error', disconnect);
    socket.on('close', disconnect);
  }

  /**
   * One complete line. Registered reply types (plan P4) are measured in
   * bytes against their ceiling before parsing and go to their request,
   * never to 'event' listeners; every other line keeps its existing
   * handling.
   */
  private handleLine(line: string): void {
    const prefixed = replyTypeForLine(line);
    if (prefixed && Buffer.byteLength(line, 'utf8') + 1 > prefixed.maxLineBytes) {
      this.requests.oversized(requestIdFromHead(line));
      return;
    }
    let event: unknown;
    try {
      event = JSON.parse(line);
    } catch {
      // Preserve normal post-authentication tolerance of malformed event lines.
      return;
    }
    const type = (event as { type?: unknown } | null)?.type;
    if (type === 'authenticate' || type === 'authenticated') return;
    const replyType = replyTypeFor(type);
    if (replyType) {
      if (!prefixed && Buffer.byteLength(line, 'utf8') + 1 > replyType.maxLineBytes) {
        this.requests.oversized(requestIdFromHead(line));
        return;
      }
      this.requests.deliver(event as Record<string, unknown>, replyType);
      return;
    }
    if (type === 'io_series_status') this.ioSeriesStatus = event;
    this.emit('event', event);
  }

  /**
   * A reply line still waiting for its newline is never buffered past its
   * ceiling: its request fails and the rest of the line is discarded as it
   * arrives. A UTF-16 code unit is at most 3 UTF-8 bytes, so the byte count
   * is only taken once the partial line could possibly be over.
   */
  private guardPartialReply(): void {
    const replyType = replyTypeForLine(this.buffer);
    if (!replyType || this.buffer.length * 3 < replyType.maxLineBytes) return;
    if (Buffer.byteLength(this.buffer, 'utf8') < replyType.maxLineBytes) return;
    this.requests.oversized(requestIdFromHead(this.buffer));
    this.buffer = '';
    this.discardingLine = true;
  }

  /**
   * KAN-129 (spec D5): sends `message` with a fresh 128-bit `requestId` and
   * resolves with the agent's correlated reply of type `replyType`, after
   * that type's `validate`. Rejects with `AgentRequestError`: 499 on abort,
   * 502 for an oversized or invalid reply, 503 when the agent is not
   * connected, disconnects, re-authenticates or has more than 64 KiB of
   * unsent control bytes, and 504 after `timeoutMs` (default 5 s).
   */
  request<T>(
    message: Record<string, unknown>,
    opts: { replyType: string; signal: AbortSignal; timeoutMs?: number },
  ): Promise<T> {
    const replyType = replyTypeFor(opts.replyType);
    if (!replyType) return Promise.reject(new Error(`unregistered reply type ${opts.replyType}`));
    if (opts.signal.aborted) return Promise.reject(new AgentRequestError(499, 'request aborted'));
    const socket = this.socket;
    if (!this.authenticated || !socket) return Promise.reject(new AgentRequestError(503, 'agent not connected'));
    if (socket.writableLength > MAX_AGENT_WRITE_BACKLOG) {
      return Promise.reject(new AgentRequestError(503, 'agent connection backlogged'));
    }
    const requestId = newRequestId();
    const reply = this.requests.add(requestId, replyType.type, opts.timeoutMs ?? REQUEST_TIMEOUT_MS, opts.signal);
    socket.write(JSON.stringify({ ...message, requestId }) + '\n');
    return reply as Promise<T>;
  }

  pendingRequestCount(): number {
    return this.requests.size();
  }

  droppedReplies(): Readonly<Record<DropReason, number>> {
    return this.requests.dropped();
  }

  sendControl(
    message:
      | { type: 'pause' | 'resume' }
      | { type: 'register_decrypt_eligible'; pid: number; keylogPath: string }
      | { type: 'unregister_decrypt_eligible'; pid: number }
      | { type: 'trace_route'; targetIp: string }
      | { type: 'set_capture_filter'; filter: string }
      | { type: 'set_snaplen'; bytes: number }
      | { type: 'list_interfaces' }
      | { type: 'set_interface'; name: string }
      | {
          type: 'set_io_series';
          baseEpoch: string;
          baseRevision: number;
          requestId: string;
          series: { id: string; filter: string }[];
        }
  ): void {
    if (this.authenticated) this.socket?.write(JSON.stringify(message) + '\n');
  }

  latestIoSeriesStatus(): unknown {
    return this.authenticated ? this.ioSeriesStatus : undefined;
  }

  isConnected(): boolean {
    return this.authenticated && this.socket !== null;
  }

  stop(): void {
    this.stopped = true;
    this.ioSeriesStatus = undefined;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    if (this.authTimer) clearTimeout(this.authTimer);
    this.authTimer = null;
    this.authenticated = false;
    this.buffer = '';
    this.discardingLine = false;
    this.requests.failAll(503, 'agent client stopped');
    this.socket?.destroy();
    this.socket = null;
  }
}
