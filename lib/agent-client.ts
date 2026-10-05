import { EventEmitter } from 'node:events';
import net from 'node:net';
import { StringDecoder } from 'node:string_decoder';
import { readAgentToken, resolveAgentTokenPath } from './agent-auth';
import { isAgentAuthenticatedMessage } from './agent-mapping';
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
      this.buffer = '';
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
        this.emit('status', { connected: true });
        if (!active()) return;
        chunk = chunk.subarray(newline + 1);
      }
      this.buffer += decoder.write(chunk);
      let newlineIndex: number;
      while ((newlineIndex = this.buffer.indexOf('\n')) !== -1) {
        const line = this.buffer.slice(0, newlineIndex);
        this.buffer = this.buffer.slice(newlineIndex + 1);
        if (line.trim().length === 0) continue;
        try {
          const event = JSON.parse(line);
          if (event?.type === 'authenticate' || event?.type === 'authenticated') continue;
          this.emit('event', event);
          if (!active()) return;
        } catch {
          // Preserve normal post-authentication tolerance of malformed event lines.
        }
      }
    });
    socket.on('error', disconnect);
    socket.on('close', disconnect);
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
  ): void {
    if (this.authenticated) this.socket?.write(JSON.stringify(message) + '\n');
  }

  isConnected(): boolean {
    return this.authenticated && this.socket !== null;
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    if (this.authTimer) clearTimeout(this.authTimer);
    this.authTimer = null;
    this.authenticated = false;
    this.buffer = '';
    this.socket?.destroy();
    this.socket = null;
  }
}
