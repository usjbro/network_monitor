import { EventEmitter } from 'node:events';
import net from 'node:net';

const RECONNECT_DELAY_MS = 2000;

export class AgentClient extends EventEmitter {
  private host: string;
  private port: number;
  private socket: net.Socket | null = null;
  private buffer = '';
  private stopped = false;
  private reconnectTimer: NodeJS.Timeout | null = null;

  constructor(host: string, port: number) {
    super();
    this.host = host;
    this.port = port;
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  private connect(): void {
    if (this.stopped) return;
    const socket = net.createConnection({ host: this.host, port: this.port });
    this.socket = socket;

    socket.on('connect', () => {
      this.emit('status', { connected: true });
    });

    socket.on('data', (chunk) => {
      this.buffer += chunk.toString('utf8');
      let newlineIndex: number;
      while ((newlineIndex = this.buffer.indexOf('\n')) !== -1) {
        const line = this.buffer.slice(0, newlineIndex);
        this.buffer = this.buffer.slice(newlineIndex + 1);
        if (line.trim().length === 0) continue;
        try {
          this.emit('event', JSON.parse(line));
        } catch {
          // Malformed line from the agent — skip it, don't crash the relay.
        }
      }
    });

    const handleDisconnect = () => {
      this.emit('status', { connected: false });
      this.socket = null;
      if (!this.stopped) {
        this.reconnectTimer = setTimeout(() => this.connect(), RECONNECT_DELAY_MS);
      }
    };

    socket.on('error', handleDisconnect);
    socket.on('close', handleDisconnect);
  }

  sendControl(message: { type: 'pause' | 'resume' }): void {
    this.socket?.write(JSON.stringify(message) + '\n');
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.socket?.destroy();
    this.socket = null;
  }
}
