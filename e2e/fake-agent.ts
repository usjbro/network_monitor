import net from 'node:net';
import { readAgentToken } from '../lib/agent-auth';
import { ensureE2EAgentCredential } from './agent-auth-fixture';

// The E2E smoke test's "capture agent" double. Unlike the vitest-level fake
// agents in lib/__tests__ (each spun up fresh per test against an ephemeral
// port, since they construct their own AgentClient directly), this one must
// bind to the real, hardcoded 127.0.0.1:9990 that lib/stream-response.ts's
// getAgentClient() singleton connects to in the real production code path —
// there is no dependency-injection point at the Next.js server-process
// level the way lib/stream-response.ts's StreamRouteDeps offers for unit
// tests. It intentionally speaks the same newline-delimited-JSON wire
// protocol documented in docs/wire-protocol.md, nothing more.
export class FakeAgentDouble {
  private server: net.Server | null = null;
  private sockets = new Set<net.Socket>();
  private buffers = new WeakMap<net.Socket, string>();
  private controlMessages: unknown[] = [];
  private authenticated = new Set<net.Socket>();

  async start(): Promise<void> {
    const token = readAgentToken(ensureE2EAgentCredential());
    this.server = net.createServer((socket) => {
      this.sockets.add(socket);
      this.buffers.set(socket, '');
      socket.on('data', (chunk) => {
        const buffered = (this.buffers.get(socket) ?? '') + chunk.toString('utf8');
        const lines = buffered.split('\n');
        const partial = lines.pop() ?? '';
        this.buffers.set(socket, partial);
        if (!this.authenticated.has(socket) && Buffer.byteLength(lines[0] ?? partial) + (lines.length ? 1 : 0) > 256) { socket.destroy(); return; }
        for (const line of lines) {
          if (!this.authenticated.has(socket)) {
            try {
              const message = JSON.parse(line);
              if (message.type !== 'authenticate' || message.token !== token || Object.keys(message).length !== 2) { socket.destroy(); return; }
            } catch { socket.destroy(); return; }
            this.authenticated.add(socket);
            socket.write('{"type":"authenticated"}\n');
            continue;
          }
          if (line.trim().length === 0) continue;
          try {
            this.controlMessages.push(JSON.parse(line));
          } catch {
            // Not this double's problem — a malformed control message is
            // exactly what the relay itself should be tolerant of.
          }
        }
      });
      const remove = () => { this.sockets.delete(socket); this.authenticated.delete(socket); };
      socket.on('close', remove);
      socket.on('error', remove);
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(9990, '127.0.0.1', resolve);
    });
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }

  // Broadcasts a wire event to every connected client — in practice just
  // the one AgentClient singleton the Next.js server process under test
  // holds, but broadcasting (rather than tracking "the" socket) keeps this
  // double correct across a reconnect mid-run.
  send(event: Record<string, unknown>): void {
    const line = JSON.stringify(event) + '\n';
    for (const socket of this.authenticated) socket.write(line);
  }

  hasReceivedControlMessage(predicate: (msg: unknown) => boolean): boolean {
    return this.controlMessages.some(predicate);
  }

  async waitForControlMessage(
    predicate: (msg: unknown) => boolean,
    timeoutMs = 10_000
  ): Promise<unknown> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const found = this.controlMessages.find(predicate);
      if (found !== undefined) return found;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`no control message matched within ${timeoutMs}ms`);
  }
}
