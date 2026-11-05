import net from 'node:net';

export interface WhoisServerFixture {
  server: net.Server;
  port: number;
  readonly peerResetCount: number;
  close(): Promise<void>;
}

// A size-limited client deliberately destroys its connection before EOF. Only
// fixtures exercising that abort may tolerate ECONNRESET on the accepted peer.
export async function startWhoisServer(
  onConnection: (socket: net.Socket) => void,
  { allowPeerReset = false }: { allowPeerReset?: boolean } = {},
): Promise<WhoisServerFixture> {
  const sockets = new Set<net.Socket>();
  const failures: Error[] = [];
  let peerResetCount = 0;
  let closing: Promise<void> | undefined;
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('error', (error: NodeJS.ErrnoException) => {
      if (allowPeerReset && error.code === 'ECONNRESET') peerResetCount++;
      else failures.push(error);
    });
    socket.once('close', () => sockets.delete(socket));
    onConnection(socket);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  return {
    server,
    port: (server.address() as net.AddressInfo).port,
    get peerResetCount() { return peerResetCount; },
    close() {
      if (!closing) {
        closing = (async () => {
          const serverClosed = new Promise<void>((resolve, reject) => {
            server.close((error) => error ? reject(error) : resolve());
          });
          const socketClosures = [...sockets].map((socket) => new Promise<void>((resolve) => {
            socket.once('close', () => resolve());
            socket.destroy();
          }));
          await Promise.all([serverClosed, ...socketClosures]);
          if (failures.length) throw new AggregateError(failures, 'Unexpected WHOIS fixture socket errors');
        })();
      }
      return closing;
    },
  };
}
