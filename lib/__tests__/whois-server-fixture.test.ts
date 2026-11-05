import { afterEach, describe, expect, it } from 'vitest';
import net from 'node:net';
import { startWhoisServer, type WhoisServerFixture } from './helpers/whois-server';

describe('WHOIS server fixture lifecycle', () => {
  let fixture: WhoisServerFixture | undefined;
  let client: net.Socket | undefined;
  let clientErrors: Error[] = [];
  afterEach(async () => {
    client?.destroy();
    await fixture?.close();
    expect(clientErrors).toEqual([]);
    clientErrors = [];
  });

  it('contains a real peer reset only when the fixture expects a client abort', async () => {
    let acceptedClosed!: Promise<void>;
    fixture = await startWhoisServer((socket) => {
      acceptedClosed = new Promise<void>((resolve) => socket.once('close', () => resolve()));
      socket.write('ready');
    }, { allowPeerReset: true });
    client = net.createConnection({ host: '127.0.0.1', port: fixture.port });
    await new Promise<void>((resolve, reject) => {
      client!.once('error', reject);
      client!.once('data', () => { client!.resetAndDestroy(); resolve(); });
    });
    await acceptedClosed;
    expect(fixture.peerResetCount).toBe(1);
    await expect(fixture.close()).resolves.toBeUndefined();
  });

  it('destroys and awaits accepted connections that never respond before closing the server', async () => {
    let accepted!: () => void;
    const connected = new Promise<void>((resolve) => { accepted = resolve; });
    fixture = await startWhoisServer(() => accepted());
    client = net.createConnection({ host: '127.0.0.1', port: fixture.port });
    client.on('error', (error) => clientErrors.push(error));
    await connected;
    const clientClosed = new Promise<void>((resolve) => client!.once('close', () => resolve()));
    await fixture.close();
    await clientClosed;
    expect(client.destroyed).toBe(true);
    expect(fixture.server.listening).toBe(false);
  });

  it.each([
    { code: 'EIO', allowPeerReset: false },
    { code: 'EIO', allowPeerReset: true },
    { code: 'ECONNRESET', allowPeerReset: false },
  ])('fails teardown for $code with allowPeerReset=$allowPeerReset', async ({ code, allowPeerReset }) => {
    const failure = Object.assign(new Error('unexpected fixture failure'), { code });
    fixture = await startWhoisServer((socket) => socket.emit('error', failure), { allowPeerReset });
    client = net.createConnection({ host: '127.0.0.1', port: fixture.port });
    client.on('error', (error) => clientErrors.push(error));
    await new Promise<void>((resolve) => fixture!.server.once('connection', () => resolve()));
    const failedFixture = fixture;
    fixture = undefined;
    await expect(failedFixture.close()).rejects.toMatchObject({ errors: [failure] });
  });
});
