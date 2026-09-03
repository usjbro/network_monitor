// lib/__tests__/enrichment-whois-client.test.ts
import { describe, expect, it, afterEach } from 'vitest';
import net from 'node:net';
import { queryWhois, WHOIS_ALLOWLIST } from '../enrichment/whois-client';

describe('queryWhois', () => {
  let server: net.Server;
  afterEach(() => server?.close());

  it('returns response text under the 64KB cap', async () => {
    server = net.createServer((socket) => {
      socket.on('data', () => socket.end('Registrant Organization: Example Org\r\n'));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as net.AddressInfo).port;

    const entry = { matches: () => true, host: '127.0.0.1', port, fieldPatterns: {} };
    const text = await queryWhois(entry, 'example.test');
    expect(text).toContain('Example Org');
  });

  it('aborts and treats an oversized response as a failure rather than buffering it fully', async () => {
    server = net.createServer((socket) => {
      socket.on('data', () => {
        const big = Buffer.alloc(100 * 1024, 'a'); // 100KB > 64KB cap
        socket.write(big);
        // deliberately never .end() — client must abort based on size, not EOF
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as net.AddressInfo).port;

    const entry = { matches: () => true, host: '127.0.0.1', port, fieldPatterns: {} };
    const text = await queryWhois(entry, 'example.test');
    expect(text).toBeNull();
  });

  it('times out rather than hanging when the server never responds', async () => {
    server = net.createServer(() => {}); // accepts, never writes, never closes
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as net.AddressInfo).port;

    const entry = { matches: () => true, host: '127.0.0.1', port, fieldPatterns: {} };
    const text = await queryWhois(entry, 'example.test', { timeoutMs: 50 });
    expect(text).toBeNull();
  });

  it('resolves null (not a thrown error) when the connection is refused', async () => {
    // Nothing listening on this port.
    const entry = { matches: () => true, host: '127.0.0.1', port: 1, fieldPatterns: {} };
    const text = await queryWhois(entry, 'example.test', { timeoutMs: 500 });
    expect(text).toBeNull();
  });

  it('the shipped allowlist has at most 5 entries', () => {
    expect(WHOIS_ALLOWLIST.length).toBeLessThanOrEqual(5);
  });

  it('every shipped allowlist entry only defines org-level field patterns (org/registrant)', () => {
    for (const entry of WHOIS_ALLOWLIST) {
      for (const key of Object.keys(entry.fieldPatterns)) {
        expect(['org', 'registrant']).toContain(key);
      }
    }
  });
});
