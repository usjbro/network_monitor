import { describe, expect, it } from 'vitest';
import { compileDisplayFilter, type DisplayFilterRecord } from '../display-filter';
import type { NetworkConnection, PacketFrame, WireField } from '../types';

const field = (path: string, type: WireField['type'], value?: WireField['value']): WireField => ({
  path, label: path, type, value, region: 'header', offset: 0, len: 1,
});
const packet: PacketFrame = {
  id: 'p', timestamp: '', relativeTimeMs: 0, layer: 4, protocol: 'TCP', src: '', dst: '',
  length: 120, summary: '', hexDump: '', headerHexDump: '', fields: [
    field('tcp', 'group'), field('tcp.dst_port', 'uint', 443),
    field('tls.handshake.sni', 'str', 'Example.COM'), field('tcp.flags.syn', 'bool', true),
    field('ip.src', 'addr', '2001:DB8::1'), field('app.quote', 'str', 'say "hello"'),
    field('app.slash', 'str', 'C:\\temp'), field('app.bytes', 'bytes'),
  ],
};
const connection: NetworkConnection = {
  id: 'c', protocol: 'HTTPS', appLayerProtocol: 'HTTPS', transportProtocol: 'TCP', osiStack: '',
  localAddr: '127.0.0.1', localPort: 12345, remoteAddr: '2001:DB8::1', remotePort: 443,
  processName: 'Browser', pid: 1, rxSpeed: 0, txSpeed: 0, rxBytesTotal: 0, txBytesTotal: 0,
  latencyMs: 0, packetLoss: 0, status: 'ESTABLISHED', encryption: '', sparkline: [],
};
const packetRecord: DisplayFilterRecord = { kind: 'packet', packet };
const connectionRecord: DisplayFilterRecord = { kind: 'connection', connection };

function run(source: string, record: DisplayFilterRecord): boolean {
  const result = compileDisplayFilter(source);
  if (!result.ok) throw new Error(`${result.error.message} at ${result.error.position}`);
  return result.predicate(record);
}

describe('compileDisplayFilter', () => {
  it('matches typed packet fields and frame.len', () => {
    expect(run('tcp.dst_port == 443', packetRecord)).toBe(true);
    expect(run('frame.len >= 100', packetRecord)).toBe(true);
    expect(run('tls.handshake.sni == "example.com"', packetRecord)).toBe(true);
  });
  it('does not make an absent field match !=', () => {
    expect(run('tcp.src_port != 443', packetRecord)).toBe(false);
    expect(run('connection.remote_port != 443', packetRecord)).toBe(false);
  });
  it('matches boolean values only with boolean literals', () => {
    expect(run('tcp.flags.syn == true', packetRecord)).toBe(true);
    expect(run('tcp.flags.syn == 1', packetRecord)).toBe(false);
    expect(run('tcp.flags.syn != 1', packetRecord)).toBe(false);
  });
  it('resolves connection values on connection records', () => {
    expect(run('connection.remote_port == 443', connectionRecord)).toBe(true);
    expect(run('connection.remote_port == 443', packetRecord)).toBe(false);
  });
  it('supports membership and substring matching with case-insensitive values', () => {
    expect(run('tcp.dst_port in {80, 443}', packetRecord)).toBe(true);
    expect(run('tls.handshake.sni contains "example"', packetRecord)).toBe(true);
    expect(run('ip.src in {"2001:db8::1"}', packetRecord)).toBe(true);
    expect(run('connection.remote_addr contains "DB8"', connectionRecord)).toBe(true);
    expect(run('connection.process in {"browser", "terminal"}', connectionRecord)).toBe(true);
  });
  it('respects boolean precedence and parentheses', () => {
    expect(run('tcp.dst_port >= 400 and not tcp.dst_port == 80', packetRecord)).toBe(true);
    expect(run('(tcp.dst_port == 80 or tcp.dst_port == 443) and frame.len < 1500', packetRecord)).toBe(true);
    expect(run('tcp.dst_port == 80 or tcp.dst_port == 443 and frame.len > 1500', packetRecord)).toBe(false);
    expect(run('not tcp.src_port == 443', packetRecord)).toBe(true);
  });
  it('handles escaped strings and case-insensitive paths and keywords', () => {
    expect(run('APP.QUOTE == "say \\"hello\\""', packetRecord)).toBe(true);
    expect(run('app.slash == "C:\\\\temp"', packetRecord)).toBe(true);
    expect(run('TCP.DST_PORT IN {443}', packetRecord)).toBe(true);
  });
  it('checks ordered numeric comparisons and exact types', () => {
    expect(run('frame.len > 119', packetRecord)).toBe(true);
    expect(run('frame.len <= 120', packetRecord)).toBe(true);
    expect(run('frame.len < 120', packetRecord)).toBe(false);
    expect(run('tcp.dst_port == "443"', packetRecord)).toBe(false);
    expect(run('tcp.dst_port != "443"', packetRecord)).toBe(false);
    expect(run('tcp.dst_port in {"443"}', packetRecord)).toBe(false);
    expect(run('tls.handshake.sni > "A"', packetRecord)).toBe(false);
    expect(run('tcp.dst_port contains "4"', packetRecord)).toBe(false);
  });
  it('treats unknown and cross-kind paths as absent while recognizing groups', () => {
    expect(run('unknown.path', packetRecord)).toBe(false);
    expect(run('unknown.path != 3', packetRecord)).toBe(false);
    expect(run('constructor', connectionRecord)).toBe(false);
    expect(run('tcp', packetRecord)).toBe(true);
    expect(run('tcp == true', packetRecord)).toBe(false);
    expect(run('tcp.dst_port', connectionRecord)).toBe(false);
    expect(run('connection.transport == "tcp"', connectionRecord)).toBe(true);
  });
  it.each([
    ['', '<end>', 0],
    ['tcp.dst_port ==', '<end>', 15],
    ['tcp.dst_port in {80,', '<end>', 20],
    ['(tcp.dst_port == 443', '<end>', 20],
    ['tcp.dst_port == 443 extra', 'extra', 20],
    ['app.quote == "unterminated', '<end>', 26],
  ])('reports first offending token for %j', (source, token, position) => {
    const result = compileDisplayFilter(source);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatchObject({ token, position });
  });

});
