// @vitest-environment jsdom
//
// Formatting and round-trip coverage for lib/export.ts (JAM-147).
// The decrypted-content guarantee lives in decrypted-export-exclusion.test.ts.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { connectionsToCsv, downloadBlob, packetsToJson } from '@/lib/export';
import type { NetworkConnection, PacketFrame } from '@/lib/types';

function connection(overrides: Partial<NetworkConnection> = {}): NetworkConnection {
  return {
    id: 'c1',
    protocol: 'HTTPS',
    appLayerProtocol: 'HTTP/2',
    transportProtocol: 'TCP',
    osiStack: 'L7:HTTP/2 -> L4:TCP',
    localAddr: '10.0.0.1',
    localPort: 51234,
    remoteAddr: '93.184.216.34',
    remotePort: 443,
    processName: 'chrome',
    pid: 4242,
    rxSpeed: 0,
    txSpeed: 0,
    rxBytesTotal: 1024,
    txBytesTotal: 2048,
    latencyMs: 0,
    packetLoss: 0,
    status: 'ESTABLISHED',
    encryption: 'TLS 1.3',
    sparkline: [],
    ...overrides,
  };
}

function packet(overrides: Partial<PacketFrame> = {}): PacketFrame {
  return {
    id: 'pkt-1',
    timestamp: '12:00:00.000',
    relativeTimeMs: 12,
    layer: 4,
    protocol: 'TCP',
    src: '10.0.0.1',
    dst: '93.184.216.34',
    length: 64,
    summary: 'GET /',
    hexDump: '00 01 02 03',
    headerBreakdown: {
      layer4: { transport: 'TCP', srcPort: 51234, dstPort: 443, flags: 'PSH,ACK', windowSize: 65535, seqAck: '1/1' },
      layer3: { ipVersion: 'IPv4', srcIp: '10.0.0.1', dstIp: '93.184.216.34', ttl: 64, protocolNum: 6, checksum: '0x0' },
    },
    ...overrides,
  };
}

describe('connectionsToCsv', () => {
  it('states the observed-vs-shown horizon as a leading comment line', () => {
    const csv = connectionsToCsv([], 41207);
    expect(csv.split('\n')[0]).toBe('# showing 0 of 41207 observed');
  });

  it('writes a header row and one row per connection', () => {
    const csv = connectionsToCsv([connection(), connection({ id: 'c2' })], 2);
    const lines = csv.split('\n');
    expect(lines[1]).toBe('Protocol,Local,Remote,Process,PID,RX Bytes,TX Bytes,Status');
    expect(lines).toHaveLength(4); // horizon + header + 2 rows
    expect(lines[2]).toBe('HTTPS,10.0.0.1:51234,93.184.216.34:443,chrome,4242,1024,2048,ESTABLISHED');
  });

  it('quotes a field containing a comma, per RFC 4180', () => {
    const csv = connectionsToCsv([connection({ processName: 'Chrome, Helper' })], 1);
    expect(csv).toContain('"Chrome, Helper"');
  });

  it('doubles internal quotes rather than emitting them raw', () => {
    const csv = connectionsToCsv([connection({ processName: 'say "hi"' })], 1);
    expect(csv).toContain('"say ""hi"""');
  });

  it('quotes a field containing a newline or carriage return', () => {
    // A process name is network/OS-sourced and not guaranteed well-behaved;
    // an unquoted embedded newline would split one row into two.
    expect(connectionsToCsv([connection({ processName: 'two\nlines' })], 1)).toContain('"two\nlines"');
    expect(connectionsToCsv([connection({ processName: 'two\rlines' })], 1)).toContain('"two\rlines"');
  });

  it('leaves an ordinary field unquoted', () => {
    expect(connectionsToCsv([connection()], 1)).toContain(',chrome,');
  });

  it('exports exactly the rows it is handed, not some wider set', () => {
    // Callers pass the *filtered* table; the exporter must not second-guess.
    const csv = connectionsToCsv([connection({ processName: 'only-me' })], 999);
    expect(csv).toContain('only-me');
    expect(csv.split('\n')).toHaveLength(3);
    expect(csv.split('\n')[0]).toBe('# showing 1 of 999 observed');
  });
});

describe('packetsToJson', () => {
  it('round-trips through JSON.parse with headerBreakdown intact', () => {
    const packets = [packet()];
    const parsed = JSON.parse(packetsToJson(packets));
    expect(parsed).toEqual(packets);
    expect(parsed[0].headerBreakdown.layer4.srcPort).toBe(51234);
  });

  it('is indented for reading rather than minified', () => {
    expect(packetsToJson([packet()])).toContain('\n  {');
  });

  it('handles an empty list', () => {
    expect(JSON.parse(packetsToJson([]))).toEqual([]);
  });
});

describe('downloadBlob', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('attaches the anchor before clicking and removes it afterwards', () => {
    // A detached anchor's click is ignored by Firefox, and leaving it
    // attached leaks a node per export.
    const createObjectURL = vi.fn().mockReturnValue('blob:fake');
    const revokeObjectURL = vi.fn();
    Object.assign(URL, { createObjectURL, revokeObjectURL });

    let attachedWhenClicked = false;
    const click = vi.fn(function (this: HTMLAnchorElement) {
      attachedWhenClicked = document.body.contains(this);
    });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(click);

    downloadBlob('a,b', 'out.csv', 'text/csv');

    expect(click).toHaveBeenCalled();
    expect(attachedWhenClicked).toBe(true);
    expect(document.querySelectorAll('a[download]')).toHaveLength(0);
    expect(createObjectURL).toHaveBeenCalled();
  });

  it('sets the download filename and revokes the object URL', async () => {
    const revokeObjectURL = vi.fn();
    Object.assign(URL, { createObjectURL: vi.fn().mockReturnValue('blob:fake'), revokeObjectURL });

    let filename = '';
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      filename = this.download;
    });

    downloadBlob('{}', 'packets-123.json', 'application/json');

    expect(filename).toBe('packets-123.json');
    // Revocation is deferred a tick so it can't cancel the download the
    // click has only just scheduled.
    expect(revokeObjectURL).not.toHaveBeenCalled();
    await new Promise((r) => setTimeout(r, 0));
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:fake');
  });
});
