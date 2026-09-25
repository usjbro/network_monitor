// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import type { PacketFrame } from '@/lib/types';
import type { CompiledDisplayFilter } from '@/lib/display-filter';
import * as exportModule from '@/lib/export';

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const packet = (id: string, summary: string): PacketFrame => ({
  id, timestamp: '12:00:00', relativeTimeMs: 0, layer: 4, protocol: 'TCP',
  src: '10.0.0.1', dst: '10.0.0.2', length: 60, summary,
  hexDump: 'aa bb', headerHexDump: 'aa', fields: [],
});
const hidden = packet('pkt-hidden', 'hidden packet summary');
const match = packet('pkt-match', 'matching packet summary');
const displayFilter: CompiledDisplayFilter = (record) => record.kind === 'packet' && record.packet.id === 'pkt-match';
const withFields = (frame: PacketFrame): PacketFrame => ({
  ...frame,
  headerHexDump: 'aa bb', hexDump: 'cc dd',
  fields: [
    { path: 'tcp.dst_port', label: 'Destination Port', type: 'uint', value: 443,
      region: 'header', offset: 0, len: 1 },
    { path: 'tcp.src_port', label: 'Source Port', type: 'uint', value: 55555,
      region: 'header', offset: 1, len: 1 },
    { path: 'app.value', label: 'Application Value', type: 'str', value: frame.id,
      region: 'payload', offset: 0, len: 1 },
    { path: 'app.other', label: 'Other Application Value', type: 'str', value: 'other',
      region: 'payload', offset: 1, len: 1 },
  ],
});

describe('PacketStreamView shared display filter', () => {
  it('scopes feed and JSON export while reporting matches against the full retained buffer', () => {
    const download = vi.spyOn(exportModule, 'downloadBlob').mockImplementation(() => {});
    const packets = [hidden, match];
    render(<PacketStreamView packets={packets} theme={THEMES.matrix} onClearPackets={() => {}}
      displayFilter={displayFilter} displayFilterExpression="frame.len == 60" />);

    expect(screen.getByText('matching packet summary')).toBeInTheDocument();
    expect(screen.queryByText('hidden packet summary')).not.toBeInTheDocument();
    expect(screen.getByText(/1 of 2 buffered packets match/i)).toBeInTheDocument();
    expect(screen.getByText(/hidden packets remain buffered/i)).toBeInTheDocument();
    expect(packets).toEqual([hidden, match]);

    fireEvent.click(screen.getByRole('button', { name: /export json/i }));
    expect(JSON.parse(download.mock.calls[0][0])).toEqual([match]);
  });

  it('falls back to a visible selection and clears details when no packets match', () => {
    const { rerender } = render(<PacketStreamView packets={[hidden, match]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByText('ID: pkt-hidden')).toBeInTheDocument();
    rerender(<PacketStreamView packets={[hidden, match]} theme={THEMES.matrix} onClearPackets={() => {}} displayFilter={displayFilter} />);
    expect(screen.getByText('ID: pkt-match')).toBeInTheDocument();
    expect(screen.queryByText('ID: pkt-hidden')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('matching packet summary'));
    expect(screen.getByText('ID: pkt-match')).toBeInTheDocument();
    rerender(<PacketStreamView packets={[hidden, match]} theme={THEMES.matrix} onClearPackets={() => {}} displayFilter={() => false} />);
    expect(screen.queryByText(/ID: pkt-/)).not.toBeInTheDocument();
    expect(screen.getByText(/select any packet frame/i)).toBeInTheDocument();
  });

  it('counts shared matches before the local keyword refinement', () => {
    render(<PacketStreamView packets={[hidden, match]} theme={THEMES.matrix} onClearPackets={() => {}} displayFilter={displayFilter} />);
    fireEvent.change(screen.getByPlaceholderText(/filter live pcap stream/i), { target: { value: 'absent' } });
    expect(screen.getByText(/1 of 2 buffered packets match/i)).toBeInTheDocument();
    expect(screen.getByText(/0 frames/i)).toBeInTheDocument();
  });

  it.each(['display', 'local'] as const)('clears inspector field and byte highlights when %s filtering replaces the selected packet', (filterKind) => {
    const packets = [withFields(hidden), withFields(match)];
    const props = { packets, theme: THEMES.matrix, onClearPackets: () => {} };
    const { container, rerender } = render(<PacketStreamView {...props} />);
    fireEvent.click(container.querySelector('[data-field-path="tcp.dst_port"]')!);
    fireEvent.click(container.querySelector('[data-field-path="app.value"]')!);
    fireEvent.mouseEnter(container.querySelector('[data-field-path="tcp.src_port"]')!);
    fireEvent.mouseEnter(container.querySelector('[data-field-path="app.other"]')!);
    fireEvent.mouseEnter(container.querySelector('[data-testid="header-hex-dump"] [data-byte-index="1"]')!);
    fireEvent.mouseEnter(container.querySelector('[data-testid="payload-hex-dump"] [data-byte-index="1"]')!);
    expect(container.querySelectorAll('[data-field-path][data-highlighted="true"]')).toHaveLength(4);

    if (filterKind === 'display') {
      rerender(<PacketStreamView {...props} displayFilter={displayFilter} />);
    } else {
      fireEvent.change(screen.getByPlaceholderText(/filter live pcap stream/i), { target: { value: 'matching' } });
    }

    expect(screen.getByText('ID: pkt-match')).toBeInTheDocument();
    expect(container.querySelectorAll('[data-field-path][data-highlighted="true"]')).toHaveLength(0);
    expect(container.querySelectorAll('[data-testid="header-hex-dump"] [class*="bg-emerald-500"]')).toHaveLength(0);
    expect(container.querySelectorAll('[data-testid="payload-hex-dump"] [class*="bg-emerald-500"]')).toHaveLength(0);
  });
});
