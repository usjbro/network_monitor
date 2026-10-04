// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import type { PacketFrame, WireField } from '@/lib/types';

afterEach(cleanup);

const derived = (path: string, type: WireField['type'], value: WireField['value']): WireField =>
  ({ path, label: path, group: 'dns', type, value, region: 'payload', offset: 0, len: 0 });

const base: PacketFrame = {
  id: '', timestamp: '1000', relativeTimeMs: 1, layer: 7, protocol: 'UDP', src: '10.0.0.2:40000',
  dst: '10.0.0.1:53', length: 80, summary: '', hexDump: '', headerHexDump: '', fields: [],
};
const request: PacketFrame = { ...base, id: 'pkt-req', summary: 'the query' };
const response: PacketFrame = {
  ...base, id: 'pkt-resp', summary: 'the answer',
  fields: [derived('dns.time_us', 'uint', 12_300), derived('dns.response_to', 'str', 'pkt-req')],
};

describe('PacketStreamView request/response links', () => {
  it('marks a matched response row with its service time', () => {
    render(<PacketStreamView packets={[response, request]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    const row = screen.getByText('the answer').closest('div[data-packet-row]')!;
    expect(row.querySelector('[data-testid="service-time-badge"]')).toHaveTextContent('12.3 ms');
  });

  it('links a selected response back to its request, and the request forward to its response', () => {
    render(<PacketStreamView packets={[response, request]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByTestId('transaction-link')).toHaveTextContent(/DNS response to pkt-req in 12\.3 ms/);
    fireEvent.click(screen.getByRole('button', { name: /show request/i }));
    expect(screen.getByText('ID: pkt-req')).toBeInTheDocument();
    expect(screen.getByTestId('transaction-link')).toHaveTextContent(/answered by pkt-resp in 12\.3 ms/);
    fireEvent.click(screen.getByRole('button', { name: /show response/i }));
    expect(screen.getByText('ID: pkt-resp')).toBeInTheDocument();
  });

  it('says so when the linked request is no longer in the buffer', () => {
    render(<PacketStreamView packets={[response]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByTestId('transaction-link')).toHaveTextContent(/no longer in this tab's buffer/);
    expect(screen.queryByRole('button', { name: /show request/i })).toBeNull();
  });
});
