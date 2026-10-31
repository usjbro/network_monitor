// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import TerminalApp from '@/app/page';

class FakeEventSource {
  static instance: FakeEventSource;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor() { FakeEventSource.instance = this; }
  close(): void {}
}

async function runCommand(command: string): Promise<void> {
  await act(async () => {
    const input = screen.getByPlaceholderText(/Type CLI command/i);
    fireEvent.change(input, { target: { value: command } });
    fireEvent.submit(input.closest('form')!);
  });
}

function showConnection(): void {
  act(() => FakeEventSource.instance.onmessage!({ data: JSON.stringify({
    type: 'connection_update',
    connection: {
      id: 'conn-1', protocol: 'HTTPS/TLS', appLayerProtocol: 'HTTPS/TLS', transportProtocol: 'TCP',
      osiStack: 'x', localAddr: '192.168.1.10', localPort: 51000, remoteAddr: '93.184.216.34', remotePort: 443,
      processName: 'Safari', pid: 1234, rxSpeed: 0, txSpeed: 0, rxBytesTotal: 0, txBytesTotal: 0,
      latencyMs: 0, packetLoss: 0, status: 'ESTABLISHED', encryption: 'TLS', sparkline: [],
    },
  }) } as MessageEvent));
}

const disclosure = 'Ownership queries send addresses to third parties.';
const success = () => ({ ok: true, json: async () => ({ disclosureText: disclosure }) });
const commands = [
  ['pause', '/api/control', { type: 'pause' }, 'Capture control request failed.'],
  ['resume', '/api/control', { type: 'resume' }, 'Capture control request failed.'],
  ['enrich on', '/api/enrichment/control', { action: 'enable' }, 'Enrichment control request failed.'],
  ['enrich off', '/api/enrichment/control', { action: 'disable' }, 'Enrichment control request failed.'],
  ['enrich background on', '/api/enrichment/control', { action: 'enable_background' }, 'Enrichment control request failed.'],
  ['enrich background off', '/api/enrichment/control', { action: 'disable_background' }, 'Enrichment control request failed.'],
  ['enrich clear', '/api/enrichment/control', { action: 'clear' }, 'Enrichment control request failed.'],
  ['geoip enable', '/api/geoip/control', { action: 'enable' }, 'GeoIP control request failed.'],
  ['geoip disable', '/api/geoip/control', { action: 'disable' }, 'GeoIP control request failed.'],
  ['geoip clear', '/api/geoip/control', { action: 'clear' }, 'GeoIP control request failed.'],
] as const;

beforeEach(() => {
  vi.stubGlobal('EventSource', FakeEventSource);
  vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => success()));
  window.matchMedia = vi.fn().mockReturnValue({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe.each(['rejected', 'non-OK'] as const)('%s control requests', (failure) => {
  it.each(commands)('reports and dismisses %s failure, allowing retry', async (command, endpoint, body, message) => {
    const fetchMock = vi.mocked(fetch);
    if (failure === 'rejected') fetchMock.mockRejectedValueOnce(new Error('PRIVATE_EXCEPTION_DETAIL'));
    else fetchMock.mockResolvedValueOnce({
      ok: false, status: 503,
      json: async () => ({ disclosureText: 'PRIVATE_RESPONSE_BODY' }),
    } as Response);
    render(<TerminalApp />);

    await runCommand(command);

    const expectedMessage = failure === 'non-OK' ? message.replace('.', ' (HTTP 503).') : message;
    expect(screen.getByText(expectedMessage)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/PRIVATE_EXCEPTION_DETAIL|PRIVATE_RESPONSE_BODY/);
    expect(fetchMock).toHaveBeenCalledWith(endpoint, expect.objectContaining({ body: JSON.stringify(body) }));
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss control error' }));
    expect(screen.queryByText(expectedMessage)).not.toBeInTheDocument();
    await runCommand(command);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(screen.queryByText(expectedMessage)).not.toBeInTheDocument();
  });
});

it.each(['rejected', 'non-OK'] as const)('reports a %s header pause request', async (failure) => {
  if (failure === 'rejected') vi.mocked(fetch).mockRejectedValueOnce(new Error('PRIVATE_EXCEPTION_DETAIL'));
  else vi.mocked(fetch).mockResolvedValueOnce({ ok: false, status: 403 } as Response);
  render(<TerminalApp />);
  await act(async () => fireEvent.click(screen.getByTitle('Pause/Resume Realtime Monitor')));
  expect(screen.getByText(failure === 'non-OK' ? 'Capture control request failed (HTTP 403).' : 'Capture control request failed.')).toBeInTheDocument();
  expect(document.body).not.toHaveTextContent('PRIVATE_EXCEPTION_DETAIL');
});

it.each(commands)('clears the old failure when retrying %s', async (command, _endpoint, _body, message) => {
  vi.mocked(fetch).mockRejectedValueOnce(new Error('request failed'));
  render(<TerminalApp />);
  await runCommand(command);
  expect(screen.getByText(message)).toBeInTheDocument();
  let finishRetry!: (response: Response) => void;
  vi.mocked(fetch).mockReturnValueOnce(new Promise<Response>((resolve) => { finishRetry = resolve; }));
  await runCommand(command);
  expect(screen.queryByRole('button', { name: 'Dismiss control error' })).not.toBeInTheDocument();
  await act(async () => { finishRetry(success() as Response); });
  expect(screen.queryByRole('button', { name: 'Dismiss control error' })).not.toBeInTheDocument();
});

it.each(['rejected', 'non-OK'] as const)('preserves the header pause state after %s pause and resume requests', async (failure) => {
  const failNext = () => {
    if (failure === 'rejected') vi.mocked(fetch).mockRejectedValueOnce(new Error('request failed'));
    else vi.mocked(fetch).mockResolvedValueOnce({ ok: false, status: 503 } as Response);
  };
  render(<TerminalApp />);
  const button = screen.getByTitle('Pause/Resume Realtime Monitor');
  failNext();
  await act(async () => { fireEvent.click(button); });
  expect(button).toHaveTextContent('PAUSE');
  await act(async () => { fireEvent.click(button); });
  expect(button).toHaveTextContent('RESUMED');
  failNext();
  await act(async () => { fireEvent.click(button); });
  expect(button).toHaveTextContent('RESUMED');
  await act(async () => { fireEvent.click(button); });
  expect(button).toHaveTextContent('PAUSE');
  expect(vi.mocked(fetch).mock.calls.map(([, init]) => JSON.parse(init!.body as string))).toEqual([
    { type: 'pause' }, { type: 'pause' }, { type: 'resume' }, { type: 'resume' },
  ]);
});

it('keeps enrichment disabled when enabling fails', async () => {
  vi.mocked(fetch).mockResolvedValueOnce({ ok: false, json: async () => ({ disclosureText: 'PRIVATE_RESPONSE_BODY' }) } as Response);
  render(<TerminalApp />);
  showConnection();
  await runCommand('conn');
  await runCommand('enrich on');
  expect(screen.getByText(/Enrichment disabled/)).toBeInTheDocument();
  expect(document.body).not.toHaveTextContent('PRIVATE_RESPONSE_BODY');
});

it('keeps enrichment mode, pending lookup and its timer when clear fails', async () => {
  vi.useFakeTimers();
  render(<TerminalApp />);
  showConnection();
  await runCommand('conn');
  await runCommand('enrich on');
  fireEvent.click(screen.getByRole('button', { name: /Not yet looked up/ }));
  expect(screen.getByText('Looking up…')).toBeInTheDocument();
  vi.mocked(fetch).mockResolvedValueOnce({ ok: false, json: async () => ({}) } as Response);
  await runCommand('enrich clear');
  expect(screen.getByText('Looking up…')).toBeInTheDocument();
  await act(async () => { await vi.advanceTimersByTimeAsync(25_000); });
  expect(screen.getByText(/Unavailable — no ownership data/)).toBeInTheDocument();
});

it('keeps unavailable lookup bookkeeping when clear fails', async () => {
  vi.useFakeTimers();
  render(<TerminalApp />);
  showConnection();
  await runCommand('conn');
  await runCommand('enrich on');
  fireEvent.click(screen.getByRole('button', { name: /Not yet looked up/ }));
  await act(async () => { await vi.advanceTimersByTimeAsync(25_000); });
  vi.mocked(fetch).mockResolvedValueOnce({ ok: false, json: async () => ({}) } as Response);
  await runCommand('enrich clear');
  expect(screen.getByText(/Unavailable — no ownership data/)).toBeInTheDocument();
});

it('handles an enrichment response JSON rejection without changing mode', async () => {
  vi.mocked(fetch).mockResolvedValueOnce({ ok: true, json: async () => { throw new Error('PRIVATE_JSON_DETAIL'); } } as unknown as Response);
  render(<TerminalApp />);
  showConnection();
  await runCommand('conn');
  await runCommand('enrich on');
  expect(screen.getByText('Enrichment control request failed.')).toBeInTheDocument();
  expect(screen.getByText(/Enrichment disabled/)).toBeInTheDocument();
  expect(document.body).not.toHaveTextContent('PRIVATE_JSON_DETAIL');
});

it.each(['enrich on', 'enrich background on'])('reshows disclosure on every successful %s', async (command) => {
  render(<TerminalApp />);
  await runCommand(command);
  expect(screen.getByText(disclosure)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Dismiss disclosure' }));
  await runCommand(command);
  expect(screen.getByText(disclosure)).toBeInTheDocument();
});
