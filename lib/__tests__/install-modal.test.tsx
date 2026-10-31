// @vitest-environment jsdom
//
// Coverage for InstallModal: open/closed rendering, the CLI/PWA tab
// toggle, the copy-to-clipboard command buttons, and the close button.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { InstallModal } from '@/components/InstallModal';
import { THEMES } from '@/lib/osi-engine';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

beforeEach(() => {
  // jsdom implements neither of these by default.
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
    configurable: true,
  });
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
});

const theme = THEMES.matrix;

describe('InstallModal', () => {
  it('renders nothing when closed', () => {
    const { container } = render(<InstallModal isOpen={false} onClose={() => {}} theme={theme} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('shows the CLI tab by default, with the curl one-liner', () => {
    render(<InstallModal isOpen={true} onClose={() => {}} theme={theme} />);
    expect(screen.getByText('macOS CLI (Terminal.app)')).toBeInTheDocument();
    // Two commands contain a "curl -sSL ... | bash" substring (the direct
    // one-liner, and the shell-alias command that wraps it) — the direct
    // one-liner is the first of the two.
    const commands = screen.getAllByText(/curl -sSL .*\/api\/install \| bash/);
    expect(commands.length).toBe(2);
  });

  it('switches to the PWA tab on click', () => {
    render(<InstallModal isOpen={true} onClose={() => {}} theme={theme} />);
    fireEvent.click(screen.getByText('macOS Desktop App (PWA)'));
    expect(screen.getByText('Install as macOS Desktop Application')).toBeInTheDocument();
    expect(screen.queryByText('macOS Terminal One-Liner (cURL)')).not.toBeInTheDocument();
  });

  it('copies the command text to the clipboard when the copy button is clicked', () => {
    render(<InstallModal isOpen={true} onClose={() => {}} theme={theme} />);
    const commandEl = screen.getAllByText(/curl -sSL .*\/api\/install \| bash/)[0];
    const copyButton = commandEl.closest('div')?.querySelector('button[title="Copy command"]') as HTMLElement;
    fireEvent.click(copyButton);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(commandEl.textContent);
  });

  it('shows the copied indicator only after the clipboard write succeeds', async () => {
    let finishCopy!: () => void;
    vi.mocked(navigator.clipboard.writeText).mockReturnValueOnce(new Promise<void>((resolve) => { finishCopy = resolve; }));
    render(<InstallModal isOpen={true} onClose={() => {}} theme={theme} />);
    const button = screen.getAllByTitle('Copy command')[0];
    fireEvent.click(button);
    expect(button.querySelector('.lucide-check')).toBeNull();
    await act(async () => { finishCopy(); });
    expect(button.querySelector('.lucide-check')).toBeInTheDocument();
  });

  it('handles a rejected clipboard write without showing copied success', async () => {
    vi.mocked(navigator.clipboard.writeText).mockRejectedValueOnce(new Error('clipboard permission denied'));
    render(<InstallModal isOpen={true} onClose={() => {}} theme={theme} />);
    const button = screen.getAllByTitle('Copy command')[0];
    await act(async () => { fireEvent.click(button); });
    expect(button.querySelector('.lucide-check')).toBeNull();
    // A later successful retry still works.
    await act(async () => { fireEvent.click(button); });
    expect(button.querySelector('.lucide-check')).toBeInTheDocument();
  });

  it('clears a previous copied indicator while retrying and after a rejected retry', async () => {
    render(<InstallModal isOpen={true} onClose={() => {}} theme={theme} />);
    const button = screen.getAllByTitle('Copy command')[0];
    await act(async () => { fireEvent.click(button); });
    expect(button.querySelector('.lucide-check')).toBeInTheDocument();
    let rejectRetry!: (reason: Error) => void;
    vi.mocked(navigator.clipboard.writeText).mockReturnValueOnce(new Promise<void>((_resolve, reject) => { rejectRetry = reject; }));
    fireEvent.click(button);
    expect(button.querySelector('.lucide-check')).toBeNull();
    await act(async () => { rejectRetry(new Error('clipboard permission denied')); });
    expect(button.querySelector('.lucide-check')).toBeNull();
  });

  it.each([0, 1])('ignores an older clipboard completion while copy button %i has a pending or rejected write', async (newerButtonIndex) => {
    let finishOlder!: () => void;
    let rejectNewer!: (reason: Error) => void;
    vi.mocked(navigator.clipboard.writeText)
      .mockReturnValueOnce(new Promise<void>((resolve) => { finishOlder = resolve; }))
      .mockReturnValueOnce(new Promise<void>((_resolve, reject) => { rejectNewer = reject; }));
    const { container } = render(<InstallModal isOpen={true} onClose={() => {}} theme={theme} />);
    const buttons = screen.getAllByTitle('Copy command');
    fireEvent.click(buttons[0]);
    fireEvent.click(buttons[newerButtonIndex]);
    await act(async () => { finishOlder(); });
    expect(container.querySelector('.lucide-check')).toBeNull();
    await act(async () => { rejectNewer(new Error('clipboard permission denied')); });
    expect(container.querySelector('.lucide-check')).toBeNull();
  });

  it('does not let an older copied timeout clear a newer success', async () => {
    vi.useFakeTimers();
    render(<InstallModal isOpen={true} onClose={() => {}} theme={theme} />);
    const buttons = screen.getAllByTitle('Copy command');
    await act(async () => { fireEvent.click(buttons[0]); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    await act(async () => { fireEvent.click(buttons[1]); });
    expect(buttons[1].querySelector('.lucide-check')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(buttons[1].querySelector('.lucide-check')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(buttons[1].querySelector('.lucide-check')).toBeNull();
  });

  it('calls onClose when the footer close button is clicked', () => {
    const onClose = vi.fn();
    render(<InstallModal isOpen={true} onClose={onClose} theme={theme} />);
    fireEvent.click(screen.getByText('Close'));
    expect(onClose).toHaveBeenCalled();
  });

  it('calls onClose when the header X button is clicked', () => {
    const onClose = vi.fn();
    const { container } = render(<InstallModal isOpen={true} onClose={onClose} theme={theme} />);
    const headerCloseButton = container.querySelectorAll('button')[0];
    fireEvent.click(headerCloseButton);
    expect(onClose).toHaveBeenCalled();
  });
});
