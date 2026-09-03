// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';

afterEach(() => {
  cleanup();
});

describe('PacketStreamView decrypted content', () => {
  it('renders a [REDACTED] placeholder distinctly, not blank', () => {
    render(
      <PacketStreamView
        packets={[]}
        theme={THEMES.matrix}
        onClearPackets={() => {}}
        decryptedSegments={[{ connectionId: 'c1', streamId: undefined, text: '[REDACTED]', redacted: true }]}
      />
    );
    const el = screen.getByText('[REDACTED]');
    expect(el).toBeInTheDocument();
    expect(el.className).toMatch(/redacted|italic|opacity/i);
  });

  it('renders real decrypted text alongside the existing ciphertext view, not replacing it', () => {
    render(
      <PacketStreamView
        packets={[]}
        theme={THEMES.matrix}
        onClearPackets={() => {}}
        decryptedSegments={[{ connectionId: 'c1', streamId: undefined, text: 'GET /api/x', redacted: false }]}
      />
    );
    expect(screen.getByText(/GET \/api\/x/)).toBeInTheDocument();
    // The existing empty-buffer message from the ciphertext pane should
    // still be present — decrypted content is additive, not a replacement.
    expect(screen.getByText(/No packet frames in capture buffer/i)).toBeInTheDocument();
  });

  it('renders HTML/script-like decrypted content as inert text, never executed markup', () => {
    // Decrypted content is attacker-influenced (it's whatever bytes the
    // remote server sent) — this must render as plain text, the same
    // invariant lib/__tests__/no-dangerous-html.test.ts enforces
    // structurally (no dangerouslySetInnerHTML/.innerHTML anywhere in
    // app/, components/, lib/) verified here at the render level for this
    // specific, newly-added content path.
    const malicious = '<script>window.__pwned = true</script><img src=x onerror="window.__pwned = true">';
    render(
      <PacketStreamView
        packets={[]}
        theme={THEMES.matrix}
        onClearPackets={() => {}}
        decryptedSegments={[{ connectionId: 'c1', streamId: undefined, text: malicious, redacted: false }]}
      />
    );
    expect(screen.getByText(malicious)).toBeInTheDocument();
    expect(document.querySelector('script')).toBeNull();
    expect((window as unknown as { __pwned?: boolean }).__pwned).toBeUndefined();
  });

  it('renders nothing extra when decryptedSegments is omitted (backward compatible)', () => {
    render(<PacketStreamView packets={[]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByText(/No packet frames in capture buffer/i)).toBeInTheDocument();
  });
});
