// lib/__tests__/connections-view-ownership.test.tsx
// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { ConnectionsView } from '../../components/ConnectionsView';
import { THEMES } from '../osi-engine';
import { NetworkConnection } from '../types';

// This file imports `afterEach` explicitly rather than relying on vitest's
// `globals: true` (not enabled in vitest.config.ts), so @testing-library/
// react's own auto-cleanup — which detects a *global* afterEach — never
// registers here. Without this, every render() in this file accumulates in
// document.body across tests, and a later query (e.g. Task 15's "Unavailable"
// case asserting `queryByText(/org:/i)` is absent) can spuriously find
// leftover matches from an earlier test's still-mounted DOM.
afterEach(() => cleanup());

const theme = THEMES.sophisticated;

function baseConn(overrides: Partial<NetworkConnection> = {}): NetworkConnection {
  return {
    id: 'conn-1', protocol: 'HTTPS/TLS', appLayerProtocol: 'HTTPS/TLS', transportProtocol: 'TCP',
    osiStack: 'x', localAddr: '192.168.1.10', localPort: 51000, remoteAddr: '93.184.216.34', remotePort: 443,
    processName: 'Safari', pid: 1234, rxSpeed: 0, txSpeed: 0, rxBytesTotal: 0, txBytesTotal: 0,
    latencyMs: 0, packetLoss: 0, status: 'ESTABLISHED', encryption: 'TLS', sparkline: [],
    ...overrides,
  };
}

describe('ConnectionsView Ownership section', () => {
  it('shows "Enrichment disabled" when enrichmentMode is off', () => {
    render(<ConnectionsView connections={[baseConn()]} theme={theme} enrichmentMode="off" onRequestLookup={() => {}} />);
    expect(screen.getByText(/enrichment disabled/i)).toBeInTheDocument();
  });

  it('shows "Not yet looked up" for a selected connection with no enrichment field, mode on', () => {
    render(<ConnectionsView connections={[baseConn()]} theme={theme} enrichmentMode="on-demand" onRequestLookup={() => {}} />);
    expect(screen.getByText(/not yet looked up/i)).toBeInTheDocument();
  });

  it('shows org/ASN/as-of when enrichment data is present', () => {
    render(
      <ConnectionsView
        connections={[baseConn({ enrichment: { org: 'EXAMPLE-ORG', asn: 'AS15133', source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' } })]}
        theme={theme}
        enrichmentMode="on-demand"
        onRequestLookup={() => {}}
      />,
    );
    expect(screen.getByText(/EXAMPLE-ORG/)).toBeInTheDocument();
    expect(screen.getByText(/AS15133/)).toBeInTheDocument();
  });

  it('shows a blank/"—" ASN, not an error, when the registry record has no ASN (best-effort field)', () => {
    render(
      <ConnectionsView
        connections={[baseConn({ enrichment: { org: 'EXAMPLE-ORG', source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' } })]}
        theme={theme}
        enrichmentMode="on-demand"
        onRequestLookup={() => {}}
      />,
    );
    expect(screen.queryByText(/error/i)).not.toBeInTheDocument();
  });

  it('shows registrant when present (extended tier)', () => {
    render(
      <ConnectionsView
        connections={[baseConn({ enrichment: { org: 'EXAMPLE-ORG', registrant: 'EXAMPLE REGISTRANT ORG', source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' } })]}
        theme={theme}
        enrichmentMode="on-demand"
        onRequestLookup={() => {}}
      />,
    );
    expect(screen.getByText(/EXAMPLE REGISTRANT ORG/)).toBeInTheDocument();
  });

  it('shows "Unavailable" (Task 15\'s fifth state) when a lookup completed but produced no org/ASN/registrant at all — distinct from a legitimately-blank ASN', () => {
    render(
      <ConnectionsView
        connections={[baseConn({ enrichment: { source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' } })]}
        theme={theme}
        enrichmentMode="on-demand"
        onRequestLookup={() => {}}
      />,
    );
    expect(screen.getByText(/unavailable/i)).toBeInTheDocument();
    expect(screen.queryByText(/org:/i)).not.toBeInTheDocument();
  });

  it('renders org/registrant strings as plain text, never via dangerouslySetInnerHTML', () => {
    const hostileOrg = '<img src=x onerror="window.__pwned=true">';
    render(
      <ConnectionsView
        connections={[baseConn({ enrichment: { org: hostileOrg, source: 'rdap', fetchedAt: '2026-08-28T00:00:00.000Z' } })]}
        theme={theme}
        enrichmentMode="on-demand"
        onRequestLookup={() => {}}
      />,
    );
    // If this were rendered as raw HTML, there would be no literal text node
    // containing the tag characters — they'd have been parsed into a DOM
    // element instead. Finding the literal string proves JSX text
    // interpolation (auto-escaped), not an HTML sink.
    expect(screen.getByText(hostileOrg)).toBeInTheDocument();
    expect(document.querySelector('img[src="x"]')).toBeNull();
  });
});
