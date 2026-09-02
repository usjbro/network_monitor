// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import React from 'react';
import { render, screen } from '@testing-library/react';
import { ConnectionsView } from '../../components/ConnectionsView';
import { THEMES } from '../osi-engine';
import { NetworkConnection } from '../types';

// This file stays a plain `.ts` (not `.tsx`) so it keeps matching the exact
// path a sibling sub-project's own no-dangerous-html regression test
// targets (docs/superpowers/plans/2026-08-26-secure-lan-access.md's Task
// 4) — a `.tsx` rename here risks the same kind of module-collision issue
// that convention was set up to avoid. Since a `.ts` file's default esbuild
// loader doesn't parse JSX syntax, the rendering fixture below uses
// `React.createElement` instead of a `<ConnectionsView ... />` literal.

const SCAN_DIRS = ['app', 'components', 'lib'];
const DANGEROUS_PATTERN = /dangerouslySetInnerHTML|\.innerHTML\s*=/;

function collectSourceFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      if (entry === '__tests__' || entry === 'node_modules') continue;
      files.push(...collectSourceFiles(full));
    } else if (/\.(tsx?|jsx?)$/.test(entry)) {
      files.push(full);
    }
  }
  return files;
}

describe('network-sourced strings are never rendered as raw HTML', () => {
  it('no source file under app/, components/, or lib/ uses dangerouslySetInnerHTML or .innerHTML', () => {
    const offenders: string[] = [];
    for (const dir of SCAN_DIRS) {
      for (const file of collectSourceFiles(dir)) {
        const content = readFileSync(file, 'utf-8');
        if (DANGEROUS_PATTERN.test(content)) {
          offenders.push(file);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});

// The static scan above only proves the two dangerous APIs are absent from
// the source *text* repo-wide — it can't prove that the specific untrusted
// RDAP/WHOIS-derived strings this sub-project introduces (org, asnOrg,
// registrant — see lib/types.ts NetworkConnection['enrichment']) actually
// flow through a safe render path at runtime. This block closes that gap:
// it renders ConnectionsView's Ownership section (added in Task 10; see
// components/ConnectionsView.tsx lines ~202-232) with deliberately hostile
// org/registrant values and asserts, via actual DOM inspection, that
// React's default JSX text interpolation ({...}) rendered them as inert
// literal text rather than parsing them into live HTML elements.
describe('ConnectionsView renders hostile RDAP/WHOIS ownership strings as inert text', () => {
  function baseConn(overrides: Partial<NetworkConnection> = {}): NetworkConnection {
    return {
      id: 'conn-hostile-1',
      protocol: 'HTTPS/TLS',
      appLayerProtocol: 'HTTPS/TLS',
      transportProtocol: 'TCP',
      osiStack: 'x',
      localAddr: '192.168.1.10',
      localPort: 51000,
      remoteAddr: '93.184.216.34',
      remotePort: 443,
      processName: 'Safari',
      pid: 1234,
      rxSpeed: 0,
      txSpeed: 0,
      rxBytesTotal: 0,
      txBytesTotal: 0,
      latencyMs: 0,
      packetLoss: 0,
      status: 'ESTABLISHED',
      encryption: 'TLS',
      sparkline: [],
      ...overrides,
    };
  }

  it('renders a hostile org string as literal text, never as a live <img> element', () => {
    const hostileOrg = '<img src=x onerror="window.__pwned=true">';

    render(
      React.createElement(ConnectionsView, {
        connections: [
          baseConn({
            enrichment: {
              org: hostileOrg,
              asn: 'AS15133',
              source: 'rdap',
              fetchedAt: '2026-08-28T00:00:00.000Z',
            },
          }),
        ],
        theme: THEMES.sophisticated,
        enrichmentMode: 'on-demand',
        onRequestLookup: () => {},
      }),
    );

    // If ConnectionsView had rendered this via dangerouslySetInnerHTML (or
    // an .innerHTML= assignment), the browser/jsdom would have parsed the
    // markup into a real <img> element and there would be no literal text
    // node containing the tag characters to find. Finding the literal
    // string — and finding no matching <img> — proves the escape held.
    expect(screen.getByText(hostileOrg)).toBeInTheDocument();
    expect(document.querySelector('img[src="x"]')).toBeNull();
  });

  it('renders a hostile registrant string as literal text, never as a live <script> element', () => {
    const hostileRegistrant = '<script>window.__pwned2=true</script>';

    render(
      React.createElement(ConnectionsView, {
        connections: [
          baseConn({
            enrichment: {
              org: 'EXAMPLE-ORG',
              asn: 'AS15133',
              registrant: hostileRegistrant,
              source: 'rdap',
              fetchedAt: '2026-08-28T00:00:00.000Z',
            },
          }),
        ],
        theme: THEMES.sophisticated,
        enrichmentMode: 'on-demand',
        onRequestLookup: () => {},
      }),
    );

    expect(screen.getByText(hostileRegistrant)).toBeInTheDocument();
    expect(document.querySelector('script')).toBeNull();
  });
});

// geoIP-provider-derived strings this sub-project introduces (hop.location
// .city/.country — see lib/types.ts's TracerouteHop) actually flow through
// a safe render path at runtime. This block closes that gap: it renders
// ConnectionsView's hop table (components/ConnectionsView.tsx, the "Trace
// Route" section) with deliberately hostile city/country values and
// asserts, via actual DOM inspection, that React's default JSX text
// interpolation ({...}) rendered them as inert literal text rather than
// parsing them into live HTML elements.
describe('ConnectionsView renders hostile geoIP location strings as inert text', () => {
  function baseConn(overrides: Partial<NetworkConnection> = {}): NetworkConnection {
    return {
      id: 'conn-hostile-1',
      protocol: 'HTTPS/TLS',
      appLayerProtocol: 'HTTPS/TLS',
      transportProtocol: 'TCP',
      osiStack: 'x',
      localAddr: '192.168.1.10',
      localPort: 51000,
      remoteAddr: '93.184.216.34',
      remotePort: 443,
      processName: 'Safari',
      pid: 1234,
      rxSpeed: 0,
      txSpeed: 0,
      rxBytesTotal: 0,
      txBytesTotal: 0,
      latencyMs: 0,
      packetLoss: 0,
      status: 'ESTABLISHED',
      encryption: 'TLS',
      sparkline: [],
      ...overrides,
    };
  }

  it('renders a hostile geoIP city string as literal text, never as a live <img> element', () => {
    const hostileCity = '<img src=x onerror="window.__pwned=true">';
    const conn = baseConn();

    render(
      React.createElement(ConnectionsView, {
        connections: [conn],
        theme: THEMES.sophisticated,
        onTraceRoute: () => {},
        traceroute: {
          [conn.id]: [
            {
              targetIp: conn.remoteAddr,
              hopNumber: 1,
              hopIp: '10.0.0.1',
              rttMs: 1.2,
              location: { city: hostileCity, country: 'US' },
            },
          ],
        },
      })
    );

    // If ConnectionsView had rendered this via dangerouslySetInnerHTML (or
    // an .innerHTML= assignment), the browser/jsdom would have parsed the
    // markup into a real <img> element and there would be no literal text
    // node containing the tag characters to find. Finding the literal
    // string — and finding no matching <img> — proves the escape held.
    expect(screen.getByText(new RegExp(hostileCity.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))).toBeInTheDocument();
    expect(document.querySelector('img[src="x"]')).toBeNull();
  });

  it('renders a hostile geoIP country string as literal text, never as a live <script> element', () => {
    const hostileCountry = '<script>window.__pwned2=true</script>';
    const conn = baseConn();

    render(
      React.createElement(ConnectionsView, {
        connections: [conn],
        theme: THEMES.sophisticated,
        onTraceRoute: () => {},
        traceroute: {
          [conn.id]: [
            {
              targetIp: conn.remoteAddr,
              hopNumber: 1,
              hopIp: '10.0.0.1',
              rttMs: 1.2,
              location: { city: 'Ashburn', country: hostileCountry },
            },
          ],
        },
      })
    );

    expect(
      screen.getByText(new RegExp(hostileCountry.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    ).toBeInTheDocument();
    expect(document.querySelector('script')).toBeNull();
  });
});
