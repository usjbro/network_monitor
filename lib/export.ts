// Browser-side export of what the operator is already looking at
// (JAM-7/GitHub #74, spec Components §5). Pure functions over
// already-in-memory arrays: no fetch, no API route, nothing written
// server-side.
//
// THE RULE THIS FILE EXISTS TO ENFORCE: `DecryptedPayloadSegment` never
// appears in any signature here. Decrypted TLS content is not "filtered
// out" on the way to a file — it is structurally impossible to pass to
// anything in this module. That matters because a filter is a line of code
// someone can delete by accident, while a type that was never accepted in
// the first place fails at compile time. The runtime half of the same
// guarantee is lib/__tests__/decrypted-export-exclusion.test.ts.
//
// The wider reason (docs/security.md, "Export crosses a narrower boundary
// than the live view"): an exported file leaves the mTLS layer, the
// loopback bind, and every other protection the live stream has. Decrypted
// content lives only in the agent's mlock'd, zeroed-on-evict ring buffer
// and is never written to disk there either — letting it reach a Downloads
// folder would undo that on the last hop.
import { NetworkConnection, PacketFrame } from './types';

// An explicit allowlist, not "every field on the object". A future widening
// of NetworkConnection therefore cannot add a column for free — see the
// exclusion test's second case.
const CSV_COLUMNS: Array<{ header: string; get: (c: NetworkConnection) => string | number }> = [
  { header: 'Protocol', get: (c) => c.protocol },
  { header: 'Local', get: (c) => `${c.localAddr}:${c.localPort}` },
  { header: 'Remote', get: (c) => `${c.remoteAddr}:${c.remotePort}` },
  { header: 'Process', get: (c) => c.processName },
  { header: 'PID', get: (c) => c.pid },
  { header: 'RX Bytes', get: (c) => c.rxBytesTotal },
  { header: 'TX Bytes', get: (c) => c.txBytesTotal },
  { header: 'Status', get: (c) => c.status },
];

/**
 * RFC 4180 field escaping: a field containing a comma, double quote, CR or
 * LF is wrapped in quotes with internal quotes doubled.
 *
 * Network-sourced strings are exactly the kind of untrusted text this
 * matters for — `processName` comes from the local process table and
 * `remoteAddr`/hostnames from the wire. This is the same "never trust a
 * network-sourced string to be well-behaved" posture that
 * no-dangerous-html.test.ts applies to rendering, applied to a different
 * output format.
 *
 * Note CR is handled as well as LF: a bare \r inside a field breaks naive
 * line-splitting parsers just as a \n does, and the plan's own sketch
 * checked only for \n.
 */
function csvEscape(value: string | number): string {
  const s = String(value);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

/**
 * The connections table as CSV.
 *
 * `connections` is whatever the caller is displaying — the *filtered* rows,
 * per the spec's requirement that an export match the table on screen.
 * `totalObserved` is the agent's `capture_stats.totalConnectionsObserved`,
 * carried into a leading comment line so the file states its own horizon
 * rather than silently looking like the whole session (JAM-6's honesty
 * requirement, applied to the exported artifact too).
 */
export function connectionsToCsv(connections: NetworkConnection[], totalObserved: number): string {
  const horizon = `# showing ${connections.length} of ${totalObserved} observed`;
  const header = CSV_COLUMNS.map((c) => c.header).join(',');
  const rows = connections.map((c) => CSV_COLUMNS.map((col) => csvEscape(col.get(c))).join(','));
  return [horizon, header, ...rows].join('\n');
}

/**
 * The packet list as JSON, indented for reading. Round-trips through
 * JSON.parse with `fields` intact — the field registry is the
 * point of exporting packets rather than a flat summary table.
 */
export function packetsToJson(packets: PacketFrame[]): string {
  return JSON.stringify(packets, null, 2);
}

/**
 * Hands `content` to the browser as a download. The only impure function
 * here, and deliberately the only one that touches the DOM, so the
 * formatters above stay trivially testable.
 *
 * The anchor is attached to the document before clicking and removed after:
 * a detached anchor's click is ignored by Firefox, and leaving it attached
 * leaks a node per export. The object URL is revoked on a later tick
 * because revoking it synchronously can cancel the download that the click
 * has only just scheduled.
 */
export function downloadBlob(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
