// lib/enrichment/error-label.ts
//
// What enrichment logs about an error: its code or name, never its message,
// which can quote an address, a hostname or the log's path (KAN-318).

const MAX_CAUSES = 2;

export function errorLabel(err: unknown, depth = 0): string {
  if (typeof err !== 'object' || err === null) return typeof err;
  const { code, name, cause } = err as { code?: unknown; name?: unknown; cause?: unknown };
  const label = typeof code === 'string' ? code : typeof name === 'string' ? name : 'object';
  if (typeof cause !== 'object' || cause === null) return label;
  return `${label} (${depth < MAX_CAUSES ? errorLabel(cause, depth + 1) : '…'})`;
}
