// lib/enrichment/error-label.ts
//
// What enrichment logs about an error: its code or name, never its message,
// which can quote an address, a hostname or the log's path (KAN-318). Only an
// Error's own code or name is used, and only when it looks like one.

const MAX_CAUSES = 2;
const LABEL = /^[A-Za-z][A-Za-z0-9_]{0,39}$/;

export function errorLabel(err: unknown): string {
  try {
    return label(err, 0);
  } catch {
    return 'unlabelled error';
  }
}

function label(err: unknown, depth: number): string {
  if (!(err instanceof Error)) return typeof err;
  const { code, name, cause } = err as { code?: unknown; name?: unknown; cause?: unknown };
  const own = [code, name].find((v): v is string => typeof v === 'string' && LABEL.test(v)) ?? 'Error';
  if (!(cause instanceof Error)) return own;
  return `${own} (${depth < MAX_CAUSES ? label(cause, depth + 1) : '…'})`;
}
