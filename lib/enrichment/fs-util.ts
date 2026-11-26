// lib/enrichment/fs-util.ts
//
// File helpers shared by the enrichment cache, query log and bootstrap files.
import { promises as fs, mkdirSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

const TEMP_SUFFIX = /^\.tmp-[0-9a-f]{12}$/;

// The temp file a rewrite of `filePath` goes through; removeTempFiles finds
// what a crash leaves of these.
export function tempPathFor(filePath: string): string {
  return `${filePath}.tmp-${randomBytes(6).toString('hex')}`;
}

export async function atomicWriteJson(filePath: string, data: unknown): Promise<void> {
  mkdirSync(dirname(filePath), { recursive: true, mode: 0o700 });
  const tmpPath = tempPathFor(filePath);
  try {
    await fs.writeFile(tmpPath, JSON.stringify(data), { mode: 0o600 });
    await fs.rename(tmpPath, filePath); // atomic on the same filesystem — no partial-write window on `filePath`
  } catch (err) {
    await fs.rm(tmpPath, { force: true }).catch(() => {});
    throw err;
  }
}

// Removes temp files a crash left for `filePath` (KAN-317).
export async function removeTempFiles(filePath: string): Promise<void> {
  const base = basename(filePath);
  let names: string[];
  try {
    names = await fs.readdir(dirname(filePath));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw err;
  }
  for (const name of names) {
    if (name.startsWith(base) && TEMP_SUFFIX.test(name.slice(base.length))) {
      await fs.rm(join(dirname(filePath), name), { force: true });
    }
  }
}

// Runs writes one at a time, in call order. A failed write rejects for its
// own caller only.
export class SerialWrites {
  private tail: Promise<void> = Promise.resolve();

  run<T>(write: () => Promise<T>): Promise<T> {
    const result = this.tail.then(write);
    this.tail = result.then(() => {}, () => {});
    return result;
  }
}
