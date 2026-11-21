#!/usr/bin/env node
// Fails when the shared Standing Rules block differs between CLAUDE.md and
// AGENTS.md, or when either file is missing it. The block runs from the line
// starting `<!-- BEGIN:standing-rules` to the line starting
// `<!-- END:standing-rules`, inclusive. See "Keeping the Agent Files in Sync"
// in either file.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const files = ['CLAUDE.md', 'AGENTS.md'];

function block(name) {
  const lines = readFileSync(join(root, name), 'utf8').split(/\r?\n/);
  const begins = lines.flatMap((l, i) => (l.startsWith('<!-- BEGIN:standing-rules') ? [i] : []));
  const ends = lines.flatMap((l, i) => (l.startsWith('<!-- END:standing-rules') ? [i] : []));
  if (begins.length !== 1 || ends.length !== 1 || ends[0] <= begins[0]) {
    throw new Error(`${name}: expected exactly one standing-rules BEGIN/END marker pair`);
  }
  return lines.slice(begins[0], ends[0] + 1);
}

try {
  const [a, b] = files.map(block);
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) {
      console.error(`Standing Rules differ between ${files[0]} and ${files[1]} at block line ${i + 1}:`);
      console.error(`  ${files[0]}: ${a[i] ?? '<missing>'}`);
      console.error(`  ${files[1]}: ${b[i] ?? '<missing>'}`);
      console.error('Update both files in the same PR so the block stays identical.');
      process.exit(1);
    }
  }
  console.log(`Standing Rules in sync (${a.length} lines).`);
} catch (err) {
  console.error(err.message);
  process.exit(1);
}
