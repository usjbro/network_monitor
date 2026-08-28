import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

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
