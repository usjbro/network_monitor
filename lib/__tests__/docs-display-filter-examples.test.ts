import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { compileDisplayFilter } from '../display-filter';

const documents = ['docs/analysis-guide.md', 'docs/usage.md'];

describe('documented display-filter commands', () => {
  it.each(documents)('compiles every fenced display example in %s', (document) => {
    const path = resolve(document);
    const source = existsSync(path) ? readFileSync(path, 'utf8') : '';
    const examples = [...source.matchAll(/^```[^\r\n]*\r?\n([\s\S]*?)^```[ \t]*$/gm)]
      .flatMap((block) => block[1].split(/\r?\n/))
      .map((line) => line.trim())
      .filter((line) => /^display\s+/.test(line) && line !== 'display clear');

    expect(examples, `${document} must include executable display examples`).not.toHaveLength(0);
    for (const command of examples) {
      expect(compileDisplayFilter(command.replace(/^display\s+/, '')), `${document}: ${command}`)
        .toMatchObject({ ok: true });
    }
  });
});
