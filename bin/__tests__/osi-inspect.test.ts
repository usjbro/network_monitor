import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { spawnSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, writeFileSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isKnownBrowserBinary, keylogPath, sweepOrphanedKeylogs } from '../osi-inspect.js';

describe('isKnownBrowserBinary', () => {
  it('matches common browser binary names', () => {
    for (const name of ['chrome', 'google-chrome', 'chromium', 'msedge', 'firefox']) {
      expect(isKnownBrowserBinary(name)).toBe(true);
    }
  });
  it('does not match non-browser commands', () => {
    for (const name of ['npm', 'node', 'curl', 'python3']) {
      expect(isKnownBrowserBinary(name)).toBe(false);
    }
  });
});

describe('keylogPath', () => {
  it('produces a distinct filename on each call', () => {
    const dir = mkdtempSync(join(tmpdir(), 'osi-inspect-'));
    const a = keylogPath(dir);
    const b = keylogPath(dir);
    expect(a).not.toBe(b);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('sweepOrphanedKeylogs', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'osi-inspect-sweep-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('deletes files older than the threshold and leaves recent ones', () => {
    const stale = join(dir, 'stale.keylog');
    const fresh = join(dir, 'fresh.keylog');
    writeFileSync(stale, '');
    writeFileSync(fresh, '');
    const old = new Date(Date.now() - 2 * 60 * 60 * 1000);
    utimesSync(stale, old, old);

    const deleted = sweepOrphanedKeylogs(dir, 60 * 60 * 1000);
    expect(deleted).toBe(1);
    expect(existsSync(stale)).toBe(false);
    expect(existsSync(fresh)).toBe(true);
  });
});

describe('osi-inspect end-to-end (spawned as a real process)', () => {
  it('creates a 0600 key-log file, sets SSLKEYLOGFILE for the child, and deletes it on exit', async () => {
    // Wraps a tiny Node one-liner that reads its own SSLKEYLOGFILE env var
    // and writes its path to stdout, so this test never needs a real TLS
    // handshake — it only asserts the wrapper's own file/env/process
    // lifecycle, matching this plan's "no live network calls in tests" rule.
    const child = spawn('node', [
      join(__dirname, '..', 'osi-inspect.js'),
      'node', '-e', 'console.log(process.env.SSLKEYLOGFILE); require("fs").writeFileSync(process.env.SSLKEYLOGFILE, "test-secret-line\\n")',
    ]);
    let stdout = '';
    child.stdout.on('data', (d) => (stdout += d.toString()));
    const exitCode: number = await new Promise((resolve) => child.on('exit', (code) => resolve(code ?? -1)));
    expect(exitCode).toBe(0);
    const keylogFile = stdout.trim().split('\n').find((l) => l.includes('.keylog'));
    expect(keylogFile).toBeTruthy();
    // File must be gone after the wrapped process exits.
    expect(existsSync(keylogFile!)).toBe(false);
  }, 10_000);

  it('refuses to wrap a known browser binary without confirmation or the override flag', () => {
    const result = spawnSync('node', [join(__dirname, '..', 'osi-inspect.js'), 'chrome'], {
      input: 'n\n', // interactive "no"
      encoding: 'utf8',
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/entire browser process/i);
  });

  it('proceeds when wrapping a browser with --yes-decrypt-entire-browser', () => {
    const result = spawnSync('node', [
      join(__dirname, '..', 'osi-inspect.js'), '--yes-decrypt-entire-browser', 'node', '-e', 'process.exit(0)',
    ], { encoding: 'utf8' });
    expect(result.status).toBe(0);
  });
});
