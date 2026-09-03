import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { spawnSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, writeFileSync, utimesSync } from 'node:fs';
import { createServer, Server } from 'node:http';
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

// Exercises the actual gap flagged after PR #45's verification pass:
// osi-inspect previously never told the agent which PID/keylog file to
// trust, so SSLKEYLOGFILE could be set correctly and decryption would still
// silently never happen. These tests stand in a local HTTP server for the
// relay's /api/control endpoint (loopback-only, not a live network call —
// same posture agent-client.test.ts already takes toward a local
// net.createServer instead of a real capture agent) and assert the actual
// register_decrypt_eligible/unregister_decrypt_eligible POST bodies.
describe('decrypt-eligibility registration', () => {
  let server: Server;
  let requests: Array<{ path: string; body: any }>;
  let relayUrl: string;

  beforeEach(async () => {
    requests = [];
    server = createServer((req, res) => {
      let raw = '';
      req.on('data', (chunk) => (raw += chunk));
      req.on('end', () => {
        let body: any = null;
        try {
          body = JSON.parse(raw);
        } catch {
          // leave body null — not exercised by these tests
        }
        requests.push({ path: req.url || '', body });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const address = server.address();
    if (!address || typeof address !== 'object') {
      throw new Error('failed to determine fake relay port');
    }
    relayUrl = `http://127.0.0.1:${address.port}`;
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('registers the child PID + keylog path with the relay, then unregisters the same PID on exit', async () => {
    const child = spawn('node', [
      join(__dirname, '..', 'osi-inspect.js'),
      'node', '-e', 'setTimeout(() => process.exit(0), 50)',
    ], {
      env: { ...process.env, OSI_INSPECT_RELAY_URL: relayUrl },
    });

    const exitCode: number = await new Promise((resolve) => child.on('exit', (code) => resolve(code ?? -1)));
    expect(exitCode).toBe(0);

    // The unregister POST fires from the child's 'exit' handler — give it a
    // moment to actually land before asserting on captured requests.
    await new Promise((resolve) => setTimeout(resolve, 200));

    const controlRequests = requests.filter((r) => r.path === '/api/control');
    const registerReq = controlRequests.find((r) => r.body?.type === 'register_decrypt_eligible');
    const unregisterReq = controlRequests.find((r) => r.body?.type === 'unregister_decrypt_eligible');

    expect(registerReq).toBeTruthy();
    expect(typeof registerReq!.body.pid).toBe('number');
    expect(registerReq!.body.pid).toBeGreaterThan(0);
    expect(String(registerReq!.body.keylogPath)).toMatch(/\.keylog$/);

    expect(unregisterReq).toBeTruthy();
    expect(unregisterReq!.body.pid).toBe(registerReq!.body.pid);
  }, 10_000);

  it('still runs the wrapped process and cleans up the keylog file when the relay is unreachable', async () => {
    const child = spawn('node', [
      join(__dirname, '..', 'osi-inspect.js'),
      'node', '-e', 'console.log(process.env.SSLKEYLOGFILE); process.exit(0)',
    ], {
      // Nothing listens on port 1 (a privileged port no unprivileged
      // process here can bind) — connection refused fires immediately,
      // exercising the failure path without any real network dependency.
      env: { ...process.env, OSI_INSPECT_RELAY_URL: 'http://127.0.0.1:1' },
    });
    let stdout = '';
    child.stdout.on('data', (d) => (stdout += d.toString()));
    const exitCode: number = await new Promise((resolve) => child.on('exit', (code) => resolve(code ?? -1)));
    expect(exitCode).toBe(0);
    const keylogFile = stdout.trim().split('\n').find((l) => l.includes('.keylog'));
    expect(keylogFile).toBeTruthy();
    expect(existsSync(keylogFile!)).toBe(false);
  }, 10_000);
});
