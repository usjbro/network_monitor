#!/usr/bin/env node
// osi-inspect — launches exactly one target process with SSLKEYLOGFILE set
// to a fresh, ephemeral, 0600 file, so the capture agent's KeyLogWatcher can
// decrypt that one process's TLS traffic for this run only. No CA, no
// certificate forging, no traffic redirection — see
// docs/superpowers/specs/2026-08-29-tls-interception-design.md, Components §2.
//
// Registration: once the child's PID is known, this wrapper POSTs
// register_decrypt_eligible to the relay's /api/control endpoint (which
// forwards it to the capture agent's KeyLogWatcher over the existing
// TCP control channel — see docs/wire-protocol.md), and unregisters on the
// child's exit, whatever the reason. Without this, the agent never learns
// which PID/key-log file pairing to trust and decryption silently never
// happens despite SSLKEYLOGFILE being set correctly.

const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const readline = require('node:readline');

const BROWSER_BASENAMES = new Set([
  'chrome', 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser',
  'msedge', 'microsoft-edge', 'microsoft-edge-stable', 'firefox', 'firefox-esr',
  'chrome.exe', 'msedge.exe', 'firefox.exe',
]);

function isKnownBrowserBinary(command) {
  const base = path.basename(command).toLowerCase();
  return BROWSER_BASENAMES.has(base);
}

function keylogPath(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  return path.join(dataDir, `${crypto.randomBytes(8).toString('hex')}.keylog`);
}

function sweepOrphanedKeylogs(dataDir, maxAgeMs) {
  if (!fs.existsSync(dataDir)) return 0;
  let deleted = 0;
  const now = Date.now();
  for (const name of fs.readdirSync(dataDir)) {
    if (!name.endsWith('.keylog')) continue;
    const full = path.join(dataDir, name);
    let stat;
    try {
      stat = fs.statSync(full);
    } catch {
      continue; // already gone — race with another process, not our problem
    }
    if (now - stat.mtimeMs > maxAgeMs) {
      try {
        fs.unlinkSync(full);
        deleted += 1;
      } catch {
        // already gone — ignore
      }
    }
  }
  return deleted;
}

function confirmBrowserWrap(command) {
  process.stderr.write(
    `osi-inspect: "${command}" looks like a general-purpose browser.\n` +
    `This will decrypt traffic for the ENTIRE browser process — every tab and origin\n` +
    `currently open or later opened in it, not just one site.\n` +
    `Proceed? [y/N] `
  );
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr, terminal: false });
  return new Promise((resolve) => {
    rl.question('', (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y');
    });
  });
}

// Best-effort POST to the relay's /api/control, which forwards the message
// to the capture agent over its existing TCP control channel. Failures
// (relay not running, agent not connected) are logged and swallowed, never
// thrown — a missing relay must not stop the wrapped process from running,
// it just means decryption won't happen for this run (same "opt-in,
// best-effort" posture as EnrichmentClient elsewhere in this repo). A short
// timeout keeps a hung/unreachable relay from stalling the wrapped process's
// startup or exit.
async function sendControlMessage(relayUrl, message) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2000);
  try {
    const res = await fetch(`${relayUrl}/api/control`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message),
      signal: controller.signal,
    });
    if (!res.ok) {
      process.stderr.write(`osi-inspect: relay rejected ${message.type} (HTTP ${res.status}) — decryption may not be active for this run.\n`);
      return false;
    }
    return true;
  } catch (err) {
    process.stderr.write(`osi-inspect: could not reach relay at ${relayUrl} for ${message.type} (${err.message}) — decryption will not be active for this run.\n`);
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

async function main() {
  const dataDir = path.join(process.cwd(), '.data', 'keylogs');
  sweepOrphanedKeylogs(dataDir, 60 * 60 * 1000); // 1 hour orphan threshold

  let args = process.argv.slice(2);
  const yesDecryptBrowser = args.includes('--yes-decrypt-entire-browser');
  args = args.filter((a) => a !== '--yes-decrypt-entire-browser');

  if (args.length === 0) {
    process.stderr.write('usage: osi-inspect [--yes-decrypt-entire-browser] <command> [args...]\n');
    process.exit(2);
    return;
  }

  const [command, ...commandArgs] = args;

  if (isKnownBrowserBinary(command) && !yesDecryptBrowser) {
    const confirmed = await confirmBrowserWrap(command);
    if (!confirmed) {
      process.stderr.write('osi-inspect: refusing to wrap entire browser process without confirmation.\n');
      process.exit(1);
      return;
    }
  }

  // Overridable for tests and for non-default relay ports/hosts; defaults to
  // the same loopback address+port every other piece of this app assumes
  // (see CLAUDE.md — the relay is always bound to 127.0.0.1:3000).
  const relayUrl = process.env.OSI_INSPECT_RELAY_URL || 'http://127.0.0.1:3000';

  const keylog = keylogPath(dataDir);
  fs.writeFileSync(keylog, '', { mode: 0o600 }); // created 0600 before the child can ever write to it

  let unregistered = false;
  const cleanup = async (pid) => {
    if (pid !== undefined && !unregistered) {
      unregistered = true;
      await sendControlMessage(relayUrl, { type: 'unregister_decrypt_eligible', pid });
    }
    try {
      fs.unlinkSync(keylog);
    } catch {
      /* already gone */
    }
  };
  // Synchronous last-resort fallback if the process exits without the
  // 'exit'/'error' handlers below getting a chance to run their async
  // cleanup (e.g. an uncaught exception elsewhere) — best-effort file
  // removal only, since fetch() can't run inside a synchronous 'exit'
  // handler. The unregister POST is not repeated here; it's a no-op on the
  // agent side if the process that owned the PID is already gone.
  process.on('exit', () => {
    try {
      fs.unlinkSync(keylog);
    } catch {
      /* already gone, or normal cleanup() already removed it */
    }
  });

  const child = spawn(command, commandArgs, {
    stdio: 'inherit',
    env: { ...process.env, SSLKEYLOGFILE: keylog },
  });

  child.on('error', async (err) => {
    process.stderr.write(`osi-inspect: failed to launch "${command}": ${err.message}\n`);
    await cleanup(child.pid);
    process.exit(1);
  });

  // Registered as soon as the PID is known, rather than before spawn — a
  // PID doesn't exist to register until the child process actually starts.
  // This leaves a small window where the child's very first TLS handshake
  // could begin before registration completes; closing that fully would
  // require pausing the child's own start, which plain child_process has no
  // primitive for. Registering immediately (not deferred to next tick)
  // keeps that window as small as this API allows.
  if (child.pid !== undefined) {
    sendControlMessage(relayUrl, {
      type: 'register_decrypt_eligible',
      pid: child.pid,
      keylogPath: keylog,
    });
  }

  child.on('exit', async (code, signal) => {
    await cleanup(child.pid);
    if (signal) {
      // Match the wrapped process's signal-based termination rather than
      // inventing an unrelated exit code for it.
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });
}

if (require.main === module) {
  main();
}

module.exports = { isKnownBrowserBinary, keylogPath, sweepOrphanedKeylogs, sendControlMessage };
