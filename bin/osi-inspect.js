#!/usr/bin/env node
// osi-inspect — launches exactly one target process with SSLKEYLOGFILE set
// to a fresh, ephemeral, 0600 file, so the capture agent's KeyLogWatcher can
// decrypt that one process's TLS traffic for this run only. No CA, no
// certificate forging, no traffic redirection — see
// docs/superpowers/specs/2026-08-29-tls-interception-design.md, Components §2.

const { spawnSync } = require('node:child_process');
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

  const keylog = keylogPath(dataDir);
  fs.writeFileSync(keylog, '', { mode: 0o600 }); // created 0600 before the child can ever write to it

  const cleanup = () => {
    try {
      fs.unlinkSync(keylog);
    } catch {
      /* already gone */
    }
  };

  const result = spawnSync(command, commandArgs, {
    stdio: 'inherit',
    env: { ...process.env, SSLKEYLOGFILE: keylog },
  });

  cleanup();

  if (result.error) {
    process.stderr.write(`osi-inspect: failed to launch "${command}": ${result.error.message}\n`);
    process.exit(1);
    return;
  }
  process.exit(result.status ?? 1);
}

if (require.main === module) {
  main();
}

module.exports = { isKnownBrowserBinary, keylogPath, sweepOrphanedKeylogs };
