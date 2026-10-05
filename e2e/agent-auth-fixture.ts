import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
/** Created by the runner; inherited by workers and Next. Never use operator credentials. */
export function ensureE2EAgentCredential(): string {
    const existing = process.env.NETWORK_MONITOR_E2E_TOKEN_FILE;
    if (existing)
        return existing;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'network-monitor-e2e-agent-'));
    fs.chmodSync(dir, 0o700);
    const file = path.join(dir, 'token');
    fs.writeFileSync(file, randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
    process.env.NETWORK_MONITOR_E2E_TOKEN_FILE = file;
    // Only the creator removes its own directory, after runner teardown; worker exits don't unlink it.
    process.once('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
    return file;
}
