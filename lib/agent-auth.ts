import fs from 'node:fs';
import path from 'node:path';

function invalid(): Error { return new Error('unsafe or unavailable agent credential'); }
export function resolveAgentTokenPath(): string {
  const value = process.env.AGENT_TOKEN_FILE ?? (process.env.HOME ? path.join(process.env.HOME, '.network-monitor', 'agent-control-token') : '');
  if (!path.isAbsolute(value)) throw invalid();
  return value;
}
export function readAgentToken(file: string): string {
  if (!path.isAbsolute(file) || !process.getuid) throw invalid();
  const parent = path.dirname(file);
  const canonicalParent = path.join(fs.realpathSync(path.dirname(parent)), path.basename(parent));
  const dir = fs.lstatSync(canonicalParent);
  if (!dir.isDirectory() || dir.isSymbolicLink() || dir.uid !== process.getuid() || (dir.mode & 0o7777) !== 0o700) throw invalid();
  const fd = fs.openSync(path.join(canonicalParent, path.basename(file)), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || stat.nlink !== 1 || (stat.mode & 0o7777) !== 0o600) throw invalid();
    const bytes = Buffer.alloc(66);
    try {
      let length = 0;
      while (length < bytes.length) { const n = fs.readSync(fd, bytes, length, bytes.length - length, null); if (!n) break; length += n; }
      if (length !== 65 || !/^[0-9a-f]{64}\n$/.test(bytes.subarray(0, length).toString('latin1'))) throw invalid();
      return bytes.subarray(0, 64).toString('latin1');
    } finally { bytes.fill(0); }
  } finally { fs.closeSync(fd); }
}
