import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
export function createAuthFixture() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-client-auth-'));
    fs.chmodSync(dir, 0o700);
    const file = path.join(dir, 'token');
    let token = randomBytes(32).toString('hex');
    const rotate = () => { token = randomBytes(32).toString('hex'); fs.writeFileSync(file, token + '\n', { mode: 0o600 }); };
    rotate();
    return { file, get token() { return token; }, rotate, close: () => fs.rmSync(dir, { recursive: true, force: true }), createServer: (accept: (socket: net.Socket) => void = () => { }) => net.createServer(socket => { let buffer = ''; const auth = (chunk: Buffer) => { buffer += chunk.toString('utf8'); const end = buffer.indexOf('\n'); if (end < 0)
            return; socket.off('data', auth); try {
            const msg = JSON.parse(buffer.slice(0, end));
            if (msg.type !== 'authenticate' || msg.token !== token || Object.keys(msg).length !== 2) {
                socket.destroy();
                return;
            }
        }
        catch {
            socket.destroy();
            return;
        } socket.write('{"type":"authenticated"}\n'); accept(socket); }; socket.on('data', auth); }) };
}
