import { afterEach, expect, test } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readAgentToken } from '../agent-auth';
import { isAgentAuthenticatedMessage } from '../agent-mapping';
const dirs: string[] = [];
function fixture() { const dir=fs.mkdtempSync(path.join(os.tmpdir(),'agent-auth-')); dirs.push(dir);fs.chmodSync(dir,0o700); const file=path.join(dir,'token');fs.writeFileSync(file,'a'.repeat(64)+'\n',{mode:0o600});return {dir,file}; }
afterEach(()=>{for(const dir of dirs.splice(0))fs.rmSync(dir,{recursive:true,force:true});});
test('reads exactly the private lowercase credential',()=>{const {file}=fixture();expect(readAgentToken(file)).toBe('a'.repeat(64));});
test.each(['missing','relative','mode','parent-mode','symlink','parent-symlink','hard-link','uppercase','extra','short','directory'])('rejects unsafe credential: %s',kind=>{const {dir,file}=fixture();let target=file;switch(kind){case 'missing':fs.unlinkSync(file);break;case 'relative':target='token';break;case 'mode':fs.chmodSync(file,0o644);break;case 'parent-mode':fs.chmodSync(dir,0o755);break;case 'symlink':fs.renameSync(file,file+'.real');fs.symlinkSync(file+'.real',file);break;case 'parent-symlink':fs.symlinkSync(dir,path.join(dir,'alias'));target=path.join(dir,'alias','token');break;case 'hard-link':fs.linkSync(file,file+'.link');break;case 'uppercase':fs.writeFileSync(file,'A'.repeat(64)+'\n');break;case 'extra':fs.appendFileSync(file,'\n');break;case 'short':fs.writeFileSync(file,'a');break;case 'directory':fs.unlinkSync(file);fs.mkdirSync(file);break;}expect(()=>readAgentToken(target)).toThrow();});
test('acknowledgement has the exact supported shape',()=>{expect(isAgentAuthenticatedMessage({type:'authenticated'})).toBe(true);for(const value of [null,[],{type:'authenticate'},{type:'authenticated',token:'x'}])expect(isAgentAuthenticatedMessage(value)).toBe(false);});
test('rejects high-bit bytes that ASCII decoding would mask',()=>{const {file}=fixture();fs.writeFileSync(file,Buffer.concat([Buffer.alloc(64,0xe1),Buffer.from('\n')]));expect(()=>readAgentToken(file)).toThrow();});
