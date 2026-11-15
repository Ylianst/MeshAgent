import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
const source=new URL('../meshcore/KVM/Linux/kwin-input-bridge/',import.meta.url);
const root=fs.mkdtempSync(path.join(os.tmpdir(),'meshagent-kwin-assets-'));
try {
 const directory=path.join(root,'meshcore/KVM/Linux/kwin-input-bridge');
 fs.mkdirSync(directory,{recursive:true});fs.mkdirSync(path.join(root,'modules'));
 fs.copyFileSync(new URL('generate-assets.mjs',source),path.join(directory,'generate-assets.mjs'));
 const scripts=['wire_bridge.py','session.py','install.py'].map(name=>[name,fs.readFileSync(new URL(name,source),'utf8').replaceAll('\r\n','\n')]);
 const run=(...args)=>{const result=spawnSync(process.execPath,[path.join(directory,'generate-assets.mjs'),...args],{encoding:'utf8'});assert.equal(result.status,0,result.stderr);};
 for(const [name,text] of scripts)fs.writeFileSync(path.join(directory,name),text);
 run();const expected=fs.readFileSync(path.join(root,'modules/linux-kwin-companion-assets.js'));
 for(const [name,text] of scripts)fs.writeFileSync(path.join(directory,name),text.replaceAll('\n','\r\n'));
 run('--check');run();assert.deepEqual(fs.readFileSync(path.join(root,'modules/linux-kwin-companion-assets.js')),expected);
 console.log('KWin payload and source hashes are identical for LF and CRLF checkouts');
} finally {fs.rmSync(root,{recursive:true,force:true});}
