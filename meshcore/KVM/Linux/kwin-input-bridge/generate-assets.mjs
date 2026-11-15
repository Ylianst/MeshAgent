// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import crypto from 'node:crypto';
const root=new URL('../../../../',import.meta.url);
const target=new URL('modules/linux-kwin-companion-assets.js',root);
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
// Python sources are text. Canonical LF bytes keep payloads and source hashes
// reproducible when the generator runs from a Windows CRLF checkout.
const readSource=name=>Buffer.from(fs.readFileSync(new URL(name,import.meta.url),'utf8').replaceAll('\r\n','\n'));
const names=['wire_bridge.py','session.py'];
const files=Object.fromEntries(names.map(name=>[name,readSource(name).toString('base64')]));
const payload=Buffer.from(JSON.stringify(files));
const helper=readSource('install.py').toString('utf8');
const sourceSha256=hash(Buffer.concat([...names,'install.py'].map(readSource)));
const assets={version:2,protocol:'wayland-input-method-v1',sourceSha256,bytes:payload.length,sha256:hash(payload),payload:payload.toString('base64'),helper};
const expected='/* SPDX-License-Identifier: Apache-2.0 */\nmodule.exports = '+JSON.stringify(assets)+';\n';
if(process.argv[2]==='--check') {
 if(fs.readFileSync(target,'utf8').replaceAll('\r\n','\n')!==expected)throw Error('Stale input-method wire assets');
 console.log('Input-method wire assets match source');
} else {
 if(process.argv.length!==2)throw Error('Usage: node generate-assets.mjs [--check]');
 fs.writeFileSync(target,expected);
 console.log('Generated architecture-independent input-method wire assets');
}
