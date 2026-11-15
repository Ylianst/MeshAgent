// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
const source=fs.readFileSync(new URL('cinnamon-input.js',import.meta.url),'utf8');
const target=new URL('linux_kvm_cinnamon_source.h',import.meta.url);
const output='/* Generated from cinnamon-input.js; SPDX-License-Identifier: Apache-2.0 */\nstatic const char cinnamon_source[] = '+JSON.stringify(source)+';\n';
if(process.argv[2]==='--check') {
 if(fs.readFileSync(target,'utf8')!==output)throw Error('Cinnamon input source is stale');
} else fs.writeFileSync(target,output);
