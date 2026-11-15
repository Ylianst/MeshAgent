// SPDX-License-Identifier: Apache-2.0
// Embed installer implementation sources; no installer code is executed here.
import fs from 'node:fs';
import {deflateSync} from 'node:zlib';
const target=new URL('../../microscript/ILibDuktape_Polyfills.c',import.meta.url);
let source=fs.readFileSync(target,'utf8');
for(const name of ['_agentNodeId','monitor-info','user-sessions','linux-kwin-companion','linux-kwin-companion-assets','linux-gala-companion','agent-installer','service-manager','linux-gnome-companion','linux-gnome-session','linux-gnome-startup','linux-gnome-activation-source','linux-gnome-signout-source','linux-gnome-greeter-source']) {
 const script=name==='linux-gnome-activation-source'?'activate-session.js':name==='linux-gnome-signout-source'?'signout-session.js':name==='linux-gnome-greeter-source'?'refresh-greeter.js':null;
 const prefix=name==='linux-gnome-greeter-source'?'const MESH_ACTIVATION_SOURCE='+JSON.stringify(fs.readFileSync(new URL('activate-session.js',import.meta.url),'utf8'))+';\n':'';
 const input=script
  ? Buffer.from('module.exports = '+JSON.stringify(prefix+fs.readFileSync(new URL(script,import.meta.url),'utf8'))+';\n')
  : fs.readFileSync(new URL('../../modules/'+name+'.js',import.meta.url));
 const encoded=deflateSync(input).toString('base64');
 const statement='\tduk_peval_string_noresult(ctx, "addCompressedModule(\''+name+'\', Buffer.from(\''+encoded+'\', \'base64\'), \'2026-11-07T00:00:00.000Z\');");';
 const match=new RegExp('^[ \\t]*duk_peval_string_noresult\\(ctx, "addCompressedModule\\(\''+name+'\',[^\\r\\n]*$','gm');
 const count=[...source.matchAll(match)].length;
 if(count>1||(!count&&name==='agent-installer'))throw Error('Unexpected embedded module count: '+name);
 if(count)source=source.replace(match,()=>statement);
 else {
  const anchor=/^[ \t]*duk_peval_string_noresult\(ctx, "addCompressedModule\('agent-installer',[^\r\n]*$/gm;
  if([...source.matchAll(anchor)].length!==1)throw Error('Missing installer embedding anchor');
  source=source.replace(anchor,line=>line+'\n'+statement);
 }
}
if(process.argv.length>3||(process.argv[2]&&process.argv[2]!=='--check'))throw Error('Usage: node generate-installer-modules.mjs [--check]');
if(process.argv[2]==='--check') {
 if(fs.readFileSync(target,'utf8')!==source)throw Error('Installer embeddings are stale');
 console.log('Installer ownership and activation sources match embedded modules');
} else fs.writeFileSync(target,source,'utf8');
