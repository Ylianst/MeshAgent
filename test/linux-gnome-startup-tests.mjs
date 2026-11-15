// SPDX-License-Identifier: Apache-2.0
// Only GNOME startup content, private-path independence, and exact v1 migration.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const source=fs.readFileSync(new URL('../modules/linux-gnome-startup.js',import.meta.url),'utf8');
const legacy=fs.readFileSync(new URL('fixtures/linux-gnome-startup-v1.js',import.meta.url),'utf8');
const activation=fs.readFileSync(new URL('../addons/gnome-shell/activate-session.js',import.meta.url),'utf8');
const owner='a'.repeat(64),path='/usr/local/mesh_services/meshagent/meshagent';
let passed=0;function check(ok,label){assert.ok(ok,label);passed++;}
function fixture(options={}) {
 const entries=new Map(),greeters=new Map(),events=[];let installs=0;
 const store={
  autostartInstall(id,bytes){events.push({op:'install',id,bytes});installs++;
   if(options.installFail===installs)return {status:0,changed:false};
   if(options.installUncertain===installs)return {status:-1,changed:true};
   const prior=entries.get(id);if(prior&&!prior.equals(bytes))return {status:0,changed:false};
   entries.set(id,Buffer.from(bytes));return {status:1,changed:!prior};},
  autostartRemove(id,bytes){events.push({op:'remove',id,bytes});
   if(options.removeUncertain)return {status:-1,changed:true};
   const prior=entries.get(id);if(prior&&!prior.equals(bytes))return {status:0,changed:false};
   entries.delete(id);return {status:1,changed:!!prior};}
 };
 store.greeterStartupInstall=(id,bytes)=>{if(options.greeterFail)return {status:0,changed:false};const prior=greeters.get(id);if(prior&&!prior.equals(bytes))return {status:0,changed:false};greeters.set(id,Buffer.from(bytes));return {status:1,changed:!prior};};
 store.greeterStartupRemove=(id,bytes)=>{const prior=greeters.get(id);if(prior&&!prior.equals(bytes))return {status:0,changed:false};greeters.delete(id);return {status:1,changed:!!prior};};
 function load(code){const ctx={module:{exports:{}},Buffer,require(name){
  if(name==='_gnome-companion-store')return store;
  if(name==='linux-gnome-activation-source')return options.activation===undefined?activation:options.activation;
  throw Error('Unexpected require '+name);
 }};vm.runInNewContext(code,ctx);return ctx.module.exports;}
 return {api:load(source),old:load(legacy),events,entries,greeters};
}
let f=fixture(),r=f.api.install(owner,path);check(r.status===1&&r.changed,'fresh install');
const bytes=f.entries.get(owner),text=bytes.toString();
const greeter=f.greeters.get(owner).toString();
check(greeter.includes('[Service]\nExecStartPre=-/usr/bin/timeout --kill-after=1s 8s /usr/bin/gjs'),'bounded greeter hook cannot fail local Shell startup');
check(!greeter.includes(path)&&!greeter.includes('sudo')&&!greeter.includes('/bin/sh'),'greeter hook runs public code as the existing greeter user');
check(text.startsWith('# MeshAgent GNOME autostart 2\n'),'versioned managed entry');
check(text.includes('Exec=/usr/bin/timeout --kill-after=1s 8s /usr/bin/gjs -c "'),'bounded stock interpreter');
check(!text.includes('-b64exec')&&!text.includes(path),'no access to private Agent executable required');
check(text.includes('X-MeshAgent-Service='+Buffer.from(path).toString('base64')+'\n'),'service identity remains bound');
check(text.includes('OnlyShowIn=GNOME;\n')&&text.includes('NoDisplay=true\n')&&text.includes('Terminal=false\n'),'hidden GNOME-only entry');
check(!text.includes('sudo')&&!text.includes('runuser')&&!text.includes('/bin/sh'),'no privilege request or command shell');
const encoded=/base64_decode\('([A-Za-z0-9+/=]+)'\)/.exec(text)[1];
check(Buffer.from(encoded,'base64').toString()===activation,'exact activation implementation embedded');
check(bytes.length<32768,'entry fits unchanged native writer bound');
r=f.api.install(owner,path);check(r.status===1&&!r.changed,'idempotent install');
r=f.api.install(owner,'/different/agent');check(r.status===0&&f.entries.get(owner).equals(bytes),'different service path cannot replace entry');
r=f.api.remove(owner,path);check(r.status===1&&r.changed&&!f.entries.has(owner)&&!f.greeters.has(owner),'exact new entry and greeter hook removal');
r=f.api.remove(owner,path);check(r.status===1&&!r.changed,'absent entry removal');
f=fixture();f.old.install(owner,path);const oldBytes=Buffer.from(f.entries.get(owner));f.events.length=0;
r=f.api.install(owner,path);check(r.status===1&&r.changed,'v1 entry migration succeeds');
check(f.events.map(e=>e.op).join(',')==='install,remove,install','migration removes only exact known v1 then installs v2');
check(!f.entries.get(owner).equals(oldBytes)&&f.entries.get(owner).equals(bytes),'migration produces exact v2 entry');
f=fixture();f.old.install(owner,path);r=f.api.remove(owner,path);check(r.status===1&&r.changed&&!f.entries.has(owner),'uninstall accepts exact v1 entry');
f=fixture();f.old.install(owner,path);r=f.api.install(owner,'/different/agent');check(r.status===0&&f.entries.get(owner).equals(oldBytes),'migration refuses different old service path');
for(const edited of [Buffer.from('edited'),Buffer.concat([oldBytes,Buffer.from('# edited\n')]),Buffer.concat([bytes,Buffer.from('# edited\n')])]) {
 f=fixture();f.entries.set(owner,edited);r=f.api.install(owner,path);check(r.status===0&&f.entries.get(owner).equals(edited),'install preserves edited entry');
 r=f.api.remove(owner,path);check(r.status===0&&f.entries.get(owner).equals(edited),'uninstall preserves edited entry');
}
f=fixture({installUncertain:1});r=f.api.install(owner,path);check(r.status===-1&&f.events.length===1,'fsync uncertainty never starts migration');
f=fixture({greeterFail:true});r=f.api.install(owner,path);check(r.status===0&&r.changed&&f.entries.has(owner),'greeter publication failure reports the desktop entry already changed');
f=fixture();f.api.install(owner,path);f.greeters.set(owner,Buffer.from('admin edited'));r=f.api.remove(owner,path);check(r.status===0&&r.changed&&f.greeters.get(owner).toString()==='admin edited','uninstall preserves edited greeter hook and reports prior desktop removal');
f=fixture({removeUncertain:true});f.entries.set(owner,oldBytes);r=f.api.install(owner,path);check(r.status===-1&&f.events.length===2,'migration removal uncertainty stops before new write');
f=fixture({installFail:2});f.entries.set(owner,oldBytes);r=f.api.install(owner,path);check(r.status===0&&r.changed&&!f.entries.has(owner),'failed replacement reports previous removal');
for(const bad of ['relative','/tmp/a\nExec=evil','/tmp/a\r','/tmp/a\t','/tmp/a\0','/tmp/a=b']) {
 f=fixture();assert.throws(()=>f.api.install(owner,bad));check(!f.events.length,'invalid identity rejected before native writer');
}
for(const special of ['agent with space','agent "quote"','agent $ `','agent %f','agent \\ name',"agent $(id); '& �"]) {
 f=fixture();f.api.install(owner,'/private/'+special);check(f.entries.get(owner).toString().includes('X-MeshAgent-Service='+Buffer.from('/private/'+special).toString('base64')+'\n'),'special path is data only');
}
f=fixture({activation:'x'.repeat(30000)});assert.throws(()=>f.api.install(owner,path));check(!f.events.length,'oversized activation fails before native mutation');
f=fixture({activation:''});assert.throws(()=>f.api.install(owner,path));check(!f.events.length,'missing activation fails before native mutation');
console.log(JSON.stringify({passed,scope:'GNOME startup launcher, private Agent path independence, exact legacy migration'}));
