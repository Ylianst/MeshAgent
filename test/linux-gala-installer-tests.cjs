/* SPDX-License-Identifier: Apache-2.0 */
const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const source=fs.readFileSync('modules/linux-gala-companion.js','utf8');
let calls=[],present=true,active=false,target=true,result=1;
const store={detect:()=>present,active:()=>active,target:()=>target,
 install:owner=>(calls.push(['install',owner]),{status:result,changed:true,errno:result===1?0:1}),
 release:owner=>(calls.push(['release',owner]),{status:1,changed:true,errno:0}),
 offerSignOut:()=>(calls.push(['offer']),{state:'declined'})};
const context={module:{exports:{}},process:{platform:'linux'},Buffer,require:name=>{
 if(name==='fs')return {existsSync:path=>(assert.equal(path,'/usr/bin/gala'),present)};
 if(name==='_gala-companion-store')return store;
 if(name==='SHA256Stream')return {create:()=>({syncHash:bytes=>crypto.createHash('sha256').update(bytes).digest()})};
 throw Error(name);
}};vm.runInNewContext(source,context);const api=context.module.exports;
const service={name:'meshagent',path:'/usr/local/mesh_services/meshagent/meshagent'};
let r=api.install(service);assert.equal(r.activation,'needs-sign-in');assert.equal(calls.length,1); // Never prompts in install/update.
assert.equal(api.offerSignOut(r).state,'declined');assert.equal(calls[1][0],'offer');
calls=[];active=true;r=api.install(service);assert.equal(r.activation,'active');assert.equal(api.offerSignOut(r).state,'not-needed');assert.equal(calls.length,1);
active=false;target=false;r=api.install(service);assert.equal(r.activation,'next-wayland-sign-in');assert.equal(api.offerSignOut(r).state,'not-needed');
calls=[];result=0;r=api.install(service,{name:'old',path:'/opt/old-agent'});assert.equal(r.state,'error');assert.equal(calls.length,1); // Old ownership survives failure.
calls=[];result=1;api.install(service,{name:'old',path:'/opt/old-agent'});assert.deepEqual(calls.map(c=>c[0]),['install','release']);
calls=[];present=false;assert.equal(api.install(service).state,'not-applicable');assert.equal(calls.length,0);
present=true;assert.throws(()=>api.install({name:'bad\nname',path:'/opt/agent'}));assert.throws(()=>api.install({name:'ok',path:'/../agent'}));
console.log('Gala installer: activation-only consent, Later, existing active/Classic isolation, failure-safe ownership transfer and invalid identity checks passed');
