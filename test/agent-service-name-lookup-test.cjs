// SPDX-License-Identifier: Apache-2.0
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../modules/_agentNodeId.js'),'utf8');
function lookup({units={},locations={},execPath='/opt/custom-agent',platform='linux',type='systemd',msh={},fallback=[]}={}) {
 const calls=[],module={exports:{}};
 const manager={getServiceType:()=>type,enumerateService:()=>{calls.push('enumerate');return fallback;},getService:name=>{calls.push(name);if(!(name in locations))throw Error('unknown unit');return {name,appLocation:()=>locations[name]};}};
 vm.runInNewContext(source,{module,_MSH:()=>msh,process:{platform,execPath},require:name=>{
  if(name==='service-manager')return {manager};
  if(name==='fs')return {readdirSync:()=>Object.keys(units),readFileSync:p=>{const name=p.split('/').pop();if(units[name] instanceof Error)throw units[name];return Buffer.from(units[name]);}};
  throw Error('Unexpected dependency: '+name);
 }});
 return {name:module.exports.serviceName(),calls};
}
let units={};for(let i=0;i<619;i++)units['other'+i+'.service']='[Service]\nExecStart=/usr/bin/other'+i+'\n';
assert.deepEqual(lookup({units}),{name:'meshagent',calls:[]});
units['custom.service']='[Service]\nExecStart=/opt/custom-agent\n';
assert.deepEqual(lookup({units,locations:{custom:'/opt/custom-agent'}}),{name:'custom',calls:['custom']});
assert.deepEqual(lookup({units:{'escaped.service':String.raw`ExecStart=/opt/custom\x2dagent`},locations:{escaped:'/opt/custom-agent'}}),{name:'escaped',calls:['escaped']});
assert.deepEqual(lookup({units:{'wrong.service':'Environment=/opt/custom-agent\nExecStart=/bin/other'},locations:{wrong:'/bin/other'}}),{name:'meshagent',calls:['wrong']});
assert.deepEqual(lookup({units:{'broken.service':new Error('unreadable'),'not-a-unit':'ExecStart=/opt/custom-agent'}}),{name:'meshagent',calls:[]});
assert.deepEqual(lookup({msh:{meshServiceName:'configured'}}),{name:'configured',calls:[]});
assert.deepEqual(lookup({type:'init',fallback:[{name:'legacy',appLocation:()=>'/opt/custom-agent'}]}),{name:'legacy',calls:['enumerate']});
console.log('PASS: exact/custom/encoded service lookup, unrelated-unit bound, configured name, and legacy fallback');
