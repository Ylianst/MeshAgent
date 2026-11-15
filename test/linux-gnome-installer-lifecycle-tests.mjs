// SPDX-License-Identifier: Apache-2.0
// Only installer ownership logic and its service lifecycle call sites.
import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const companionSource=fs.readFileSync(new URL('../modules/linux-gnome-companion.js',import.meta.url),'utf8');
const installerSource=fs.readFileSync(new URL('../modules/agent-installer.js',import.meta.url),'utf8');
const originalAssets=require('../modules/linux-gnome-companion-assets.js');
let passed=0;
function check(ok,label){assert.ok(ok,label);passed++;}
function companion(options={}){
 const events=[], assets=structuredClone(originalAssets);
 const store={
  acquire(...args){events.push({op:'acquire',args});if(options.acquireThrow)throw Error('injected');return options.acquire||{status:1,changed:true,backup:options.backup||''};},
  release(owner){events.push({op:'release',owner});if(options.releaseThrow)throw Error('injected');return options.release||{status:1,changed:true,backup:options.releaseBackup||''};},
  commit(token){events.push({op:'commit',token});if(options.commitThrow)throw Error('injected');return options.commit||{status:1,changed:true};}
 };
 const fakeFs={existsSync(p){return p==='/usr/bin/gnome-shell' ? options.gnome!==false : options.present!==false;}};
 const ctx={module:{exports:{}},Buffer,process:{platform:options.platform||'linux'},require(name){
  if(name==='fs')return fakeFs;
  if(name==='_gnome-companion-store')return store;
  if(name==='linux-gnome-companion-assets')return assets;
  if(name==='linux-gnome-startup')return {
   install(owner,path){events.push({op:'startupInstall',owner,path});return options.startupInstall||{status:1,changed:true};},
   remove(owner,path){events.push({op:'startupRemove',owner,path});return options.startupRemove||{status:1,changed:true};}
  };
  if(name==='linux-gnome-session')return {prepareCurrent(){events.push({op:'prepare'});if(options.prepareThrow)throw Error('activation failure');return options.currentSessions||{state:'no-running-gnome',sessions:[]};},
   prepareGreeter(){events.push({op:'greeter'});if(options.greeterThrow)throw Error('greeter failure');return {state:'greeter-prepared'};}};
  if(name==='SHA256Stream')return{create(){return{syncHash(b){return crypto.createHash('sha256').update(b).digest();}};}};
  throw Error('Unexpected module '+name);
 }};
 vm.runInNewContext(companionSource,ctx);return{api:ctx.module.exports,events,assets};
}
const service={name:'meshagent',path:'/usr/local/mesh_services/meshagent/meshagent'};
const previous={name:'meshagent',path:'/old/meshagent'};
let c=companion(),r=c.api.install(service);
check(r.state==='files-ready'&&r.activation==='pending','ownership success does not claim activation');
check(c.events.slice(-2).map(e=>e.op).join(',')==='prepare,greeter','current sessions and absent greeter prepared after ownership success');
let prepared=companion({prepareThrow:true}),preparedResult=prepared.api.install(service);
check(preparedResult.state==='files-ready'&&preparedResult.currentSessions.state==='activation-pending','activation failure retains durable ownership');
prepared=companion({acquire:{status:0,changed:false}});prepared.api.install(service);
check(!prepared.events.some(e=>e.op==='prepare'),'failed ownership never changes session settings');
prepared=companion({currentSessions:{state:'current-sessions-active',sessions:[]}});preparedResult=prepared.api.install(service);
check(preparedResult.currentSessions.state==='current-sessions-active'&&preparedResult.activation==='pending','current sessions do not claim future-user activation complete');
check(c.events[0].args[0]===crypto.createHash('sha256').update('MeshAgent GNOME service 1\nmeshagent\n/usr/local/mesh_services/meshagent/meshagent').digest('hex'),'stable documented service identity');
check(c.events[0].args[1]===originalAssets.version&&c.events[0].args[2].length===originalAssets.files['metadata.json'].bytes,'exact versioned embedded payload');
c=companion({backup:'new-backup',releaseBackup:'old-backup'});r=c.api.install(service,previous);
check(r.state==='files-ready'&&c.events.map(x=>x.op).join(',')==='acquire,commit,startupInstall,startupRemove,release,commit,prepare,greeter','new startup entry is durable before old entry/lease removal and activation');
c=companion();c.api.install(service,{name:'meshagent',path:'/usr/local/mesh_services/./meshagent/meshagent'});
check(c.events.map(x=>x.op).join(',')==='acquire,startupInstall,prepare,greeter','normalized same-path upgrade retains existing lease');
c=companion({acquire:{status:0,changed:false,errno:16,backup:''}});r=c.api.install(service,previous);
check(r.state==='error'&&r.stage==='acquire'&&c.events.length===1,'acquire refusal preserves previous owner');
c=companion({acquire:{status:-1,changed:true,errno:5,backup:'uncertain'}});r=c.api.install(service,previous);
check(r.state==='error'&&r.changed===true&&r.backup==='uncertain'&&c.events.length===1,'durability failure retained without blind retry');
c=companion({backup:'pending',commit:{status:0,changed:null,errno:5}});r=c.api.install(service,previous);
check(r.stage==='acquire-commit'&&r.backup==='pending'&&r.currentChanged===true&&!c.events.some(x=>x.op==='release'),'commit error preserves old owner and applied-state details');
c=companion({backup:'pending',commitThrow:true});r=c.api.install(service,previous);
check(r.stage==='acquire-commit'&&r.backup==='pending'&&r.changed===null,'cleanup exception preserves pending backup');
c=companion({release:{status:0,changed:false,errno:1,backup:''}});r=c.api.install(service,previous);
check(r.stage==='transfer-release'&&typeof r.activeOwner==='string','transfer failure retains new ownership');
c=companion();c.assets.files['extension.js'].sha256='0'.repeat(64);r=c.api.install(service);
check(r.stage==='payload'&&c.events.length===0,'payload verification precedes mutation');
c=companion();c.assets.version++;r=c.api.install(service);
check(r.stage==='payload'&&c.events.length===0,'metadata and generation must agree');
c=companion();r=c.api.install({name:'bad\nname',path:'/agent'});
check(r.stage==='identity'&&c.events.length===0,'invalid identity cannot reach store');
c=companion({gnome:false,present:false});r=c.api.install(service);
check(r.state==='not-applicable'&&c.events.length===0,'systems without GNOME remain untouched');
c=companion({platform:'win32'});r=c.api.install(service);
check(r.state==='not-applicable'&&c.events.length===0,'other platforms remain untouched');
c=companion();r=c.api.uninstall(service);
check(r.state==='files-retained'&&c.events.map(x=>x.op).join(',')==='startupRemove,release','startup removal precedes shared companion release');
c=companion({present:false});r=c.api.uninstall(service);
check(r.state==='not-applicable'&&c.events.map(x=>x.op).join(',')==='startupRemove','absent companion still cleans own startup entry');
c=companion({release:{status:-1,changed:true,backup:'pending',errno:5}});r=c.api.uninstall(service);
check(r.state==='error'&&r.backup==='pending'&&c.events.map(x=>x.op).join(',')==='startupRemove,release','uncertain release is not retried');
for(const startupInstall of [{status:0,changed:false},{status:-1,changed:true}]){
 c=companion({startupInstall});r=c.api.install(service,previous);
 check(r.state==='error'&&r.stage==='startup-install'&&!c.events.some(e=>['startupRemove','release','prepare'].includes(e.op)),'startup install failure retains previous entry/lease and does not activate');
}
c=companion({startupRemove:{status:0,changed:false}});r=c.api.install(service,previous);
check(r.state==='error'&&r.stage==='startup-transfer'&&!c.events.some(e=>e.op==='release'),'edited previous startup entry preserves previous lease');
c=companion({startupRemove:{status:0,changed:false}});r=c.api.uninstall(service);
check(r.state==='error'&&r.stage==='startup-remove'&&!c.events.some(e=>e.op==='release'),'failed startup removal retains companion lease');

function installer(options={}){
 const events=[], output=[];let installed=options.existing||false;
 const svc={appLocation(){return installed ? '/new/meshagent' : '/old/meshagent';},appWorkingDirectory(){return '/old';},
  start(){events.push('start');if(options.startThrow)throw Error('start failure');},stop(){events.push('stop');},
  isRunning(){events.push('running');return !options.notRunning;},close(){events.push('close');}};
 const manager={installService(serviceOptions){events.push('create');events.push({parameters:JSON.stringify(serviceOptions.parameters),keys:Object.keys(serviceOptions.parameters)});if(options.createThrow)throw Error('create failure');if(options.escapeName)serviceOptions.name=serviceOptions.name.replace(/-/g,'\\x2d');installed=true;},
  uninstallService(){events.push('remove');if(options.removeThrow)throw Error('remove failure');installed=false;},
  getService(name){if(name.endsWith('Diagnostic'))throw Error('absent');return svc;}};
 const ownership={install(current,prior){events.push('acquire');events.push({current,prior});if(options.hookThrow)throw Error('ownership failure');return{state:options.ownershipState||'files-ready',activation:'pending',currentSessions:options.currentSessions};},
  uninstall(old){events.push('release');events.push({old});return{state:'files-removed'};}};
 const ctx={module:{exports:{}},Buffer,_MSH(){return{};},console:{info1(){},setDestination(){},setInfoLevel(){},Destinations:{DISABLED:0}},
  process:{platform:options.platform||'linux',pid:1,execPath:'/installer',stdout:{write(x){output.push(x);}},stderr:{write(x){output.push(x);}},exit(){throw Error('TEST_EXIT');}},
  require(name){if(name==='service-manager')return{manager};if(name==='linux-gnome-companion')return ownership;
   if(name==='linux-gnome-session')return{offerSignOut(current){events.push('offer');if(options.offerThrow)throw Error('choice unavailable');return options.choices||[];},
    offerGreeterRefresh(current){events.push('greeter-offer');return options.greeterChoices||[];}};
   if(name==='user-sessions')return{tty(){return'lab';},getUid(){return 1000;},getProcessOwnerName(){return{name:'lab'};}};
   if(name==='fs')return{existsSync(){return false;},unlinkSync(){}};
   if(name==='win-registry')return{usernameToUserKey(){return'lab';}};
   if(name==='win-bcd')return{enableSafeModeService(){}};
   if(name==='win-firewall')return{addFirewallRule(){}};
   throw Error('Unexpected installer module '+name);
  }};ctx.global=ctx;vm.createContext(ctx);vm.runInContext(installerSource,ctx);
 function run(action){try{vm.runInContext(action,ctx);}catch(e){if(e.message!=='TEST_EXIT')throw e;}}
 return{events,output,run};
}
let i=installer();i.run('installService(["--__skipExit=1"])');
check(i.events.indexOf('create')<i.events.indexOf('start')&&i.events.indexOf('start')<i.events.indexOf('acquire'),'actual install hook follows service create/start');
i=installer({createThrow:true});i.run('installService([])');check(!i.events.includes('acquire'),'create failure never claims companion');
i=installer({startThrow:true});i.run('installService(["--__skipExit=1"])');check(!i.events.includes('acquire'),'start failure never claims companion');
i=installer({notRunning:true});i.run('installService(["--__skipExit=1"])');check(!i.events.includes('acquire'),'failed running-state verification preserves ownership');
i=installer();i.run('uninstallService(["_stop"])');
check(i.events.indexOf('remove')<i.events.indexOf('release'),'actual uninstall hook follows successful service removal');
i=installer({removeThrow:true});i.run('uninstallService(["_stop"])');check(!i.events.includes('release'),'failed removal retains ownership');
i=installer();i.run('uninstallService(["--__skipExit=1"])');
check(!i.events.includes('release')&&i.events.indexOf('remove')<i.events.indexOf('acquire'),'upgrade retains lease during replacement');
check(i.events.find(x=>typeof x==='object'&&x.current)?.prior.path==='/old/meshagent','upgrade preserves previous executable identity');
check(i.events.find(x=>typeof x==='object'&&x.parameters)?.keys.every(key=>/^\d+$/.test(key)),'upgrade metadata cannot become a service argument');
i=installer({startThrow:true});i.run('uninstallService(["--__skipExit=1"])');check(!i.events.includes('release')&&!i.events.includes('acquire'),'failed replacement retains old lease');
i=installer({hookThrow:true});i.run('installService(["--__skipExit=1"])');check(i.output.some(x=>x.includes('setup is incomplete')),'installer reports incomplete ownership setup');
i=installer({platform:'win32',notRunning:true});i.run('installService(["--__skipExit=1"])');
check(!i.events.includes('acquire')&&!i.events.includes('running'),'Linux hook does not change Windows startup verification');
c=companion({greeterThrow:true});r=c.api.install(service);
check(r.state==='files-ready'&&r.greeter.state==='activation-pending'&&r.activation==='pending','greeter failure retains durable files and does not claim complete activation');
i=installer({choices:[{result:{state:'declined'}}]});i.run('installService(["--__skipExit=1"])');
check(i.events.indexOf('acquire')<i.events.indexOf('offer')&&i.output.some(x=>x.includes('until you sign out and sign back in')),'installer offers only after setup and explains decline');
i=installer({choices:[{result:{state:'sign-out-requested'}}]});i.run('installService(["--__skipExit=1"])');
check(i.output.some(x=>x.includes('Sign-out requested'))&&!i.output.some(x=>x.includes('signed out successfully')),'installer reports request without claiming session ended');
i=installer({ownershipState:'error'});i.run('installService(["--__skipExit=1"])');check(!i.events.includes('offer'),'failed companion ownership never asks for sign-out');
i=installer({choices:[{result:{state:'deferred'}}]});i.run('installService(["--__skipExit=1"])');check(i.output.some(x=>x.includes('activation is pending')),'unavailable choice leaves pending-session guidance');
i=installer({escapeName:true});i.run('installService(["--meshServiceName=meshagent-gnome-test","--__skipExit=1"])');
check(i.events.find(x=>typeof x==='object'&&x.current)?.current.name==='meshagent-gnome-test','service-manager systemd escaping cannot change companion identity');
i=installer({greeterChoices:[{result:{state:'declined'}}]});i.run('installService(["--__skipExit=1"])');
check(i.events.indexOf('acquire')<i.events.indexOf('greeter-offer')&&i.output.some(x=>x.includes('until the login screen restarts')),'greeter decline preserves pending-login-screen guidance after setup');
i=installer({greeterChoices:[{result:{state:'greeter-refresh-requested'}}]});i.run('installService(["--__skipExit=1"])');check(i.output.some(x=>x.includes('Login-screen refresh requested')),'greeter action reports request without claiming capture ready');
i=installer({ownershipState:'error'});i.run('installService(["--__skipExit=1"])');check(!i.events.includes('greeter-offer'),'failed companion setup cannot request greeter refresh');
console.log(passed+' focused installer ownership checks passed');
