// SPDX-License-Identifier: Apache-2.0
// Installer-only sign-out choice: identity, consent, policy and ordinary logout.
import fs from 'node:fs';import vm from 'node:vm';import assert from 'node:assert/strict';
const source=fs.readFileSync(new URL('../addons/gnome-shell/signout-session.js',import.meta.url),'utf8');
const UUID='meshagent-console@meshcentral.com';let passed=0;
function check(ok,label){assert.ok(ok,label);passed++;}
function run(options={}){
 let result,dialogs=0,logouts=0,queries=0;
 class Variant{constructor(_,v){this.value=v;}deep_unpack(){return this.value;}}
 const base={Id:'c7',User:[1000,'/user'],Seat:['seat0','/seat'],Desktop:'GNOME',Class:'user',Type:'wayland',State:'active',Active:true,Remote:false,LockedHint:false};
 const bus={call_sync(dest,path,iface,method,args,_,flags,timeout){
  queries++;assert.equal(flags,1);assert.equal(timeout,2500);
  const after=dialogs>0;
  if(method===options.failMethod)throw Error('injected API failure');
  if(method==='GetNameOwner')return new Variant('',[args.value[0]==='org.gnome.Shell'?(after&&options.shellChanged?':1.4':':1.2'):(after&&options.managerChanged?':1.5':':1.3')]);
  if(method==='GetConnectionUnixProcessID')return new Variant('',[options.wrongPid?43:42]);
  if(method==='GetConnectionUnixUser')return new Variant('',[options.wrongManagerUser?0:1000]);
  if(method==='GetAll'){
   if(args.value[0]==='org.freedesktop.login1.Seat')return new Variant('',[{ActiveSession:[after&&options.sessionChanged?'c8':'c7','/org/freedesktop/login1/session/c7']}]);
   return new Variant('',[{...base,...options.properties,...(after&&options.lockedAfter?{LockedHint:true}:{})}]);
  }
  if(method==='GetExtensionInfo'){assert.equal(dest,':1.2');return new Variant('',[after&&options.activatedAfter?{version:1,state:1}:options.resident||{}]);}
  if(method==='Logout'){
   assert.equal(dest,':1.3');assert.equal(path,'/org/gnome/SessionManager');assert.equal(iface,'org.gnome.SessionManager');assert.equal(JSON.stringify(args.value),'[1]');logouts++;return new Variant('',[]);
  }
  throw Error('Unexpected method '+method);
 }};
 const Gio={Credentials:class{get_unix_user(){return options.root?0:1000;}},BusType:{SESSION:1,SYSTEM:2},DBusCallFlags:{NO_AUTO_START:1},
 FileType:{DIRECTORY:1,REGULAR:2},FileQueryInfoFlags:{NOFOLLOW_SYMLINKS:1},
 File:{new_for_path(path){return{query_info(){return{get_file_type(){return path.endsWith('metadata.json')?2:1;},get_attribute_uint32(k){return k==='unix::uid'?(options.unsafe?1000:0):k==='unix::mode'?0o755:1;}};},load_contents(){return[true,Buffer.from(JSON.stringify({uuid:UUID,version:options.generation||1}))];}};}},
 Settings:class{get_strv(k){return k==='enabled-extensions'?(options.unconfigured?[]:[UUID]):options.disabled?[UUID]:[];}get_boolean(){return !!options.policy;}},
 bus_get_sync(){return bus;},SubprocessFlags:{STDOUT_SILENCE:1,STDERR_SILENCE:2},
 Subprocess:{new(args){dialogs++;assert.equal(args[0],'/usr/bin/zenity');assert.ok(args.includes('--default-cancel'));assert.ok(args.includes('--timeout=45'));assert.ok(args.includes('--cancel-label=Later'));return{wait(){},get_if_exited(){return !options.killed;},get_exit_status(){return options.accept?0:1;}};}}};
 const GLib={Variant,getenv(k){return k==='XDG_CURRENT_DESKTOP'?options.shellDesktop:(options.noBus?null:'unix:path=/run/user/1000/bus');},file_test(){return !options.noDialog;},FileTest:{IS_EXECUTABLE:1}};
 vm.runInNewContext(source,{ARGV:options.args||['42','c7',options.inspect?'inspect':'offer'],imports:{gi:{Gio,GLib},byteArray:{toString(b){return Buffer.from(b).toString();}}},print(s){assert.equal(result,undefined);result=JSON.parse(s);}});
 return {result,dialogs,logouts,queries};
}
let t=run();check(t.result.state==='declined'&&t.dialogs===1&&!t.logouts,'default/cancel keeps session open');
t=run({accept:true});check(t.result.state==='sign-out-requested'&&t.dialogs===1&&t.logouts===1,'explicit accept requests ordinary GNOME logout once');
t=run({inspect:true});check(t.result.state==='sign-out-available'&&!t.dialogs&&!t.logouts,'read-only eligibility probe cannot prompt or logout');
for(const options of [{resident:{version:1,state:1}},{resident:{version:2,state:1}},{resident:{version:1,state:3}},{unconfigured:true},{disabled:true},{policy:true}]){
 t=run({...options,accept:true});check(t.result.state==='not-needed'&&!t.dialogs&&!t.logouts,'no prompt for active/error/newer/unprepared/policy-blocked companion');
}
t=run({generation:2,resident:{version:1,state:3}});check(t.result.state==='declined'&&t.dialogs===1&&!t.logouts,'old errored generation can need next sign-in');
for(const properties of [{Class:'greeter'},{Type:'x11'},{User:[1001,'/other']},{Remote:true},{LockedHint:true},{Active:false},{State:'online'},{Seat:['seat1','/seat']},{Id:'c8'},{Desktop:'KDE'},{Desktop:''}]){
 t=run({properties,accept:true});check(t.result.state==='deferred'&&!t.dialogs&&!t.logouts,'ineligible logind identity never prompts or signs out');
}
for(const options of [{root:true},{noBus:true},{wrongPid:true},{wrongManagerUser:true},{unsafe:true},{noDialog:true},{failMethod:'GetNameOwner'},{failMethod:'GetAll'},{failMethod:'GetExtensionInfo'}]){
 t=run({...options,accept:true});check(t.result.state==='deferred'&&!t.dialogs&&!t.logouts,'missing prerequisites/identity/API leave session untouched');
}
for(const options of [{shellChanged:true},{managerChanged:true},{sessionChanged:true},{lockedAfter:true}]){
 t=run({...options,accept:true});check(t.result.state==='deferred'&&t.dialogs===1&&!t.logouts,'revalidate session after consent');
}
t=run({activatedAfter:true,accept:true});check(t.result.state==='not-needed'&&!t.logouts,'activation completed while choosing avoids unnecessary logout');
t=run({killed:true,accept:true});check(t.result.state==='declined'&&!t.logouts,'killed/timed-out dialog is never consent');
for(const args of [['42','c7','force'],['42;id','c7','offer'],['42','../c7','offer'],['42','c7','offer','extra']]){
 t=run({args});check(t.result.state==='deferred'&&!t.dialogs&&!t.logouts&&!t.queries,'reject invalid target before bus access');
}
t=run({args:['42','-','inspect']});check(t.result.state==='sign-out-available'&&!t.dialogs&&!t.logouts,'missing environment ID uses verified active GNOME seat identity');
t=run({properties:{Desktop:'ubuntu:GNOME'},accept:true});check(t.result.state==='sign-out-requested'&&t.logouts===1,'qualified Ubuntu GNOME desktop identity is accepted');
t=run({properties:{Desktop:''},shellDesktop:'ubuntu:GNOME',inspect:true});check(t.result.state==='sign-out-available'&&!t.dialogs&&!t.logouts,'blank logind Desktop uses verified Shell desktop identity');
t=run({properties:{Desktop:'KDE'},shellDesktop:'ubuntu:GNOME',accept:true});check(t.result.state==='deferred'&&!t.dialogs&&!t.logouts,'conflicting logind desktop is not overridden by Shell environment');
console.log(JSON.stringify({passed,scope:'GNOME installer sign-out consent and session identity'}));
