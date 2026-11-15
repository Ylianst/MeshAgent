// SPDX-License-Identifier: Apache-2.0
// Only the fixed-purpose GJS session activation helper.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const source=fs.readFileSync(new URL('../addons/gnome-shell/activate-session.js',import.meta.url),'utf8');
const UUID='meshagent-console@meshcentral.com';let passed=0;
function check(ok,label){assert.ok(ok,label);passed++;}
function run(options={}){
 let enabled=options.enabled||['other@example'],disabled=options.disabled||[],pending={},result;
 let resident=options.resident||{},writes=0,enables=0,reverted=false,sleeps=0,apiCalls=0;
 class Variant{constructor(_,v){this.value=v;}deep_unpack(){return this.value;}}
 const settings={get_strv(k){return [...(k==='enabled-extensions'?enabled:disabled)];},get_boolean(){return !!options.globallyDisabled;},
  is_writable(k){return !(options.locked||[]).includes(k);},delay(){pending={};},
  set_strv(k,value){writes++;if(options.setFails)return false;pending[k]=[...value];return true;},
  revert(){pending={};reverted=true;},apply(){if(pending['enabled-extensions'])enabled=pending['enabled-extensions'];if(pending['disabled-extensions'])disabled=pending['disabled-extensions'];}};
 const Gio={FileType:{DIRECTORY:1,REGULAR:2},FileQueryInfoFlags:{NOFOLLOW_SYMLINKS:1},BusType:{SESSION:1},DBusCallFlags:{NO_AUTO_START:1},
  File:{new_for_path(path){return{query_info(){return{get_file_type(){return path.endsWith('metadata.json')?2:1;},get_attribute_uint32(name){return name==='unix::uid'?(options.unsafe?1000:0):name==='unix::mode'?0o755:1;}};},
   load_contents(){return[true,Buffer.from(JSON.stringify({uuid:options.badUuid?'other':UUID,version:options.generation||1}))];}};}},
  SettingsSchemaSource:{get_default(){return{lookup(){return options.noSchema?null:{has_key(){return true;}};}};}},
  Settings:function(){return settings;},
  bus_get_sync(){return{call_sync(destination,path,iface,method,____,_____,flags,timeout){
   apiCalls++;
   assert.equal(destination,'org.gnome.Shell');assert.equal(path,'/org/gnome/Shell');assert.equal(iface,'org.gnome.Shell.Extensions');
   assert.equal(flags,1);assert.equal(timeout,2500);
   if(options.apiThrows)throw Error('extension API unavailable');
   if(method==='EnableExtension'){enables++;if(options.immediate)resident={version:options.generation||1,state:1};return new Variant('(b)',[!!options.immediate]);}
   if(options.activating&&enables){resident=sleeps>0?{version:1,state:1}:{version:1,state:8};}
   return new Variant('(a{sv})',[resident]);
  }};}};
 Gio.Settings.sync=()=>{if(options.syncThrows)throw Error('sync failure');};
 const ctx={imports:{gi:{Gio,GLib:{Variant,getenv(){return options.noBus?null:'unix:path=/run/user/1000/bus';},usleep(){sleeps++;}}},byteArray:{toString(b){return Buffer.from(b).toString();}}},ARGV:options.args||[options.mode||'prepare'],print(v){assert.equal(result,undefined);result=JSON.parse(v);}};
 vm.runInNewContext(source,ctx);
 return{result,enabled,disabled,writes,enables,reverted,sleeps,apiCalls};
}
let t=run({mode:'inspect',resident:{version:1,state:1},enabled:[UUID]});
check(t.result.state==='active'&&!t.result.changed&&!t.writes&&!t.enables,'inspection of active extension is read-only');
t=run({mode:'inspect'});check(t.result.state==='needs-sign-in'&&!t.writes&&!t.enables,'unknown UUID inspection cannot mutate or activate');
t=run({disabled:[UUID,'disabled@example'],immediate:true});
check(t.result.state==='active'&&t.result.changed&&t.result.configured,'try immediate activation after preparation');
check(t.enabled.join(',')==='other@example,'+UUID&&t.disabled.join(',')==='disabled@example','preserve every unrelated extension setting');
t=run();check(t.result.state==='needs-sign-in'&&t.result.configured&&t.enables===1,'unsupported first-load API leaves a configured next-sign-in state');
t=run({resident:{version:1,state:1},enabled:[UUID]});check(t.result.state==='active'&&!t.result.changed&&!t.writes&&!t.enables,'already active path is neutral');
t=run({generation:2,resident:{version:1,state:1},enabled:[UUID]});check(t.result.state==='needs-sign-in'&&!t.result.changed,'cached old generation is not reported active');
t=run({resident:{version:2,state:1}});check(t.result.state==='version-conflict'&&!t.writes&&!t.enables,'do not replace a newer resident generation');
t=run({globallyDisabled:true});check(t.result.state==='policy-blocked'&&!t.writes&&!t.enables,'never clear global extension-disable policy');
t=run({locked:['enabled-extensions']});check(t.result.state==='policy-blocked'&&!t.writes,'locked required setting is preserved');
t=run({locked:['enabled-extensions'],enabled:[UUID],resident:{version:1,state:1}});check(t.result.state==='active'&&!t.writes,'read-only already-configured setting needs no write');
t=run({setFails:true});check(t.result.state==='error'&&t.reverted&&!t.result.changed&&t.enabled.join(',')==='other@example','failed delayed write is reverted before apply');
t=run({syncThrows:true});check(t.result.state==='error'&&t.result.changed===null,'uncertain applied settings are reported explicitly');
t=run({resident:{version:1,state:3}});check(t.result.state==='extension-error'&&!t.writes&&!t.enables,'extension error is not mislabeled as a login requirement');
t=run({noSchema:true});check(t.result.state==='unsupported-settings'&&!t.writes,'missing schema is handled without mutation');
t=run({noBus:true});check(t.result.state==='no-session-bus'&&!t.writes&&!t.enables,'do not autolaunch a missing session bus');
t=run({unsafe:true});check(t.result.state==='error'&&t.result.stage==='installed-metadata'&&!t.writes,'reject untrusted installed metadata');
t=run({badUuid:true});check(t.result.state==='error'&&!t.writes,'fixed UUID cannot be redirected');
t=run({args:['invalid']});check(t.result.state==='error'&&t.result.stage==='arguments'&&!t.writes,'reject arbitrary operation input');
t=run({activating:true});check(t.result.state==='active'&&t.sleeps===1,'bounded activation polling can observe completion');
t=run({mode:'inspect',apiThrows:true});check(t.result.state==='extension-api-unavailable'&&!t.writes,'API failure is not a sign-in requirement');
t=run({generation:2,resident:{version:1,state:3},enabled:[UUID]});check(t.result.state==='needs-sign-in','updated files can require reload of an older errored resident');
t=run({mode:'prepare-greeter',disabled:[UUID,'keep-disabled'],apiThrows:true});
check(t.result.state==='greeter-configured'&&t.result.changed&&t.enabled.join(',')==='other@example,'+UUID&&t.disabled.join(',')==='keep-disabled'&&!t.apiCalls,'offline preparation preserves other settings and never contacts Shell');
t=run({mode:'inspect-greeter'});check(t.result.state==='greeter-unconfigured'&&!t.writes&&!t.apiCalls,'offline inspection cannot write or contact Shell');
t=run({mode:'inspect-greeter',enabled:[UUID]});check(t.result.state==='greeter-configured'&&!t.writes&&!t.apiCalls,'offline inspection verifies configured settings without claiming active Shell');
t=run({mode:'prepare-greeter',enabled:[UUID]});check(t.result.state==='greeter-configured'&&!t.result.changed&&!t.writes&&!t.apiCalls,'already configured offline profile is neutral');
t=run({mode:'prepare-greeter',globallyDisabled:true});check(t.result.state==='policy-blocked'&&!t.writes&&!t.apiCalls,'offline path respects global extension policy');
t=run({mode:'prepare-greeter',locked:['enabled-extensions']});check(t.result.state==='policy-blocked'&&!t.writes&&!t.apiCalls,'offline path respects locked keys');
t=run({mode:'prepare-greeter',syncThrows:true});check(t.result.state==='error'&&t.result.changed===null&&!t.apiCalls,'offline uncertain apply is not readiness');
console.log(passed+' focused GNOME activation helper checks passed');
