// SPDX-License-Identifier: Apache-2.0
// Only root greeter identity, one-time terminal choice and scoped refresh.
import fs from 'node:fs';import vm from 'node:vm';import assert from 'node:assert/strict';
const source=fs.readFileSync(new URL('../addons/gnome-shell/refresh-greeter.js',import.meta.url),'utf8');
let passed=0;function check(ok,label){assert.ok(ok,label);passed++;}
function run(options={}) {
 let result,choices=0,inspections=0,terminations=0,chosen=false,queued=null,timer=null,closed=false;
 class Variant{constructor(_,v){this.value=v;}deep_unpack(){return this.value;}}
 const session={Id:'c7',User:[113,'/user'],Class:'greeter',Type:'wayland',Seat:['seat0','/seat'],Active:true,State:'active',Remote:false};
 const files={'/etc/passwd':'Debian-gdm:x:113:113:GDM:/var/lib/gdm3:/bin/false\n',
  '/proc/42/comm':'gnome-shell\n','/proc/42/status':'Uid:\t113\t113\t113\t113\n',
  '/proc/42/environ':'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/113/bus\0XDG_RUNTIME_DIR=/run/user/113\0DCONF_PROFILE=Debian-gdm\0SECRET=never-forward\0'};
 Object.assign(files,options.files);
 function load(p){if(p==='/proc/42/stat')return '42 (gnome-shell) S '+Array(18).fill('0').join(' ')+' '+(chosen&&options.pidChanged?'988':'987')+' 0';
  if(p==='/proc/43/comm')return 'gnome-shell\n';if(p==='/proc/43/status')return files['/proc/42/status'];if(!(p in files))throw Error('ENOENT');return files[p];}
 const bus={call_sync(dest,path,iface,method,args,_,flags,timeout){
  assert.equal(flags,1);assert.equal(timeout,2500);
  if(method===options.failMethod)throw Error('injected bus failure');
  if(method==='GetNameOwner')return new Variant('',[':1.1']);
  if(method==='GetConnectionUnixUser')return new Variant('',[options.untrustedLogind?1000:0]);
  assert.equal(dest,':1.1');
  if(method==='GetAll'){
   if(args.value[0]==='org.freedesktop.login1.Seat')return new Variant('',[{ActiveSession:[chosen&&options.sessionChanged?'c8':'c7',chosen&&options.sessionChanged?'/org/freedesktop/login1/session/c8':'/org/freedesktop/login1/session/c7']}]);
   if(path==='/other')return new Variant('',[{Class:'user',Type:'wayland',Active:false,State:'online'}]);
   return new Variant('',[{...session,...options.properties,...(chosen&&options.userAfter?{Class:'user',User:[1000,'/user']}:{})}]);
  }
  if(method==='ListSessions'){
   const rows=[['c7',113,'Debian-gdm','seat0','/org/freedesktop/login1/session/c7']];
   if(options.otherUser||(chosen&&options.otherUserAfter))rows.push(['c9',1000,'lab','seat0','/other']);
   if(options.otherSeat)rows.push(['c9',1000,'lab','seat1','/other']);
   return new Variant('',[options.badInventory?null:rows]);
  }
  if(method==='Terminate'){assert.equal(path,'/org/freedesktop/login1/session/c7');assert.equal(iface,'org.freedesktop.login1.Session');assert.equal(chosen,true);terminations++;return new Variant('',[]);}
  throw Error('Unexpected method '+method);
 }};
 const Gio={Credentials:class{get_unix_user(){return options.nonroot?1000:0;}},bus_get_sync(){return bus;},BusType:{SYSTEM:1},DBusCallFlags:{NO_AUTO_START:1},FileQueryInfoFlags:{NOFOLLOW_SYMLINKS:1},
 File:{new_for_path(p){return{load_contents(){return [true,Buffer.from(load(p))];},enumerate_children(){let names=options.duplicate?['42','43']:['42'],index=0;return{next_file(){const name=names[index++];return name?{get_name(){return name;}}:null;},close(){}};},
  open_readwrite(){choices++;if(options.noTty)throw Error('ENXIO');return{get_input_stream(){return {};},get_output_stream(){return{write_all(data){assert.ok(Buffer.from(data).toString().includes('Type RESTART'));},flush(){}};},close(){closed=true;}};}};}},
 SubprocessFlags:{STDOUT_PIPE:1,STDERR_SILENCE:2},Subprocess:{new(args){if(args[0]==='/usr/bin/timeout'){assert.equal(args.join('|'),'/usr/bin/timeout|--kill-after=1s|3s|/usr/bin/getent|passwd|113');return{communicate_utf8(){return[true,options.nssOutput??''];},get_successful(){return options.nssExit!==1;}};}inspections++;
  assert.equal(args[0],'/usr/sbin/runuser');assert.ok(args.includes('HOME='+(options.nssOutput?'/run/gdm/home/gdm-greeter':'/var/lib/gdm3')));assert.ok(args.includes('DCONF_PROFILE=Debian-gdm'));
  assert.equal(args.at(-1),'inspect');assert.ok(args.at(-2).includes('GetConnectionUnixProcessID'));assert.ok(args.at(-2).endsWith('activation-fixture'));assert.ok(!args.some(a=>a.startsWith('SECRET=')));
  return{communicate_utf8(){return[true,options.badReply?'bad JSON':JSON.stringify(options.inspectResult||(chosen&&options.activatedAfter?{state:'active'}:{state:'needs-sign-in',configured:true,changed:false}))];},get_if_exited(){return true;},get_exit_status(){return options.childFailure?1:0;}};
 }},Cancellable:class{cancel(){}},DataInputStream:class{read_line_async(_,__,callback){queued=()=>{chosen=true;callback(this,{});};}read_line_finish_utf8(){return[options.answer===undefined?'':options.answer,0];}}};
 const GLib={Variant,PRIORITY_DEFAULT:0,SOURCE_REMOVE:false,MainLoop:class{run(){if(options.timeout){timer();}else{queued();}}quit(){}},timeout_add_seconds(_,seconds,callback){assert.equal(seconds,45);timer=callback;return 1;},source_remove(){}};
 vm.runInNewContext(source,{ARGV:options.args||[options.inspect?'inspect':'offer','42','113','987'],MESH_ACTIVATION_SOURCE:'activation-fixture',imports:{gi:{Gio,GLib},byteArray:{toString(b){return Buffer.from(b).toString();},fromString(s){return Buffer.from(s);}}},print(s){assert.equal(result,undefined);result=JSON.parse(s);}});
 return {result,choices,inspections,terminations,closed};
}
let t=run();check(t.result.state==='declined'&&t.choices===1&&!t.terminations&&t.closed,'Enter defaults to keeping greeter: '+JSON.stringify(t));
t=run({answer:'RESTART'});check(t.result.state==='greeter-refresh-requested'&&t.terminations===1&&t.inspections===2,'explicit terminal approval refreshes only verified greeter once');
t=run({inspect:true});check(t.result.state==='greeter-refresh-available'&&!t.choices&&!t.terminations,'read-only probe never prompts or refreshes');
for(const answer of ['yes','restart','RESTART extra',null]){t=run({answer});check(t.result.state==='declined'&&!t.terminations,'only exact explicit approval is accepted');}
t=run({timeout:true});check(t.result.state==='declined'&&!t.terminations,'terminal timeout is not approval');
t=run({noTty:true});check(t.result.state==='deferred'&&!t.terminations,'noninteractive installation defers');
for(const properties of [{Class:'user'},{Type:'x11'},{User:[1000,'/other']},{Seat:['seat1','/seat']},{Active:false},{State:'closing'},{Remote:true},{Id:'c8'}]){
 t=run({properties,answer:'RESTART'});check(t.result.state==='deferred'&&!t.choices&&!t.terminations,'ineligible logind target cannot prompt or refresh');
}
for(const options of [{nonroot:true},{untrustedLogind:true},{duplicate:true},{otherUser:true},{badInventory:true},{failMethod:'GetAll'},{childFailure:true},{badReply:true},
 {files:{'/etc/passwd':'lab:x:113:113::/tmp:/bin/false\n'}},{files:{'/proc/42/comm':'other'}},{files:{'/proc/42/status':'Uid:\t113\t0\t113\t113\n'}},{files:{'/proc/42/environ':'XDG_RUNTIME_DIR=/run/user/113\0'}}]){
 t=run({...options,answer:'RESTART'});check(t.result.state==='deferred'&&!t.choices&&!t.terminations,'failed identity/dependencies never acquire consent');
}
for(const inspectResult of [{state:'policy-blocked',configured:true},{state:'needs-sign-in',configured:false},{state:'extension-api-unavailable',configured:true}]){
 t=run({inspectResult,answer:'RESTART'});check(t.result.state==='deferred'&&!t.choices&&!t.terminations,'unprepared greeter is not restarted');
}
t=run({inspectResult:{state:'active'}});check(t.result.state==='not-needed'&&!t.choices&&!t.terminations,'active companion does not trigger refresh');
for(const options of [{pidChanged:true},{sessionChanged:true},{userAfter:true},{otherUserAfter:true}]){
 t=run({...options,answer:'RESTART'});check(t.result.state==='deferred'&&t.choices===1&&!t.terminations,'post-choice identity changes cancel refresh');
}
t=run({activatedAfter:true,answer:'RESTART'});check(t.result.state==='not-needed'&&!t.terminations,'activation while choosing avoids unnecessary refresh');
t=run({otherSeat:true,inspect:true});check(t.result.state==='greeter-refresh-available'&&!t.terminations,'other seat desktop is outside scoped target');
for(const args of [['force','42','113','987'],['offer','42;id','113','987'],['offer','42','0','987']]){t=run({args});check(t.result.state==='deferred'&&!t.choices&&!t.terminations,'invalid target rejected before consent');}
const modern='gdm-greeter:x:113:120:GDM:/run/gdm/home/gdm-greeter:/bin/false\n';
t=run({inspect:true,files:{'/etc/passwd':''},nssOutput:modern});check(t.result.state==='greeter-refresh-available'&&!t.terminations,'NSS greeter retains read-only consent and logind guards');
for(const o of [{nssOutput:modern+modern},{nssOutput:modern,nssExit:1},{nssOutput:modern.replace(':113:',':114:')}]){t=run({inspect:true,files:{'/etc/passwd':''},...o});check(t.result.state==='deferred'&&!t.terminations,'invalid NSS identity cannot refresh');}
console.log(JSON.stringify({passed,scope:'GNOME greeter refresh identity and terminal approval'}));
