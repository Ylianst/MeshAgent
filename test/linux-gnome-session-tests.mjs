// SPDX-License-Identifier: Apache-2.0
// Only GNOME session selection and bounded privilege-separated helper launch.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
const source=fs.readFileSync(new URL('../modules/linux-gnome-session.js',import.meta.url),'utf8');
const gjs=fs.readFileSync(new URL('../addons/gnome-shell/activate-session.js',import.meta.url),'utf8');
const signout=fs.readFileSync(new URL('../addons/gnome-shell/signout-session.js',import.meta.url),'utf8');
let passed=0;
function check(value,label){assert.ok(value,label);passed++;}
function fixture(options={}) {
 const id=options.uid??124, status=n=>`Name:\tgnome-shell\nUid:\t${n}\t${n}\t${n}\t${n}\n`;
 const files={'/proc/self/status':status(options.selfUid??0),'/proc/42/comm':'gnome-shell\n',
  '/proc/42/status':status(id),'/proc/42/stat':'42 (gnome shell) S '+Array(18).fill('0').join(' ')+' 987 0',
  '/etc/passwd':`gdm:x:${id}:124:GDM:/var/lib/gdm:/bin/false\n`,
  '/etc/X11/default-display-manager':'/usr/sbin/gdm3\n','/etc/dconf/profile/gdm':'user-db:user\nfile-db:/var/lib/gdm/greeter-defaults\n',
  '/proc/42/environ':`DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${id}/bus\0XDG_RUNTIME_DIR=/run/user/${id}\0DCONF_PROFILE=gdm\0XDG_DATA_DIRS=/usr/share/gnome:/usr/share\0LD_PRELOAD=/evil\0SECRET=never-export\0`};
 files['/proc/self/environ']=files['/proc/42/environ'];
 Object.assign(files,options.files);
 let launch=null;const launches=[];
 const ctx={Buffer,module:{exports:{}},process:{platform:options.platform||'linux'},require(name){
  if(name==='fs')return {readFileSync(p){if(!(p in files))throw Error('ENOENT');const b=Buffer.from(files[p]);
   // Model the native Agent's NUL-terminated Buffer.toString contract.
   b.toString=function(){const end=this.indexOf(0);return Buffer.prototype.toString.call(end<0?this:this.subarray(0,end));};return b;},
   readdirSync(){return ['self','42','43','not-a-pid'];},existsSync(p){return p!==options.missing&&((p in files)||['/usr/bin/timeout','/usr/sbin/runuser','/usr/bin/env','/usr/bin/gjs','/usr/bin/dbus-run-session','/usr/sbin/gdm3'].includes(p));}};
  if(name==='linux-gnome-activation-source')return gjs;
  if(name==='linux-gnome-signout-source')return signout;
  if(name==='linux-gnome-greeter-source')return 'greeter-source-fixture';
  if(name==='child_process')return {execFile(path,args,opts){launch={path,args:[...args],opts};const index=launches.length;launches.push(launch);const c=new EventEmitter();c.stdout=new EventEmitter();c.stderr=new EventEmitter();
   c.waitExit=()=>{const nss=args.includes('/usr/bin/getent');c.stdout.emit('data',Buffer.from(nss?(options.nssOutput??''):(options.outputs?.[index]??options.output??'{"state":"active","changed":false}')));c.emit('exit',nss?(options.nssExit??0):(options.exit??0));};return c;}};
  throw Error('Unexpected require '+name);
 }};
 vm.runInNewContext(source,ctx);
 return {api:ctx.module.exports,files,launch:()=>launch,launches};
}
let f=fixture(),s=f.api.sessions();
check(s.length===1&&s[0].pid==='42'&&s[0].uid===124&&s[0].start==='987','select one eligible Shell incarnation');
check(!JSON.stringify(s).includes('DBUS')&&!JSON.stringify(s).includes('gdm'),'discovery exposes no session environment');
let r=f.api.run(s[0],'inspect'),l=f.launch();
check(r.state==='active'&&r.changed===false,'parse exact helper reply');
check(l.path==='/usr/bin/timeout'&&l.args.slice(0,8).join('|')==='timeout|--kill-after=1s|8s|/usr/sbin/runuser|-u|gdm|--|/usr/bin/env','bound entire privilege-separated command without a shell');
check(l.args.includes('DCONF_PROFILE=gdm')&&l.args.includes('XDG_DATA_DIRS=/usr/share/gnome:/usr/share'),'preserve actual Shell profile');
check(!l.args.some(v=>v.includes('LD_PRELOAD')||v.includes('SECRET'))&&Object.keys(l.opts.env).sort().join(',')==='LANG,PATH','no unapproved environment reaches root launcher or target');
check(l.args[l.args.length-2]===gjs&&l.args[l.args.length-1]==='inspect','execute exact bundled helper with fixed operation');
f.api.run(s[0],'prepare');check(f.launch().args.at(-1)==='prepare','prepare uses same bounded launch');
for(const operation of ['logout','prepare;id','',null]){assert.throws(()=>f.api.run(s[0],operation));passed++;}
for(const options of [{selfUid:1000},{platform:'win32'}]){f=fixture(options);assert.throws(()=>f.api.sessions());passed++;}
for(const [label,files] of [
 ['UID mismatch',{'/proc/42/status':'Uid:\t124\t0\t124\t124\n'}],
 ['root desktop',{'/proc/42/status':'Uid:\t0\t0\t0\t0\n'}],
 ['non-Shell',{'/proc/42/comm':'other\n'}],
 ['duplicate account',{'/etc/passwd':'gdm:x:124:124:GDM:/var/lib/gdm:/bin/false\nother:x:124:124::/tmp:/bin/sh\n'}],
 ['option-like account',{'/etc/passwd':'-u:x:124:124:GDM:/var/lib/gdm:/bin/false\n'}],
 ['missing bus',{'/proc/42/environ':'XDG_RUNTIME_DIR=/run/user/124\0'}],
 ['wrong runtime',{'/proc/42/environ':'DBUS_SESSION_BUS_ADDRESS=a\0XDG_RUNTIME_DIR=/run/user/0\0'}],
 ['duplicate variable',{'/proc/42/environ':'DBUS_SESSION_BUS_ADDRESS=a\0DBUS_SESSION_BUS_ADDRESS=b\0XDG_RUNTIME_DIR=/run/user/124\0'}],
 ['control value',{'/proc/42/environ':'DBUS_SESSION_BUS_ADDRESS=a\nmalformed\0XDG_RUNTIME_DIR=/run/user/124\0'}],
 ['unterminated environment',{'/proc/42/environ':'DBUS_SESSION_BUS_ADDRESS=a\0XDG_RUNTIME_DIR=/run/user/124'}],
 ['bad stat',{'/proc/42/stat':'42 malformed'}]
]){f=fixture({files});check(f.api.sessions().length===0,label+' is ineligible');}
f=fixture();s=f.api.sessions();f.files['/proc/42/stat']=f.files['/proc/42/stat'].replace('987','988');
assert.throws(()=>f.api.run(s[0],'prepare'));check(f.launch()===null,'reused PID rejected before launch');
f=fixture();s=f.api.sessions();assert.throws(()=>f.api.run({...s[0],pid:'42/../self'},'inspect'));passed++;
f=fixture({missing:'/usr/sbin/runuser'});s=f.api.sessions();assert.throws(()=>f.api.run(s[0],'inspect'));check(f.launch()===null,'missing prerequisite does not launch fallback');
for(const options of [{exit:124},{output:'x'.repeat(32769)},{output:'not JSON'},{output:'{"state":"active"}'},{output:'{"state":"active","changed":false}\n{"state":"active","changed":false}'}]){
 f=fixture(options);s=f.api.sessions();r=f.api.run(s[0],'inspect');check(r.state==='launcher-error'&&r.changed===null,'invalid/uncertain completion is not activation success');
}
f=fixture();r=f.api.prepareCurrent();check(r.state==='current-sessions-active'&&r.sessions.length===1&&f.launch().args.at(-1)==='prepare','prepare current sessions invokes bounded preparation');
f=fixture({files:{'/proc/42/comm':'other'}});r=f.api.prepareCurrent();check(r.state==='no-running-gnome'&&f.launch()===null,'no Shell is not an activation success');
f=fixture({exit:124});r=f.api.prepareCurrent();check(r.state==='activation-pending'&&r.sessions[0].result.changed===null,'timeout remains pending without retry or sign-out');
f=fixture({missing:'/usr/sbin/runuser'});r=f.api.prepareCurrent();check(r.state==='activation-pending'&&r.sessions[0].result.state==='launcher-error','one launch failure becomes explicit session result');
f=fixture({selfUid:124});r=f.api.prepareLogin();l=f.launch();
check(r.state==='active'&&l.path==='/usr/bin/timeout'&&l.args[3]==='/usr/bin/gjs'&&l.args.at(-1)==='prepare','login startup runs bounded GJS directly as current user');
check(l.opts.env.DCONF_PROFILE==='gdm'&&l.opts.env.HOME==='/var/lib/gdm'&&!l.opts.env.LD_PRELOAD&&!l.opts.env.SECRET,'login preserves current profile with clean environment');
f=fixture();assert.throws(()=>f.api.prepareLogin());check(f.launch()===null,'login mode refuses root');
f=fixture({selfUid:124,files:{'/proc/self/environ':'XDG_RUNTIME_DIR=/run/user/124\0'}});assert.throws(()=>f.api.prepareLogin());check(f.launch()===null,'login mode refuses absent session bus');
f=fixture();r=f.api.prepareGreeter();check(r.state==='greeter-running'&&r.sessions.length===1&&f.launch()===null,'running greeter uses existing-session preparation without a second bus');
f=fixture({files:{'/proc/42/comm':'other','/usr/lib/systemd/user/gnome-session@gnome-login.target.d/gnome-login.session.conf':'[Unit]\nRequires=org.gnome.Shell@gdm.service\n'}});r=f.api.prepareGreeter();
check(r.state==='greeter-startup-ready'&&r.persisted===false&&f.launch()===null,'modern GDM startup hook uses the future transient account instead of writing the static account home');
const configured=JSON.stringify({state:'greeter-configured',configured:true,changed:true}),verified=JSON.stringify({state:'greeter-configured',configured:true,changed:false});
f=fixture({files:{'/proc/42/comm':'other'},outputs:[configured,verified]});r=f.api.prepareGreeter();
check(r.state==='greeter-prepared'&&r.persisted&&r.changed===true&&r.profile==='gdm','offline readiness requires persisted reinspection');
check(f.launches.length===2&&f.launches[0].args.at(-1)==='prepare-greeter'&&f.launches[1].args.at(-1)==='inspect-greeter','one write attempt followed by separate read-only backend');
check(f.launches[0].args.includes('DCONF_PROFILE=gdm')&&f.launches[0].args.includes('HOME=/var/lib/gdm')&&f.launches[0].args.includes('/usr/bin/dbus-run-session')&&!f.launches[0].args.some(v=>v.startsWith('DBUS_SESSION_BUS_ADDRESS=')||v.startsWith('XDG_RUNTIME_DIR=')),'offline launch uses installed account/profile with a private bus and no invented runtime');
f=fixture({files:{'/proc/42/comm':'other','/etc/passwd':'Debian-gdm:x:124:124::/var/lib/gdm3:/bin/false\n','/etc/dconf/profile/Debian-gdm':'user-db:user\n'},outputs:[configured,verified]});r=f.api.prepareGreeter();
check(r.profile==='Debian-gdm'&&f.launches[0].args.includes('DCONF_PROFILE=Debian-gdm'),'Debian profile follows installed account name');
f=fixture({missing:'/usr/sbin/gdm3'});check(f.api.prepareGreeter().state==='not-applicable'&&f.launch()===null,'no GDM means no greeter settings writes');
f=fixture({files:{'/etc/X11/default-display-manager':'/usr/sbin/lightdm\n'}});check(f.api.prepareGreeter().state==='not-applicable'&&f.launch()===null,'other selected display manager remains untouched');
for(const passwd of ['dynamic:x:124:124::/tmp:/bin/false\n','gdm:x:124:124::/tmp:/bin/false\nDebian-gdm:x:125:125::/tmp:/bin/false\n']){
 f=fixture({files:{'/etc/passwd':passwd}});check(f.api.prepareGreeter().state==='unsupported-greeter-account'&&f.launch()===null,'unknown or ambiguous account is explicit without fallback');
}
f=fixture({files:{'/proc/42/comm':'other','/etc/dconf/profile/gdm':'system-db:gdm\n'}});check(f.api.prepareGreeter().state==='unsupported-greeter-profile'&&f.launch()===null,'system-only profile is not silently replaced');
f=fixture({files:{'/proc/42/comm':'other'}});delete f.files['/etc/dconf/profile/gdm'];check(f.api.prepareGreeter().state==='unsupported-greeter-profile'&&f.launch()===null,'missing named profile is not user-profile fallback');
f=fixture({files:{'/proc/42/comm':'other'},missing:'/usr/bin/dbus-run-session'});assert.throws(()=>f.api.prepareGreeter());check(f.launch()===null,'offline prerequisite failure never launches');
f=fixture({files:{'/proc/42/comm':'other'},outputs:[configured,'{"state":"greeter-unconfigured","configured":false,"changed":false}']});r=f.api.prepareGreeter();check(r.state==='greeter-verification-failed'&&r.changed===true&&f.launches.length===2,'unpersisted setting remains failure without repeated writes');
f=fixture({files:{'/proc/42/comm':'other'},output:'{"state":"policy-blocked","changed":false}'});r=f.api.prepareGreeter();check(r.state==='policy-blocked'&&f.launches.length===1,'policy refusal is not retried');
f=fixture();s=f.api.sessions();f.api.run(s[0],'inspect-sign-out');check(f.launch().args.at(-2)==='-'&&f.launch().args.at(-1)==='inspect','missing environment session ID requires helper logind identity validation');
const desktopEnv='DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/124/bus\0XDG_RUNTIME_DIR=/run/user/124\0XDG_SESSION_ID=c7\0WAYLAND_DISPLAY=wayland-0\0DISPLAY=:0\0XAUTHORITY=/run/user/124/auth\0XDG_CURRENT_DESKTOP=ubuntu:GNOME\0';
f=fixture({files:{'/proc/42/environ':desktopEnv,'/etc/passwd':'lab:x:124:124::/home/lab:/bin/sh\n'},output:'{"state":"declined","changed":false}'});s=f.api.sessions();r=f.api.offerSignOut({sessions:[{session:s[0],result:{state:'needs-sign-in',configured:true}}]});l=f.launch();
check(r.length===1&&r[0].result.state==='declined'&&l.args[2]==='60s'&&l.args.slice(-4).join('|')===[signout,'42','c7','offer'].join('|'),'installer choice uses bounded fixed source and actual Shell/logind identifiers');
check(l.args.includes('WAYLAND_DISPLAY=wayland-0')&&l.args.includes('DISPLAY=:0')&&l.args.includes('XAUTHORITY=/run/user/124/auth')&&l.args.includes('XDG_CURRENT_DESKTOP=ubuntu:GNOME')&&Object.keys(l.opts.env).sort().join(',')==='LANG,PATH','GUI and desktop-identity variables reach only dropped-user helper');
f.api.run(s[0],'inspect-sign-out');check(f.launch().args[2]==='8s'&&f.launch().args.at(-1)==='inspect','read-only sign-out probe has short bound');
for(const result of [{state:'active',configured:true},{state:'extension-error',configured:true},{state:'needs-sign-in',configured:false},{state:'needs-sign-in',configured:true,globallyDisabled:true}]){
 f=fixture();s=f.api.sessions();check(f.api.offerSignOut({sessions:[{session:s[0],result}]}).length===0&&f.launch()===null,'no choice outside prepared next-sign-in requirement');
}
f=fixture();s=f.api.sessions();check(f.api.offerSignOut({sessions:[{session:s[0],result:{state:'needs-sign-in',configured:true}}]}).length===0&&f.launch()===null,'GDM does not receive the user sign-out dialog');
f=fixture({output:'{"state":"declined","changed":false}'});s=f.api.sessions();r=f.api.offerGreeterRefresh({sessions:[{session:s[0],result:{state:'needs-sign-in',configured:true}}]});l=f.launch();
check(r.length===1&&r[0].result.state==='declined'&&l.path==='/usr/bin/timeout'&&l.args.slice(0,4).join(',')==='timeout,--foreground,--kill-after=1s,60s','one-time greeter offer preserves controlling terminal and has an outer bound');
check(l.args.slice(-5).join(',')==='greeter-source-fixture,offer,42,124,987'&&Object.keys(l.opts.env).sort().join(',')==='LANG,PATH','root greeter helper accepts only fixed source and discovered PID UID start with clean environment');
f.api.refreshGreeter(s[0],'inspect');check(f.launch().args[3]==='12s'&&f.launch().args.at(-4)==='inspect','read-only greeter probe cannot offer consent');
f=fixture({files:{'/etc/passwd':'lab:x:124:124::/home/lab:/bin/sh\n'}});s=f.api.sessions();check(f.api.offerGreeterRefresh({sessions:[{session:s[0],result:{state:'needs-sign-in',configured:true}}]}).length===0&&f.launch()===null,'ordinary desktop is not sent to root greeter refresh');
f=fixture();s=f.api.sessions();assert.throws(()=>f.api.refreshGreeter(s[0],'force'));check(f.launch()===null,'no programmatic force/approval mode exists');
const modernRow='gdm-greeter:x:60578:120:GDM Greeter:/run/gdm/home/gdm-greeter:/usr/bin/nologin\n';
f=fixture({uid:60578,files:{'/etc/passwd':'root:x:0:0::/root:/bin/sh\n'},nssOutput:modernRow});
s=f.api.sessions();check(s.length===1&&s[0].uid===60578,'NSS-only high UID greeter is discovered');
check(f.api.prepareGreeter().state==='greeter-running','running modern greeter uses actual environment without offline profile guess');
f.api.run(s[0],'prepare');l=f.launch();
check(l.args.includes('gdm-greeter')&&l.args.includes('HOME=/run/gdm/home/gdm-greeter'),'validated NSS identity used for privilege drop');
check(f.launches.filter(x=>x.args.includes('/usr/bin/getent')).every(x=>x.path==='/usr/bin/timeout'&&x.args.join('|')==='timeout|--kill-after=1s|3s|/usr/bin/getent|passwd|60578'),'NSS lookup uses bounded fixed numeric argv');
for(const options of [{nssOutput:modernRow.replace('60578','60579')},{nssOutput:modernRow+modernRow},{nssOutput:modernRow.replace('gdm-greeter:','-u:')},{nssOutput:modernRow.replace('/run/gdm/home/gdm-greeter','relative')},{nssOutput:modernRow,nssExit:2},{nssOutput:'x'.repeat(1048577)}]){
 f=fixture({uid:60578,files:{'/etc/passwd':''},...options});check(f.api.sessions().length===0,'invalid, failed or ambiguous NSS reply is ineligible');
}
console.log(JSON.stringify({passed,scope:'GNOME session selection and bounded helper launcher'}));
