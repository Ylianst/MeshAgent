// Focused execution of the production getXInfo function with OS-response fixtures.
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const {EventEmitter}=require('events');
const source=fs.readFileSync(require('path').join(__dirname,'../modules/monitor-info.js'),'utf8');
const start=source.indexOf('this.getXInfo = function getXInfo(');
const end=source.indexOf('\n        };',start);
assert(start>=0&&end>start);
const fn=source.slice(start+'this.getXInfo = '.length,end)+'\n        }';
function fixture({platform='linux',user='sddm',uid=964,sessionClass='greeter',type='x11',display=':0',requested=0}={}){
 const commands=[];
 const sessions={hasLoginCtl:true,gdmUid:uid,activeConsoleSession:()=>({uid,type,sessionClass,display}),getUsername:id=>id===uid?user:'root',getHomeFolder:id=>id===uid?'/var/lib/'+user:'/root',getEnvFromPid:()=>({})};
 const files={existsSync:p=>p==='/run/sddm',readdirSync:()=>['xauth_live'],statSync:()=>({uid:964})};
 const cp={execFile(){const c={stdout:new EventEmitter(),stderr:new EventEmitter(),text:''};c.stdin={write:s=>c.text+=s};c.waitExit=()=>{
  commands.push(c.text);let out='';
  if(c.text.includes('-o uid -o tty -o command')){
   if(user!=='sddm')out=requested+',tty2,/existing/auth,'+display;
  }else if(c.text.startsWith('loginctl list-sessions'))out=c.text.includes('==964')?'[{"uid":"964","SessionId":"c1","tty":""}]':'[]';
  else if(c.text.startsWith('loginctl session-status'))out='[]';
  else if(c.text.startsWith('loginctl show-session'))out='';
  else if(c.text.startsWith('ps '))out='';
  else throw Error('Unexpected command: '+c.text);
  c.stdout.emit('data',Buffer.from(out));
 };return c;}};
 const context={process:{platform},console:{info1(){}},exportEnv(){},xinfo_xdm:x=>x,require:n=>({'user-sessions':sessions,'child_process':cp,fs:files}[n])};
 return {value:vm.runInNewContext('('+fn+')',context)(requested),commands};
}
let count=0;
function check(condition){assert(condition);++count;}
let r=fixture();check(r.value.xauthority==='/run/sddm/xauth_live');check(r.value.display===':0');check(r.commands[0].includes('$1=="964"'));
r=fixture({user:'lightdm',uid:111});check(r.value.xauthority==='/existing/auth');check(r.commands[0].includes('$1=="0"'));check(r.commands[0].includes('for(arg=4;arg<=NF;++arg)'));
r=fixture({user:'gdm',uid:113});check(r.commands[0].includes('$1=="0"'));check(!r.commands[0].includes('for(arg=4;arg<=NF;++arg)'));
r=fixture({user:'labadmin',uid:1000,requested:1000,sessionClass:'user',display:':1'});check(r.value.display===':1'&&r.commands[0].includes('$1=="1000"'));
r=fixture({type:'wayland',display:''});check(r.commands[0].includes('$1=="0"'));
r=fixture({display:':0;invalid'});check(r.commands[0].includes('$1=="0"'));
r=fixture({platform:'freebsd',user:'gdm',uid:113});check(r.commands[0].includes('$1=="0"'));
console.log(count+' SDDM/displayfd and existing X11 route checks passed');
