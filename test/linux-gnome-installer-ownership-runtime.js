// Private mount fixture only. GNOME presence is simulated; native file operations are real.
var code=0,fs=require('fs'),exists=fs.existsSync,session=require('linux-gnome-session'),prepare=session.prepareCurrent,prepareGreeter=session.prepareGreeter;
var startup=require('linux-gnome-startup'),startupInstall=startup.install,startupRemove=startup.remove;
try {
 session.prepareCurrent=function(){return {state:'no-running-gnome',sessions:[],simulated:true};};
 session.prepareGreeter=function(){return {state:'not-applicable',simulated:true};};
 startup.install=startup.remove=function(){return {status:1,changed:false};};
 fs.existsSync=function(path){return path==='/usr/bin/gnome-shell'||exists.call(fs,path);};
 var companion=require('linux-gnome-companion'),passed=0;
 var base='/usr/share/gnome-shell/extensions/meshagent-console@meshcentral.com';
 var a={name:'meshagent',path:'/lab/first/meshagent'},b={name:'other agent',path:'/lab/other/meshagent'},moved={name:'meshagent',path:'/lab/new/meshagent'};
 function check(ok,label){if(!ok)throw new Error(label);passed++;}
 function owners(){return fs.readFileSync(base+'/meshagent-owned.txt').toString().split('\n').filter(function(s){return /^[a-f0-9]{64}$/.test(s);}).length;}
 var r=companion.install(a);check(r.state==='files-ready'&&r.activation==='pending','install files without claiming activation');
 check(owners()===1,'real native first owner');
 r=companion.install(a);check(r.state==='files-ready'&&r.changed===false&&owners()===1,'idempotent native install');
 r=companion.install(b);check(r.state==='files-ready'&&owners()===2,'second native service owner');
 r=companion.uninstall(a);check(r.state==='files-retained'&&owners()===1,'uninstall preserves other service');
 r=companion.uninstall(b);check(r.state==='files-removed'&&!exists.call(fs,base),'last uninstall removes managed files');
 r=companion.install(a);check(r.state==='files-ready','start actual path transfer');
 r=companion.install(moved,a);check(r.state==='files-ready'&&owners()===1,'new path transfers old ownership');
 r=companion.uninstall(a);check(r.state==='files-retained'&&owners()===1,'old path no longer owns shared files');
 r=companion.uninstall(moved);check(r.state==='files-removed','new path owns final removal');
 r=companion.install({name:'invalid\nservice',path:'/lab/agent'});check(r.state==='error'&&r.stage==='identity'&&!exists.call(fs,base),'invalid native runtime identity has no mutation');
 var assets=require('linux-gnome-companion-assets'),saved=assets.files['extension.js'].sha256;
 assets.files['extension.js'].sha256=Array(65).join('0');
 r=companion.install(a);assets.files['extension.js'].sha256=saved;
 check(r.state==='error'&&r.stage==='payload'&&!exists.call(fs,base),'native runtime verifies payload before publication');
 check(typeof require('agent-installer').fullInstallEx==='function','compiled ordinary installer module loads');
 console.log(JSON.stringify({passed:passed,scope:'installer ownership module with actual native store; GNOME detection simulated; no services or activation'}));
}catch(e){console.log(JSON.stringify({error:String(e)}));code=1;}
finally{fs.existsSync=exists;session.prepareCurrent=prepare;session.prepareGreeter=prepareGreeter;startup.install=startupInstall;startup.remove=startupRemove;}
process.exit(code);
