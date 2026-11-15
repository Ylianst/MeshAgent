// Focused actual Agent JS module probe. All service/fs/spawn operations mocked;
// no real unit, process or filesystem mutation occurs in these cases.
var code=0,fs=require('fs'),cp=require('child_process'),mgr=require('service-manager').manager;
var saved={exists:fs.existsSync,unlink:fs.unlinkSync,spawn:cp.execFile,get:mgr.getService,type:mgr.getServiceType,admin:mgr.isAdmin,escape:mgr.escape};
try {
 var passed=0,events=[],failure=false,admin=true;
 var binary='/fixture/meshagent',unit='meshagent'+String.fromCharCode(92)+'x2dtest',conf='/usr/lib/systemd/system/'+unit+'.service';
 function check(ok,label){if(!ok)throw new Error(label);passed++;}
 mgr.isAdmin=function(){return admin;};mgr.getServiceType=function(){return 'systemd';};mgr.escape=function(){return unit;};
 mgr.getService=function(){return {escname:unit,conf:conf,appLocation:function(){return binary;},appWorkingDirectory:function(){return '/fixture';}};};
 fs.existsSync=function(p){return p===binary||p===conf;};
 fs.unlinkSync=function(p){events.push('unlink:'+p);if(failure&&p===conf)throw new Error('injected unit removal failure');};
 cp.execFile=function(path,args,options){events.push('spawn:'+path);return {stdout:{on:function(){}},stderr:{on:function(){}},
  stdin:{write:function(s){events.push(s);}},waitExit:function(){events.push('wait');}};};
 mgr.uninstallService('meshagent-test');
 var escaped=unit.split(String.fromCharCode(92)).join(String.fromCharCode(92)+String.fromCharCode(92));
 check(events.indexOf('systemctl stop '+escaped+'.service\n')>=0,'stop exact resolved escaped unit');
 check(events.indexOf('systemctl disable '+escaped+'.service\n')>=0,'disable exact resolved escaped unit');
 check(events.indexOf('unlink:'+conf)<events.indexOf('systemctl daemon-reload\nexit\n'),'reload systemd after removing unit');
 check(events.indexOf('systemctl stop meshagent-test.service\n')<0,'raw-name unit is not stopped');
 events=[];mgr.uninstallService('meshagent-test',{skipDeleteBinary:true});
 check(events.indexOf('unlink:'+binary)<0&&events.indexOf('unlink:'+conf)>=0,'skip-binary option still removes service definition');
 events=[];failure=true;var threw=false;try{mgr.uninstallService('meshagent-test');}catch(e){threw=String(e).indexOf('injected unit removal failure')>=0;}
 check(threw,'actual removal failure propagates to installer ownership hook');
 check(events.indexOf('systemctl daemon-reload\nexit\n')<0,'failed removal never reports completed reload path');
 events=[];admin=false;threw=false;try{mgr.uninstallService('meshagent-test');}catch(e){threw=true;}
 check(threw&&events.length===0,'admin guard remains before mutation');
 console.log(JSON.stringify({passed:passed,scope:'actual Agent systemd uninstall method with mocked service/filesystem/spawn operations'}));
}catch(e){console.log(JSON.stringify({error:String(e)}));code=1;}
finally{fs.existsSync=saved.exists;fs.unlinkSync=saved.unlink;cp.execFile=saved.spawn;mgr.getService=saved.get;mgr.getServiceType=saved.type;mgr.isAdmin=saved.admin;mgr.escape=saved.escape;}
process.exit(code);
