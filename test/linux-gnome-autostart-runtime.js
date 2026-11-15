// Only new autostart native bindings and their actual Agent JS startup module.
// /etc is a private fixture mount; no service or GNOME session is touched.
var code=0;
try {
 var fs=require('fs'),store=require('_gnome-companion-store'),startup=require('linux-gnome-startup'),passed=0;
 var a=Array(65).join('a'),b=Array(65).join('b'),base='/etc/xdg/autostart/';
 var file=base+'meshagent-gnome-'+a+'.desktop',other=base+'meshagent-gnome-'+b+'.desktop';
 function check(value,label){if(!value)throw new Error(label);passed++;}
 var r=startup.install(a,'/lab/agent with space');check(r.status===1&&r.changed===true,'actual startup binding install');
 var expected=fs.readFileSync(file);check(expected.toString().indexOf('Exec=/usr/bin/timeout --kill-after=1s 8s /usr/bin/gjs -c ')>=0,'actual native buffer and stock interpreter entry');
 r=startup.install(a,'/lab/agent with space');check(r.status===1&&r.changed===false,'actual idempotent entry');
 r=startup.install(a,'/lab/changed');check(r.status===0&&r.changed===false,'actual binding refuses changed entry');
 r=store.autostartRemove(a,Buffer.from('edited'));check(r.status===0&&r.changed===false&&fs.existsSync(file),'actual expected-byte removal guard');
 r=startup.install(b,'/lab/other');check(r.status===1&&r.changed===true,'actual independent entry');
 r=startup.remove(a,'/lab/agent with space');check(r.status===1&&r.changed===true&&!fs.existsSync(file)&&fs.existsSync(other),'actual remove preserves other service');
 r=startup.remove(a,'/lab/agent with space');check(r.status===1&&r.changed===false,'actual absent entry removal');
 r=store.autostartInstall(Array(65).join('A'),expected);check(r.status===0&&r.changed===false,'actual owner validation');
 var rejected=0;try{store.autostartInstall('bad',expected);}catch(e){rejected++;}try{store.autostartInstall(a,'not buffer');}catch(e){rejected++;}
 check(rejected===2,'actual binding argument types and lengths');
 r=startup.remove(b,'/lab/other');check(r.status===1&&r.changed===true&&fs.readdirSync(base).length===0,'actual final entry cleanup');
 var legacy=Buffer.from('IyBNZXNoQWdlbnQgR05PTUUgYXV0b3N0YXJ0IDEKW0Rlc2t0b3AgRW50cnldClR5cGU9QXBwbGljYXRpb24KTmFtZT1NZXNoQWdlbnQgR05PTUUgYWN0aXZhdGlvbgpFeGVjPS91c3IvYmluL2VudiAtLSAiL2xhYi9hZ2VudCB3aXRoIHNwYWNlIiAtYjY0ZXhlYyBkbUZ5SUdOdlpHVTlNVHQwY25sN2RtRnlJSEk5Y21WeGRXbHlaU2duYkdsdWRYZ3RaMjV2YldVdGMyVnpjMmx2YmljcExuQnlaWEJoY21WTWIyZHBiaWdwTzJsbUtISXVjM1JoZEdVOVBUMG5ZV04wYVhabEp5bDdZMjlrWlQwd08zMWxiSE5sZTJOdmJuTnZiR1V1Ykc5bktDZEhUazlOUlNCeVpXMXZkR1VnWTI5dWRISnZiQ0JoWTNScGRtRjBhVzl1T2lBbkszSXVjM1JoZEdVcE8zMTlZMkYwWTJnb1pTbDdZMjl1YzI5c1pTNXNiMmNvSjBkT1QwMUZJSEpsYlc5MFpTQmpiMjUwY205c0lHRmpkR2wyWVhScGIyNGdabUZwYkdWa0p5azdmWEJ5YjJObGMzTXVaWGhwZENoamIyUmxLVHM9Ck9ubHlTaG93SW49R05PTUU7Ck5vRGlzcGxheT10cnVlClRlcm1pbmFsPWZhbHNlClgtR05PTUUtQXV0b3N0YXJ0LWVuYWJsZWQ9dHJ1ZQo=','base64');
 r=store.autostartInstall(a,legacy);check(r.status===1&&r.changed===true,'exact legacy entry fixture');
 r=startup.install(a,'/lab/agent with space');check(r.status===1&&r.changed===true&&fs.readFileSync(file).toString()===expected.toString(),'actual native legacy migration');
 fs.writeFileSync(file,Buffer.from(expected.toString()+'# edited\n'));
 r=startup.install(a,'/lab/agent with space');check(r.status===0&&r.changed===false,'actual migration preserves edited entry');
 r=startup.remove(a,'/lab/agent with space');check(r.status===0&&fs.existsSync(file),'actual uninstall preserves edited entry');
 fs.writeFileSync(file,expected);r=startup.remove(a,'/lab/agent with space');check(r.status===1&&r.changed===true&&fs.readdirSync(base).length===0,'actual migrated owner cleanup');
 console.log(JSON.stringify({passed:passed,scope:'native autostart binding and actual Agent startup module; private etc mount'}));
}catch(e){console.log(JSON.stringify({error:String(e)}));code=1;}process.exit(code);
