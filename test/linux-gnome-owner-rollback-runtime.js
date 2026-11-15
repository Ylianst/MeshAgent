// Private mount fixture only. No services or GNOME session are used.
var code=0;
try {
 var store=require('_gnome-companion-store'), assets=require('linux-gnome-companion-assets');
 var fs=require('fs'), passed=0;
 function check(ok,label){if(!ok)throw new Error(label);passed++;}
 var files=['metadata.json','protocol.js','extension.js'].map(function(n){return Buffer.from(assets.files[n].data,'base64');});
 var ids=[Array(65).join('a'),Array(65).join('b'),Array(65).join('c')], r;
 r=store.acquire(ids[0],1,files[0],files[1],files[2]);check(r.status===1,'first owner');
 r=store.acquire(ids[1],1,files[0],files[1],files[2]);check(r.status===1&&r.backup.length>80,'bound token crosses old size limit');var earlier=r.backup;
 r=store.acquire(ids[2],1,files[0],files[1],files[2]);check(r.status===1,'later owner');var later=r.backup;
 r=store.rollback(earlier);check(r.status===0&&r.changed===false,'stale update rejected by actual binding');
 check(store.commit(later).status===1,'commit later backup');check(store.commit(earlier).status===1,'commit stale backup preserves current');
 r=store.release(ids[2]);check(r.status===1&&r.changed===true,'later owner survived');
 check(store.rollback(r.backup).status===1,'current rollback still accepted');check(store.commit(r.backup).status===1,'commit rollback candidate');
 for(var i=0;i<ids.length;i++){r=store.release(ids[i]);check(r.status===1&&r.changed===true,'clean owner');check(store.commit(r.backup).status===1,'clean owner backup');}
 r=store.acquire(ids[0],1,files[0],files[1],files[2]);check(r.status===1,'old removal fixture');
 r=store.release(ids[0]);check(r.status===1&&r.changed===true,'old final detach');earlier=r.backup;
 var candidate=Buffer.from(files[2].toString()+'\n// focused rollback fixture\n');
 r=store.acquire(ids[1],1,files[0],files[1],candidate);check(r.status===1,'new independent installation');
 r=store.rollback(earlier);check(r.status===0&&r.changed===false,'stale final-removal rollback rejected');
 check(fs.readFileSync('/usr/share/gnome-shell/extensions/'+assets.uuid+'/extension.js').toString()===candidate.toString(),'new payload retained');
 check(store.commit(earlier).status===1,'discard old detached payload');
 r=store.release(ids[1]);check(r.status===1&&r.changed===true,'new owner survives');check(store.commit(r.backup).status===1,'clean new payload');
 check(!fs.existsSync('/usr/share/gnome-shell/extensions/'+assets.uuid),'private target removed');
 console.log(JSON.stringify({passed:passed,scope:'managed rollback bindings only'}));
}catch(e){console.log(JSON.stringify({error:String(e)}));code=1;}
process.exit(code);
