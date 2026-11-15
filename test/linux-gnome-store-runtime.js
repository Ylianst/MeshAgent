// Run only in the private WSL mount-namespace fixture. No real GNOME directory.
var resultCode=0;
try {
    var store=require('_gnome-companion-store');
    var assets=require('linux-gnome-companion-assets');
    var fs=require('fs');
    var names=['metadata.json','protocol.js','extension.js'];
    var files=names.map(function(n){return Buffer.from(assets.files[n].data,'base64');});
    var base='/usr/share/gnome-shell/extensions/'+assets.uuid;
    var passed=0;
    function check(value,name){if(!value)throw new Error(name);passed++;}
    var r=store.install(files[0],files[1],files[2]);
    check(r.status===1&&r.changed===true&&r.backup==='','first install');
    for(var i=0;i<names.length;i++) {
        var actual=fs.readFileSync(base+'/'+names[i]);
        var hash=require('SHA256Stream').create().syncHash(actual).toString('hex').toLowerCase();
        check(hash===assets.files[names[i]].sha256,'exact embedded '+names[i]);
    }
    r=store.install(files[0],files[1],files[2]);check(r.status===1&&r.changed===false,'unchanged install');
    var candidate=Buffer.from(files[2].toString()+'\n// isolated storage runtime test\n');
    r=store.install(files[0],files[1],candidate);check(r.status===1&&r.changed===true&&r.backup.length>0,'update');
    var backup=r.backup;
    check(store.rollback(backup).status===1,'update rollback');
    check(store.commit(backup).status===1,'remove rejected candidate');
    var modified=Buffer.from(files[2]);modified[0]=88;fs.writeFileSync(base+'/extension.js',modified);
    check(store.install(files[0],files[1],candidate).status===0,'preserve edited asset on update');
    check(store.uninstall().status===0,'preserve edited asset on uninstall');
    fs.writeFileSync(base+'/extension.js',files[2]);
    r=store.uninstall();check(r.status===1&&r.changed===true,'detach for uninstall');backup=r.backup;
    check(store.rollback(backup).status===1,'uninstall rollback');
    r=store.uninstall();check(r.status===1&&r.changed===true,'uninstall after rollback');
    check(store.commit(r.backup).status===1,'uninstall commit');
    r=store.uninstall();check(r.status===1&&r.changed===false,'already absent');
    check(!fs.existsSync(base),'fixture current directory gone');
    var threw=false;try{store.install('metadata',files[1],files[2]);}catch(e){threw=true;}
    check(threw,'reject non-buffer');
    threw=false;try{store.rollback('abc\u0000def');}catch(e){threw=true;}
    check(threw,'reject NUL token');
    check(store.rollback('../outside').status===0,'reject traversal');
    r=store.commit('.meshagent-console-'+Array(33).join('0'));
    check(r.status===0&&r.changed===null,'failed commit has explicit unknown cleanup state');
    var ownerA=Array(65).join('a'),ownerB=Array(65).join('b');
    r=store.acquire(ownerA,1,files[0],files[1],files[2]);check(r.status===1&&r.changed===true&&r.backup==='','first service acquire');
    r=store.acquire(ownerA,1,files[0],files[1],files[2]);check(r.status===1&&r.changed===false,'repeat owner acquire');
    r=store.acquire(ownerB,1,files[0],files[1],files[2]);check(r.status===1&&r.changed===true,'second service acquire');
    check(store.commit(r.backup).status===1,'commit second owner');
    check(store.uninstall().status===0,'unscoped removal preserves shared ownership');
    r=store.acquire(ownerA,1,files[0],files[1],candidate);check(r.status===0&&r.changed===false,'same generation conflict');
    r=store.release(ownerA);check(r.status===1&&r.changed===true&&fs.existsSync(base),'first owner release preserves files');
    check(store.rollback(r.backup).status===1,'restore released owner');check(store.commit(r.backup).status===1,'discard owner release candidate');
    r=store.release(ownerB);check(r.status===1&&r.changed===true&&fs.existsSync(base),'second owner release preserves restored first owner');
    check(store.commit(r.backup).status===1,'commit release');
    r=store.acquire(ownerA,2,files[0],files[1],candidate);check(r.status===1&&r.changed===true,'versioned payload upgrade');
    check(store.commit(r.backup).status===1,'commit versioned payload');
    r=store.acquire(ownerB,1,files[0],files[1],files[2]);check(r.status===0&&r.changed===false,'old installer cannot downgrade');
    r=store.release(ownerB);check(r.status===1&&r.changed===false,'unknown owner neutral');
    r=store.release(ownerA);check(r.status===1&&r.changed===true&&!fs.existsSync(base),'last owner detach');
    check(store.rollback(r.backup).status===1&&fs.existsSync(base),'rollback last owner detach');
    r=store.release(ownerA);check(r.status===1&&r.changed===true,'last owner detach again');
    check(store.commit(r.backup).status===1&&!fs.existsSync(base),'last owner cleanup');
    var badGenerations=[0,-1,1.5,4294967296,NaN,Infinity];
    for(i=0;i<badGenerations.length;i++){
        threw=false;try{store.acquire(ownerA,badGenerations[i],files[0],files[1],files[2]);}catch(e){threw=true;}
        check(threw,'invalid generation rejected');
    }
    threw=false;try{store.acquire(ownerA.slice(1),1,files[0],files[1],files[2]);}catch(e){threw=true;}
    check(threw,'owner identity length rejected');
    check(store.release('../outside').status===0,'release traversal cannot select path');
    console.log(JSON.stringify({passed:passed,scope:'actual native Agent runtime, private mount fixture only'}));
}catch(e){console.log(JSON.stringify({error:String(e)}));resultCode=1;}
process.exit(resultCode);
