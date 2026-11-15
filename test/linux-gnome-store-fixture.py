from pathlib import Path
import subprocess,tempfile,json,os,sys,shutil,base64
binary=Path(sys.argv[1]);baseline=sys.argv[2];source=Path(__file__).resolve().parent
assert os.geteuid()==0 and os.readlink('/proc/self/ns/mnt')!=baseline
root=Path(tempfile.mkdtemp(prefix='meshagent-native-store.',dir='/tmp'));assert root.parent==Path('/tmp') and root.resolve()==root
root.chmod(0o755);share=root/'share';extensions=share/'gnome-shell/extensions';extensions.mkdir(parents=True,mode=0o755)
mounted=False;results={}
def run(script,extra=(),nonroot=False):
    path=root/('test-'+str(len(results))+'.js');path.write_text(script);path.chmod(0o644)
    def drop():os.setgroups([]);os.setgid(65534);os.setuid(65534)
    p=subprocess.run([str(binary),str(path),*extra],cwd=root,capture_output=True,text=True,timeout=25,preexec_fn=drop if nonroot else None)
    rows=[json.loads(x) for x in p.stdout.splitlines() if x.startswith('{')]
    assert p.returncode==0 and len(rows)==1 and 'error' not in rows[0],(p.returncode,p.stdout,p.stderr)
    return rows[0]
try:
    subprocess.run(['mount','--bind',str(share),'/usr/share'],check=True);mounted=True
    script_name=sys.argv[3] if len(sys.argv)>3 else 'linux-gnome-store-runtime.js'
    assert script_name in ['linux-gnome-store-runtime.js','linux-gnome-owner-rollback-runtime.js','linux-gnome-installer-ownership-runtime.js']
    results['transactions']=run((source/script_name).read_text())
    if len(sys.argv)==3:
        rejected="""var code=0;try{var s=require('_gnome-companion-store');var a=require('linux-gnome-companion-assets').files;var r=s.install(Buffer.from(a['metadata.json'].data,'base64'),Buffer.from(a['protocol.js'].data,'base64'),Buffer.from(a['extension.js'].data,'base64'));if(r.status!==0||r.changed!==false)throw new Error('Unsafe parent accepted');console.log(JSON.stringify({rejected:true,errno:r.errno}));}catch(e){console.log(JSON.stringify({error:String(e)}));code=1;}process.exit(code);"""
        outside=root/'outside';outside.mkdir(mode=0o755);extensions.rmdir();extensions.symlink_to(outside,target_is_directory=True)
        results['symlink_parent']=run(rejected);assert not list(outside.iterdir());extensions.unlink();extensions.mkdir(mode=0o755)
        share.chmod(0o777);results['writable_parent']=run(rejected);share.chmod(0o755)
        results['nonroot']=run(rejected,nonroot=True)
        restricted="""var code=0;try{var blocked=0;try{require('fs');}catch(e){blocked++;}try{require('_gnome-companion-store');}catch(e){blocked++;}if(blocked!==2)throw new Error('Filesystem restriction bypass');console.log(JSON.stringify({filesystem_modules_blocked:blocked}));}catch(e){console.log(JSON.stringify({error:String(e)}));code=1;}process.exit(code);"""
        results['restricted_context']=run(restricted,['--script-flags','0x00000001'])
    assert not list(extensions.iterdir())
finally:
    if mounted:subprocess.run(['umount','/usr/share'],check=True)
    assert root.parent==Path('/tmp') and root.name.startswith('meshagent-native-store.') and not root.is_symlink()
    shutil.rmtree(root)
results['private_directory_removed']=not root.exists();results['isolated_namespace']=True;print(json.dumps(results))
