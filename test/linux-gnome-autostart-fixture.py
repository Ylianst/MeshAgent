from pathlib import Path
import subprocess,tempfile,json,os,sys,shutil,base64
binary=Path(sys.argv[1]);baseline=sys.argv[2];source=Path(__file__).resolve().parent
assert os.geteuid()==0 and os.readlink('/proc/self/ns/mnt')!=baseline
root=Path(tempfile.mkdtemp(prefix='meshagent-native-autostart.',dir='/tmp'));assert root.parent==Path('/tmp') and root.resolve()==root
root.chmod(0o755);etc=root/'etc';autostart=etc/'xdg/autostart';autostart.mkdir(parents=True,mode=0o755)
mounted=False;result={}
try:
 subprocess.run(['mount','--bind',str(etc),'/etc'],check=True);mounted=True
 script=(source/'linux-gnome-autostart-runtime.js').read_bytes()
 p=subprocess.run([str(binary),'-b64exec',base64.b64encode(script).decode()],cwd=root,capture_output=True,text=True,timeout=20)
 rows=[json.loads(x) for x in p.stdout.splitlines() if x.startswith('{')]
 assert p.returncode==0 and len(rows)==1 and 'error' not in rows[0],(p.returncode,p.stdout,p.stderr)
 result=rows[0];assert not list(autostart.iterdir())
finally:
 if mounted:subprocess.run(['umount','/etc'],check=True)
 assert root.parent==Path('/tmp') and root.name.startswith('meshagent-native-autostart.') and not root.is_symlink()
 shutil.rmtree(root)
result['private_directory_removed']=not root.exists();result['isolated_namespace']=True;print(json.dumps(result))
