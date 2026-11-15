# SPDX-License-Identifier: Apache-2.0
"""Root-only installation of the fixed Agent relay payload and service leases.

Walk trusted directories without symlinks, validate receipts and publish files
atomically. Per-desktop KConfig writes belong to session.py under that user's
UID. A legacy native KWin plugin may be retired only when its owned receipt
matches; an unmanaged plugin or changed file is not ours to remove.
"""
import base64,fcntl,hashlib,json,os,pwd,stat,subprocess,sys

def directory(path,create=False):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.strip('/').split('/'):
            if create:
                try: os.mkdir(part,0o700,dir_fd=fd)
                except FileExistsError: pass
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            s=os.fstat(nxt)
            if s.st_uid or s.st_mode&0o022:
                os.close(nxt); raise ValueError('Unsafe companion directory')
            os.close(fd);fd=nxt
        return fd
    except BaseException:
        os.close(fd);raise

def read(fd,name,limit):
    try: f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
    except FileNotFoundError:return None
    try:
        s=os.fstat(f)
        if not stat.S_ISREG(s.st_mode) or s.st_uid or s.st_nlink!=1 or s.st_mode&0o022 or s.st_size>limit:
            raise ValueError('Unsafe companion file')
        data=os.read(f,limit+1)
        if len(data)>limit:raise ValueError('Companion file exceeds limit')
        return data
    finally:os.close(f)

def atomic(fd,name,data,mode):
    temp='.'+name+'.'+os.urandom(12).hex()
    f=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=fd)
    try:
        with os.fdopen(f,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.rename(temp,name,src_dir_fd=fd,dst_dir_fd=fd);os.fsync(fd)
    finally:
        try:os.unlink(temp,dir_fd=fd)
        except FileNotFoundError:pass

PUBLIC='/usr/local/lib/meshagent-kwin-wire'
STORE='/var/lib/meshagent-kwin-wire'
LEGACY='/var/lib/meshagent-kwin'
NATIVE='/usr/lib64/qt6/plugins/kwin/plugins/meshagent_modifiers.so'
OWN_DESKTOP=PUBLIC+'/input-method.desktop'
CAPTURE_DESKTOPS='/usr/local/share/applications'

def public_directory(path,create=False):
    if create:
        # All components are root-owned and non-writable by other users.
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        try:
            for part in path.strip('/').split('/'):
                try:os.mkdir(part,0o755,dir_fd=fd)
                except FileExistsError:pass
                nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                info=os.fstat(nxt)
                if info.st_uid or info.st_mode&0o022:
                    os.close(nxt);raise ValueError('Unsafe public directory')
                os.close(fd);fd=nxt
            return fd
        except BaseException:
            os.close(fd);raise
    return directory(path)

def path_read(path,limit=262144):
    parent,name=path.rsplit('/',1)
    try:fd=directory(parent)
    except FileNotFoundError:return None
    try:return read(fd,name,limit)
    finally:os.close(fd)

def path_write(path,data,mode=0o644):
    parent,name=path.rsplit('/',1);fd=public_directory(parent,True)
    try:atomic(fd,name,data,mode)
    finally:os.close(fd)

def path_remove(path):
    parent,name=path.rsplit('/',1);fd=directory(parent)
    try:os.unlink(name,dir_fd=fd);os.fsync(fd)
    finally:os.close(fd)

def capture_recover(store,owner,path,receipt):
    """A durable intent precedes a public-file rename and survives lost receipts."""
    pending_name='capture-'+owner+'.pending.json'
    raw=read(store,pending_name,16384)
    if raw is None:return receipt
    pending=json.loads(raw)
    valid_hash=lambda value:isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)
    if not isinstance(pending,dict) or set(pending)!={'version','path','before_sha256','after_sha256'} or pending['version']!=1 or pending['path']!=path or not valid_hash(pending['after_sha256']) or (pending['before_sha256'] is not None and not valid_hash(pending['before_sha256'])):
        raise ValueError('Invalid capture declaration transaction')
    known={pending['before_sha256'],pending['after_sha256']}
    if receipt is not None and receipt['sha256'] not in known:
        raise ValueError('Capture ownership changed during transaction')
    current=path_read(path)
    if current is not None:
        digest=hashlib.sha256(current).hexdigest()
        if digest not in known:raise ValueError('Capture declaration changed during transaction')
        receipt={'version':1,'path':path,'sha256':digest}
        atomic(store,'capture-'+owner+'.json',json.dumps(receipt).encode(),0o600)
    os.unlink(pending_name,dir_fd=store);os.fsync(store)
    return receipt

def capture_declaration(store,operation,owner,executable=None):
    """One capture-only declaration per Agent owner; no shared lease is removed."""
    if not isinstance(owner,str) or len(owner)!=64 or any(c not in '0123456789abcdef' for c in owner):
        raise ValueError('Invalid capture declaration owner')
    name='capture-'+owner+'.json'
    path=CAPTURE_DESKTOPS+'/meshagent-capture-'+owner+'.desktop'
    raw=read(store,name,16384)
    receipt=json.loads(raw) if raw else None
    if receipt is not None and (not isinstance(receipt,dict) or set(receipt)!={'version','path','sha256'} or
            receipt['version']!=1 or receipt['path']!=path or not isinstance(receipt['sha256'],str) or
            len(receipt['sha256'])!=64 or any(c not in '0123456789abcdef' for c in receipt['sha256'])):
        raise ValueError('Invalid capture declaration ownership')
    receipt=capture_recover(store,owner,path,receipt)
    current=path_read(path)
    if current is not None and (receipt is None or hashlib.sha256(current).hexdigest()!=receipt['sha256']):
        raise ValueError('Capture declaration was modified')
    if operation=='uninstall':
        if receipt is None:return False
        if current is not None:path_remove(path)
        os.unlink(name,dir_fd=store);os.fsync(store)
        return True
    if executable is None:return False # Older installer callers retain their input-only contract.
    if not isinstance(executable,str) or not executable.startswith('/') or '=' in executable or len(executable.encode())>4096 or any(ord(c)<32 or ord(c)==127 for c in executable):
        raise ValueError('Invalid capture executable')
    parent,filename=executable.rsplit('/',1)
    directory_fd=directory(parent)
    try:
        fd=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory_fd)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode&0o022 or not info.st_mode&0o111:
                raise ValueError('Untrusted capture executable')
        finally:os.close(fd)
    finally:os.close(directory_fd)
    # First quote the Exec argument, then encode its backslashes as Desktop Entry
    # string escapes. Percent field codes must remain literal path characters.
    argument=executable.replace('\\','\\\\').replace('"','\\"').replace('`','\\`').replace('$','\\$').replace('%','%%')
    argument='"'+argument.replace('\\','\\\\')+'"'
    value=('[Desktop Entry]\nType=Application\nName=MeshCentral Agent Capture\nNoDisplay=true\nTerminal=false\nExec='+argument+' --meshagent-kwin-capture-helper\nX-KDE-Wayland-Interfaces=zkde_screencast_unstable_v1\n').encode()
    changed=current!=value
    if changed:
        digest=hashlib.sha256(value).hexdigest();pending_name='capture-'+owner+'.pending.json'
        pending={'version':1,'path':path,'before_sha256':receipt['sha256'] if receipt else None,'after_sha256':digest}
        atomic(store,pending_name,json.dumps(pending).encode(),0o600)
        path_write(path,value)
        atomic(store,name,json.dumps({'version':1,'path':path,'sha256':digest}).encode(),0o600)
        os.unlink(pending_name,dir_fd=store);os.fsync(store)
    return changed

def active_environments():
    result={}
    for pid in os.listdir('/proc'):
        if not pid.isdecimal():continue
        try:
            root='/proc/'+pid+'/'
            if open(root+'comm').read().strip()!='kwin_wayland':continue
            ids=next(x for x in open(root+'status') if x.startswith('Uid:')).split()[1:]
            if len(set(ids))!=1 or ids[0]=='0':continue
            uid=int(ids[0]);raw=open(root+'environ','rb').read(1048576)
            values=dict(x.split(b'=',1) for x in raw.split(b'\0') if b'=' in x)
            result[uid]={key:values[key.encode()].decode() for key in ['XDG_CONFIG_HOME','XDG_CONFIG_DIRS'] if key.encode() in values}
        except (OSError,ValueError,StopIteration):continue
    return result

def user_call(uid,args,environment=None,timeout=12):
    account=pwd.getpwuid(uid)
    values={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':account.pw_dir,'USER':account.pw_name,'LOGNAME':account.pw_name,'XDG_RUNTIME_DIR':'/run/user/'+str(uid),'DBUS_SESSION_BUS_ADDRESS':'unix:path=/run/user/'+str(uid)+'/bus','XDG_CONFIG_DIRS':'/etc/xdg:/usr/share/kde-settings/kde-profile/default/xdg'}
    values.update(environment or {})
    command=['/usr/sbin/runuser','-u',account.pw_name,'--','/usr/bin/env','-i']+[k+'='+v for k,v in values.items()]+args
    return subprocess.run(command,capture_output=True,text=True,timeout=timeout)

def reload_managers(environments):
    uids=set(environments)
    for value in os.listdir('/run/user'):
        if value.isdecimal() and int(value)!=0 and os.path.exists('/run/user/'+value+'/bus'):
            try:pwd.getpwuid(int(value));uids.add(int(value))
            except KeyError:pass
    for uid in sorted(uids)[:16]:
        try:user_call(uid,['/usr/bin/systemctl','--user','daemon-reload'],environments.get(uid),timeout=3)
        except (OSError,subprocess.SubprocessError):pass

def session_action(uid,action,environment=None):
    result=user_call(uid,['/usr/bin/python3','-I',PUBLIC+'/session.py',action],environment)
    if result.returncode:return {'uid':uid,'state':'error'}
    data=json.loads(result.stdout)
    if not isinstance(data,dict) or not isinstance(data.get('state'),str):raise ValueError('Invalid session response')
    return {'uid':uid,**data}

def retire_native(owner,environments):
    raw=path_read(LEGACY+'/owners.json',16384)
    if raw is None:return 'not-owned'
    receipt=json.loads(raw);owners=receipt.get('owners')
    if not isinstance(owners,list) or len(owners)>64:raise ValueError('Invalid native ownership')
    if owner not in owners:return 'not-owned'
    remaining=[value for value in owners if value!=owner]
    fd=directory(LEGACY)
    try:
        if remaining:
            receipt['owners']=remaining;atomic(fd,'owners.json',json.dumps(receipt).encode(),0o600);return 'retained-for-other-owners'
        current=path_read(NATIVE)
        if current is not None and hashlib.sha256(current).hexdigest()!=receipt.get('sha256'):
            raise ValueError('Owned native companion was modified')
        for uid,environment in environments.items():
            unload=user_call(uid,['/usr/bin/gdbus','call','--session','--dest','org.kde.KWin','--object-path','/Plugins','--method','org.kde.KWin.Plugins.UnloadPlugin','meshagent_modifiers'],environment,timeout=6)
            check=user_call(uid,['/usr/bin/gdbus','call','--session','--dest','org.kde.KWin','--object-path','/Plugins','--method','org.freedesktop.DBus.Properties.Get','org.kde.KWin.Plugins','LoadedPlugins'],environment,timeout=6)
            if unload.returncode or check.returncode or "'meshagent_modifiers'" in check.stdout:return 'activation-pending'
        if current is not None:path_remove(NATIVE)
        os.unlink('owners.json',dir_fd=fd);os.fsync(fd)
        return 'removed'
    finally:os.close(fd)

def desired_files(bundle):
    if set(bundle)!= {'wire_bridge.py','session.py'}:raise ValueError('Unexpected wire bundle files')
    files={PUBLIC+'/'+name:base64.b64decode(value,validate=True) for name,value in bundle.items()}
    if any(len(value)>131072 for value in files.values()):raise ValueError('Wire file limit')
    files[OWN_DESKTOP]=('[Desktop Entry]\nType=Application\nName=Virtual Keyboard\nNoDisplay=true\nX-KDE-Wayland-VirtualKeyboard=true\nExec=/usr/bin/python3 -I '+PUBLIC+'/session.py launch\n').encode()
    files['/etc/xdg/autostart/meshagent-kwin-input-bridge.desktop']=('[Desktop Entry]\nType=Application\nName=MeshCentral Agent\nNoDisplay=true\nOnlyShowIn=KDE;\nExec=/usr/bin/python3 -I '+PUBLIC+'/session.py install\n').encode()
    for unit in ['plasma-kwin_wayland.service','plasma-login-kwin_wayland.service']:
        if os.path.isfile('/usr/lib/systemd/user/'+unit) or os.path.isfile('/lib/systemd/user/'+unit):
            files['/etc/systemd/user/'+unit+'.d/50-meshagent-input-bridge.conf']=('[Service]\nExecStartPost=-/usr/bin/python3 -I '+PUBLIC+'/session.py install\n').encode()
    return files

def main(data):
    if os.getuid()!=0 or os.geteuid()!=0:raise ValueError('Root installer required')
    operation=data['operation'];owner=data['owner']
    if operation not in ['install','uninstall'] or len(owner)!=64 or any(c not in '0123456789abcdef' for c in owner):raise ValueError('Invalid ownership request')
    payload=base64.b64decode(data['payload'],validate=True)
    if len(payload)>262144 or hashlib.sha256(payload).hexdigest()!=data['sha256']:raise ValueError('Invalid wire bundle')
    files=desired_files(json.loads(payload));store=directory(STORE,True)
    lock=os.open('lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=store)
    try:
        info=os.fstat(lock)
        if info.st_uid or info.st_nlink!=1 or not stat.S_ISREG(info.st_mode) or info.st_mode&0o077:raise ValueError('Unsafe ownership lock')
        fcntl.flock(lock,fcntl.LOCK_EX)
        raw=read(store,'owners.json',32768);receipt=json.loads(raw) if raw else {'version':2,'owners':[],'files':{}}
        if raw is None and operation=='uninstall':
            changed=capture_declaration(store,'uninstall',owner)
            return {'state':'not-owned','changed':changed}
        owners=receipt.get('owners')
        if receipt.get('version')!=2 or not isinstance(owners,list) or len(owners)>64 or any(not isinstance(x,str) or len(x)!=64 or any(c not in '0123456789abcdef' for c in x) for x in owners):raise ValueError('Invalid wire ownership')
        allowed=set(files)|{PUBLIC+'/wire_bridge.py',PUBLIC+'/session.py',OWN_DESKTOP,'/etc/xdg/autostart/meshagent-kwin-input-bridge.desktop'}|{'/etc/systemd/user/'+unit+'.d/50-meshagent-input-bridge.conf' for unit in ['plasma-kwin_wayland.service','plasma-login-kwin_wayland.service']}
        if not isinstance(receipt.get('files'),dict) or not set(receipt['files']).issubset(allowed):raise ValueError('Invalid owned file list')
        for path in set(files)|set(receipt['files']):
            current=path_read(path)
            if current is not None:
                known={receipt['files'].get(path)}
                if path in files:known.add(hashlib.sha256(files[path]).hexdigest())
                if hashlib.sha256(current).hexdigest() not in known:raise ValueError('Owned wire file was modified')
        environments=active_environments()
        if operation=='install':
            if owner not in owners:
                if len(owners)>=64:raise ValueError('Ownership limit')
                owners.append(owner)
            changed=False
            for path,value in files.items():
                if path_read(path)!=value:path_write(path,value);changed=True
            empty=public_directory(PUBLIC+'/empty',True);os.close(empty)
            receipt={'version':2,'sha256':data['sha256'],'owners':sorted(set(owners)),'files':{path:hashlib.sha256(value).hexdigest() for path,value in files.items()}}
            atomic(store,'owners.json',json.dumps(receipt).encode(),0o600)
            capture_changed=capture_declaration(store,'install',owner,data.get('capture_executable'))
            reload_managers(environments)
            sessions=[session_action(uid,'install',environment) for uid,environment in environments.items()]
            ready=all(x['state'] in ['active','no-input-method'] for x in sessions)
            legacy=retire_native(owner,environments) if ready else 'activation-pending'
            return {'state':'files-ready' if ready and legacy!='activation-pending' else 'activation-pending','changed':changed or capture_changed,'sessions':sessions,'legacy':legacy}
        if owner not in owners:
            changed=capture_declaration(store,'uninstall',owner)
            return {'state':'not-owned','changed':changed}
        owners.remove(owner)
        if owners:
            capture_declaration(store,'uninstall',owner)
            receipt['owners']=owners;atomic(store,'owners.json',json.dumps(receipt).encode(),0o600);return {'state':'retained','changed':False}
        # Session receipts can be created by the startup integration for users
        # who were not logged in at Agent installation. Restore those too.
        accounts=[]
        for account in pwd.getpwall():
            if account.pw_uid and account.pw_dir.startswith('/') and os.path.exists(account.pw_dir+'/.local/state/meshagent/kwin-wire.json'):
                accounts.append(account)
        if len(accounts)>128:raise ValueError('Session cleanup limit; assets retained')
        sessions=[session_action(account.pw_uid,'uninstall',environments.get(account.pw_uid)) for account in accounts]
        if any(x['state'] not in ['restored','user-changed','not-owned'] for x in sessions):return {'state':'activation-pending','changed':False,'sessions':sessions}
        capture_declaration(store,'uninstall',owner)
        for path in receipt['files']:
            if path_read(path) is not None:path_remove(path)
        os.unlink('owners.json',dir_fd=store);os.fsync(store);reload_managers(environments)
        return {'state':'removed','changed':True,'sessions':sessions}
    finally:os.close(lock);os.close(store)

if __name__=='__main__':
    try:
        raw=sys.argv[1].encode() if len(sys.argv)==2 else sys.stdin.buffer.read(524289)
        if len(raw)>524288:raise ValueError('Request limit')
        result=main(json.loads(raw))
    except Exception as error:result={'state':'error','changed':None,'detail':str(error)}
    print(json.dumps(result))
