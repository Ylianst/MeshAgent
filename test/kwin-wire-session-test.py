"""Targeted per-session preference preservation and vendor-update contracts."""
import importlib.util,json,os,pathlib,subprocess,sys,tempfile,unittest,socket,struct,threading
SOURCE=pathlib.Path(__file__).resolve().parents[1]/'meshcore/KVM/Linux/kwin-input-bridge/session.py'
class SessionTests(unittest.TestCase):
 def setUp(self):
  spec=importlib.util.spec_from_file_location('kwin_wire_session',SOURCE);self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
 def test_removes_only_new_owned_key_and_group(self):
  original=b'[Other]\nKeep=exact\n';current=original+b'\n[Wayland]\nInputMethod=/managed.desktop\n'
  state={'original_line':None,'group_existed':False};self.assertEqual(self.m.restore_entry(current,state),original)
 def test_readiness_accepts_owned_text_capability_without_reselecting_method(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'XDG_RUNTIME_DIR':root}):
   self.m.compositor_pid=lambda:42
   self.m.authenticated_bridge=lambda peer,pid:True
   path=root+'/meshagent-ime-bridge.42.sock'
   with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as server:
    server.bind(path);os.chmod(path,0o600);server.listen(1);server.settimeout(1)
    for status,include_pending in [(3,False),(6,False),(7,False),(8,False),(8,True),(9,True)]:
     received=[]
     def respond():
      with server.accept()[0] as peer:
       peer.settimeout(1);received.append(peer.recv(24));peer.send(struct.pack('=9I',self.m.MAGIC,0,status,1,0,0,0,0,0))
     worker=threading.Thread(target=respond);worker.start()
     self.assertEqual(self.m.ready(include_pending),status in [3,6,7] or (include_pending and status==8));worker.join(2);self.assertFalse(worker.is_alive())
     self.assertEqual(received,[struct.pack('=6I',self.m.MAGIC,0,0,0,0,0)])
 def test_pending_readiness_still_authenticates_server_before_sending_probe(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'XDG_RUNTIME_DIR':root}):
   self.m.compositor_pid=lambda:42;self.m.authenticated_bridge=lambda peer,pid:False
   with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as server:
    server.bind(root+'/meshagent-ime-bridge.42.sock');os.chmod(root+'/meshagent-ime-bridge.42.sock',0o600);server.listen(1);server.settimeout(1)
    received=[]
    def respond():
     with server.accept()[0] as peer:peer.settimeout(1);received.append(peer.recv(24))
    worker=threading.Thread(target=respond);worker.start();self.assertFalse(self.m.ready(include_pending=True));worker.join(2);self.assertFalse(worker.is_alive())
    self.assertEqual(received,[b''])
 def test_install_replaces_legacy_relay_but_preserves_current_relay(self):
  from unittest.mock import patch
  # Exercise the real readiness socket/parser inside install(), rather than
  # substituting ready(): replacing files alone must not leave old code alive.
  for legacy in [False,True]:
   with self.subTest(legacy=legacy),tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'XDG_RUNTIME_DIR':directory}):
    root=pathlib.Path(directory);selected=[];observed_off=[];received=[];errors=[];stop=threading.Event()
    self.m.config_home=lambda:root;self.m.required_path=lambda:root/'required'
    self.m.effective=lambda *args:self.m.DESKTOP;self.m.load_state=lambda:{}
    self.m.explicit_command=lambda *args:None;self.m.original=lambda state:'/vendor.desktop'
    self.m.compositor_pid=lambda:42;self.m.authenticated_bridge=lambda peer,pid:True
    def select(value):
     if value==self.m.DESKTOP:self.assertTrue(observed_off)
     selected.append(value)
    def query(*args):
     if selected and selected[-1]=='':observed_off.append(True);return '(<false>,)'
     return '(<true>,)'
    self.m.select_method=select;self.m.command=query
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as server:
     server.bind(directory+'/meshagent-ime-bridge.42.sock');os.chmod(server.getsockname(),0o600);server.listen(8);server.settimeout(.05)
     def respond():
      try:
       while not stop.is_set():
        try:peer=server.accept()[0]
        except socket.timeout:continue
        with peer:
         peer.settimeout(1);raw=peer.recv(24);received.append(raw)
         # A legacy success response must not count as current readiness.
         version=0x4d414231 if legacy and self.m.DESKTOP not in selected else self.m.MAGIC
         peer.send(struct.pack('=9I',version,0,7,1,0,0,0,0,0))
      except Exception as error:errors.append(error)
     worker=threading.Thread(target=respond);worker.start()
     try:
      with patch.object(self.m.time,'monotonic',side_effect=range(100)),patch.object(self.m.time,'sleep'):
       self.assertEqual(self.m.install(),{'state':'active','changed':legacy})
     finally:stop.set();worker.join(2)
     self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
    self.assertEqual(self.m.MAGIC,0x4d414233)
    self.assertEqual(selected,['',self.m.DESKTOP] if legacy else [])
    self.assertGreaterEqual(len(received),2 if legacy else 1)
    self.assertTrue(all(raw==struct.pack('=6I',self.m.MAGIC,0,0,0,0,0) for raw in received))
    self.assertEqual((root/'required').read_bytes(),struct.pack('=I',self.m.MAGIC))
 def test_empty_vendor_selection_activates_owned_method_and_preserves_empty_original(self):
  with tempfile.TemporaryDirectory() as root:
   root=pathlib.Path(root);selected=[];self.m.config_home=lambda:root;self.m.state_path=lambda:root/'receipt.json'
   self.m.required_path=lambda:root/'required';self.m.effective=lambda *args:'';self.m.explicit_command=lambda *args:None
   self.m.select_method=selected.append;self.m.ready=lambda:True;self.m.command=lambda *args:'(<true>,)'
   self.assertEqual(self.m.install(),{'state':'active','changed':True});self.assertEqual(selected,[self.m.DESKTOP])
   saved=json.loads((root/'receipt.json').read_text());self.assertEqual(saved['original_value'],'');self.assertIsNone(saved['original_line'])
   self.assertEqual(self.m.original(saved),'')
   self.assertEqual((root/'required').read_bytes(),struct.pack('=I',self.m.MAGIC+1))
 def test_stock_method_keeps_ordinary_desktop_marker(self):
  with tempfile.TemporaryDirectory() as root:
   root=pathlib.Path(root);vendor=root/'vendor.desktop';vendor.write_text('[Desktop Entry]\n')
   self.m.config_home=lambda:root;self.m.state_path=lambda:root/'receipt.json';self.m.required_path=lambda:root/'required'
   self.m.effective=lambda *args:str(vendor);self.m.explicit_command=lambda *args:None
   self.m.ready=lambda:True;self.m.command=lambda *args:'(<true>,)'
   self.assertEqual(self.m.install()['state'],'active');self.assertEqual((root/'required').read_bytes(),struct.pack('=I',self.m.MAGIC))
 def test_empty_original_launches_only_owned_headless_client(self):
  self.m.load_state=lambda:{};self.m.explicit_command=lambda *args:None;self.m.original=lambda state:''
  from unittest.mock import patch
  with patch.object(self.m.os,'execv',side_effect=RuntimeError('exec')) as execute:
   with self.assertRaisesRegex(RuntimeError,'exec'):self.m.launch()
   self.assertEqual(execute.call_args.args,('/usr/bin/python3',['/usr/bin/python3','-I',str(self.m.ROOT/'wire_bridge.py')]))
 def test_selection_announces_committed_value_even_if_unchanged(self):
  disk=[self.m.DESKTOP];cached=[''];operations=[]
  def command(args):
   if args[0]=='/usr/bin/kwriteconfig6':disk[0]=args[-1];operations.append('write')
   elif args[:2]==['/usr/bin/gdbus','emit']:cached[0]=disk[0];operations.append('notify')
   else:self.fail('Unexpected selection operation')
   return ''
  self.m.command=command;self.m.select_method(self.m.DESKTOP)
  self.assertEqual(cached,disk);self.assertEqual(operations,['write','notify'])
 def test_owned_selection_recovers_missed_notification_without_preference_toggle(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as root:
   root=pathlib.Path(root);notifications=[]
   self.m.config_home=lambda:root;self.m.required_path=lambda:root/'required'
   self.m.effective=lambda *args:self.m.DESKTOP;self.m.load_state=lambda:{}
   self.m.explicit_command=lambda *args:None;self.m.original=lambda state:''
   self.m.select_method=lambda value:self.fail('Recovery must not toggle the owned preference')
   def command(args):
    if args[1]=='emit':notifications.append(args);return ''
    return '(<true>,)' if notifications else '(<false>,)'
   self.m.command=command;self.m.ready=lambda:bool(notifications)
   with patch.object(self.m.time,'monotonic',side_effect=range(100)),patch.object(self.m.time,'sleep'):
    self.assertEqual(self.m.install(),{'state':'active','changed':False})
   self.assertEqual(len(notifications),1)
   self.assertEqual((root/'required').read_bytes(),struct.pack('=I',self.m.MAGIC+1))
 def test_owned_selection_waits_for_authenticated_child_startup(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as root:
   root=pathlib.Path(root);polls=[];self.m.config_home=lambda:root;self.m.required_path=lambda:root/'required'
   self.m.effective=lambda *args:self.m.DESKTOP;self.m.load_state=lambda:{}
   self.m.explicit_command=lambda *args:None;self.m.original=lambda state:''
   self.m.select_method=lambda value:self.fail('KWin availability precedes its child listener; do not restart it early')
   self.m.command=lambda *args:'(<true>,)'
   def ready(include_pending=False):
    if not include_pending:polls.append(1)
    return include_pending and len(polls)>=3
   self.m.ready=ready
   with patch.object(self.m.time,'monotonic',side_effect=range(100)),patch.object(self.m.time,'sleep'):
    self.assertEqual(self.m.install(),{'state':'activation-pending','changed':False})
   self.assertEqual(len(polls),3)
 def test_reactivation_waits_for_disabled_method_before_managed_selection(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as root:
   root=pathlib.Path(root);selected=[];observed_off=[];polls=[]
   self.m.config_home=lambda:root;self.m.required_path=lambda:root/'required'
   self.m.effective=lambda *args:self.m.DESKTOP;self.m.load_state=lambda:{}
   self.m.explicit_command=lambda *args:None;self.m.original=lambda state:'/vendor.desktop'
   def select(value):
    if value==self.m.DESKTOP:self.assertTrue(observed_off,'KConfig notifications can coalesce before KWin handles disable')
    selected.append(value)
   def query(*args):
    if selected and selected[-1]=='':
     polls.append(1)
     if len(polls)>1:observed_off.append(True);return '(<false>,)'
    return '(<true>,)'
   self.m.select_method=select;self.m.command=query
   self.m.ready=lambda:bool(selected and selected[-1]==self.m.DESKTOP and observed_off)
   with patch.object(self.m.time,'monotonic',side_effect=range(100)),patch.object(self.m.time,'sleep'):
    self.assertEqual(self.m.install(),{'state':'active','changed':True})
   self.assertEqual(selected,['',self.m.DESKTOP]);self.assertGreaterEqual(len(polls),2)
 def test_pending_owned_context_is_retained_without_claiming_active(self):
  with tempfile.TemporaryDirectory() as root:
   root=pathlib.Path(root);self.m.config_home=lambda:root;self.m.required_path=lambda:root/'required'
   self.m.effective=lambda *args:self.m.DESKTOP;self.m.load_state=lambda:{}
   self.m.explicit_command=lambda *args:None;self.m.original=lambda state:''
   self.m.select_method=lambda value:self.fail('A context-pending owned relay must not be reselected')
   self.m.command=lambda *args:'(<true>,)';self.m.ready=lambda include_pending=False:include_pending
   self.assertEqual(self.m.install(),{'state':'activation-pending','changed':False})
   self.assertEqual((root/'required').read_bytes(),struct.pack('=I',self.m.MAGIC+1))
 def test_restarted_owned_method_reports_pending_without_waiting_for_text_context(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as root:
   root=pathlib.Path(root);selected=[];pending=[];self.m.config_home=lambda:root;self.m.required_path=lambda:root/'required'
   self.m.effective=lambda *args:self.m.DESKTOP;self.m.load_state=lambda:{};self.m.original=lambda state:''
   self.m.explicit_command=lambda *args:None;self.m.select_method=selected.append
   self.m.command=lambda *args:'(<false>,)' if selected and selected[-1]=='' else '(<true>,)'
   def ready(include_pending=False):
    if include_pending and selected and selected[-1]==self.m.DESKTOP:pending.append(1);return True
    return False
   self.m.ready=ready
   with patch.object(self.m.time,'monotonic',side_effect=range(100)),patch.object(self.m.time,'sleep'):
    self.assertEqual(self.m.install(),{'state':'activation-pending','changed':True})
   self.assertEqual(selected,['',self.m.DESKTOP]);self.assertEqual(pending,[1])
 def test_unavailable_owned_method_gets_one_notification_then_bounded_pending(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as root:
   root=pathlib.Path(root);notifications=[];self.m.config_home=lambda:root;self.m.required_path=lambda:root/'required'
   self.m.effective=lambda *args:self.m.DESKTOP;self.m.load_state=lambda:{};self.m.explicit_command=lambda *args:None
   self.m.select_method=lambda value:self.fail('Unavailable recovery must not toggle the preference')
   def command(args):
    if args[1]=='emit':notifications.append(args);return ''
    return '(<false>,)'
   self.m.command=command
   with patch.object(self.m.time,'monotonic',side_effect=range(100)),patch.object(self.m.time,'sleep'):
    self.assertEqual(self.m.install(),{'state':'activation-pending','changed':False})
   self.assertEqual(len(notifications),1);self.assertFalse((root/'required').exists())
 def test_failed_notification_is_bounded_and_cannot_claim_ready(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as root:
   root=pathlib.Path(root);notifications=[];self.m.config_home=lambda:root;self.m.required_path=lambda:root/'required'
   self.m.effective=lambda *args:self.m.DESKTOP;self.m.load_state=lambda:{};self.m.explicit_command=lambda *args:None
   self.m.select_method=lambda value:self.fail('A failed notification must not rewrite the preference')
   def command(args):
    if args[1]=='emit':notifications.append(args);raise subprocess.CalledProcessError(1,args)
    return '(<false>,)'
   self.m.command=command
   with patch.object(self.m.time,'monotonic',side_effect=range(100)),patch.object(self.m.time,'sleep'):
    self.assertEqual(self.m.install(),{'state':'activation-pending','changed':False})
   self.assertEqual(len(notifications),1);self.assertFalse((root/'required').exists())
 def test_unavailable_stock_selection_is_not_reannounced_as_owned(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as root:
   root=pathlib.Path(root);vendor=root/'vendor.desktop';vendor.write_text('[Desktop Entry]\n')
   self.m.config_home=lambda:root;self.m.state_path=lambda:root/'receipt.json'
   self.m.effective=lambda *args:str(vendor);self.m.explicit_command=lambda *args:None
   self.m.select_method=lambda value:self.fail('The unavailable stock choice must be preserved')
   def command(args):
    self.assertNotEqual(args[1],'emit');return '(<false>,)'
   self.m.command=command
   with patch.object(self.m.time,'monotonic',side_effect=range(100)),patch.object(self.m.time,'sleep'):
    self.assertEqual(self.m.install(),{'state':'activation-pending','changed':False})
   self.assertEqual(json.loads((root/'receipt.json').read_text())['original_value'],str(vendor))
 def test_disable_timeout_restores_managed_preference_without_claiming_ready(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as root:
   root=pathlib.Path(root);selected=[]
   self.m.config_home=lambda:root;self.m.required_path=lambda:root/'required'
   self.m.effective=lambda *args:self.m.DESKTOP;self.m.load_state=lambda:{}
   self.m.explicit_command=lambda *args:None;self.m.original=lambda state:'/vendor.desktop'
   self.m.select_method=selected.append;self.m.command=lambda *args:'(<true>,)';self.m.ready=lambda:False
   with patch.object(self.m.time,'monotonic',side_effect=[0,1,7,8,9,15]),patch.object(self.m.time,'sleep'):
    self.assertEqual(self.m.install(),{'state':'activation-pending','changed':True})
   self.assertEqual(selected,['',self.m.DESKTOP])
 def test_restores_original_choice_preserving_concurrent_unrelated_settings(self):
  current=b'[Other]\nKeep=changed-by-user\n\n[Wayland]\nInputMethod=/managed.desktop\nScale=2\n'
  result=self.m.restore_entry(current,{'original_line':'InputMethod=/user-choice.desktop','group_existed':True})
  self.assertIn(b'Keep=changed-by-user',result);self.assertIn(b'Scale=2',result);self.assertIn(b'InputMethod=/user-choice.desktop',result);self.assertNotIn(b'/managed.desktop',result)
 def test_uninstall_removes_legacy_and_current_markers_only(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'XDG_RUNTIME_DIR':directory}):
   root=pathlib.Path(directory);receipt=root/'receipt';receipt.write_text('{}')
   (root/'kwinrc').write_text('[Other]\nKeep=yes\n\n[Wayland]\nInputMethod='+self.m.DESKTOP+'\n')
   self.m.config_home=lambda:root;self.m.state_path=lambda:receipt;self.m.effective=lambda *args:self.m.DESKTOP
   self.m.load_state=lambda:{'original_line':None,'group_existed':False}
   self.m.original=lambda state:'';selected=[];self.m.select_method=selected.append;self.m.bridge_alive=lambda:False
   markers=[]
   for index,value in enumerate((0x4d414231,0x4d414232,self.m.MAGIC,self.m.MAGIC+1,0x12345678)):
    path=root/('meshagent-ime-bridge.%d.required'%index);path.write_bytes(struct.pack('=I',value));path.chmod(0o600);markers.append(path)
   self.assertEqual(self.m.uninstall(),{'state':'restored','changed':True})
   self.assertEqual(selected,['']);self.assertFalse(receipt.exists())
   self.assertTrue(all(not path.exists() for path in markers[:-1]));self.assertTrue(markers[-1].exists())
   self.assertIn('Keep=yes',(root/'kwinrc').read_text())
 def test_does_not_freeze_inherited_vendor_choice_across_updates(self):
  state={'original_line':None,'original_value':'/old.desktop','explicit':False}
  self.m.effective=lambda inherited:'/vendor-before.desktop';self.assertEqual(self.m.original(state),'/vendor-before.desktop')
  self.m.effective=lambda inherited:'/vendor-after.desktop';self.assertEqual(self.m.original(state),'/vendor-after.desktop')
 def test_immutable_or_ambiguous_setting_is_refused(self):
  for raw in [b'[Wayland]\nInputMethod[$i]=/locked.desktop\n',b'[Wayland]\nInputMethod=/one\nInputMethod=/two\n']:
   with self.assertRaises(ValueError):self.m.local_entry(raw)
 def test_session_receipt_cannot_inject_additional_config_lines(self):
  with tempfile.TemporaryDirectory() as root:
   path=pathlib.Path(root)/'state';path.write_text(json.dumps({'version':1,'group_existed':True,'original_line':'InputMethod=/one\nInjected=yes','original_value':'/one','config_home':root}));self.m.state_path=lambda:path
   with self.assertRaises(ValueError):self.m.load_state()
 def test_vendor_query_uses_private_writable_profile_and_cleans_it(self):
  paths=[]
  def query(args,env):
   path=pathlib.Path(env['XDG_CONFIG_HOME']);paths.append(path)
   self.assertEqual(path.stat().st_mode&0o777,0o700)
   self.assertEqual(path.stat().st_uid,os.getuid());(path/'kreadconfig6rc').write_text('application state')
   return '/vendor.desktop'
  self.m.command=query
  self.assertEqual(self.m.effective(True),'/vendor.desktop');self.assertFalse(paths[0].exists())
 def test_reads_current_vendor_command_arguments(self):
  process=subprocess.Popen([sys.executable,'-c','import time;print("READY",flush=True);time.sleep(30)','--inputmethod','/usr/bin/plasma-keyboard --new-vendor-option'],stdout=subprocess.PIPE,text=True)
  try:
   self.assertEqual(process.stdout.readline().strip(),'READY')
   self.assertEqual(self.m.explicit_command(process.pid),['/usr/bin/plasma-keyboard','--new-vendor-option'])
  finally:process.terminate();process.wait(timeout=2);process.stdout.close()
if __name__=='__main__':unittest.main()
