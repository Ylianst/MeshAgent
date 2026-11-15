"""Root-owned capture declarations, independent owners and hostile filesystem state."""
import base64,hashlib,importlib.util,json,os,pathlib,tempfile,unittest
SOURCE=pathlib.Path(__file__).resolve().parents[1]/'meshcore/KVM/Linux/kwin-input-bridge/install.py'
class CaptureDeclarations(unittest.TestCase):
 def setUp(self):
  if os.geteuid():self.skipTest('isolated root environment required')
  spec=importlib.util.spec_from_file_location('capture_install',SOURCE);self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
  self.temp=tempfile.TemporaryDirectory(prefix='meshagent-capture-declaration-',dir='/run')
  self.root=pathlib.Path(self.temp.name);self.m.CAPTURE_DESKTOPS=str(self.root/'applications')
  self.store=self.root/'store';self.store.mkdir();self.fd=os.open(self.store,os.O_RDONLY|os.O_DIRECTORY)
  self.exe=self.root/'Mesh Agent';self.exe.write_bytes(b'fixture executable');self.exe.chmod(0o755)
  self.owner='a'*64;self.other='b'*64
 def tearDown(self):
  if hasattr(self,'fd'):os.close(self.fd);self.temp.cleanup()
 def declaration(self,owner=None):return pathlib.Path(self.m.CAPTURE_DESKTOPS)/('meshagent-capture-'+(owner or self.owner)+'.desktop')
 def install(self,owner=None):return self.m.capture_declaration(self.fd,'install',owner or self.owner,str(self.exe))
 def test_exact_capture_only_executable_and_no_input_authority(self):
  self.assertTrue(self.install());text=self.declaration().read_text()
  self.assertIn('Exec="'+str(self.exe)+'" --meshagent-kwin-capture-helper\n',text)
  self.assertEqual([x for x in text.splitlines() if x.startswith('X-KDE-Wayland-Interfaces=')],['X-KDE-Wayland-Interfaces=zkde_screencast_unstable_v1'])
  self.assertNotIn('fake_input',text);self.assertEqual(self.declaration().stat().st_uid,0)
  self.assertFalse(self.declaration().stat().st_mode&0o022)
 def test_repeated_install_and_uninstall_preserve_other_service(self):
  self.install();self.install(self.other);other=self.declaration(self.other).read_bytes()
  self.assertFalse(self.install());self.assertTrue(self.m.capture_declaration(self.fd,'uninstall',self.owner))
  self.assertFalse(self.declaration().exists());self.assertEqual(self.declaration(self.other).read_bytes(),other)
  self.assertFalse(self.m.capture_declaration(self.fd,'uninstall',self.owner))
 def test_root_executable_update_refreshes_only_owned_declaration(self):
  self.install();old=self.declaration().read_bytes();new=self.root/'new agent';new.write_bytes(b'new fixture');new.chmod(0o755)
  self.assertTrue(self.m.capture_declaration(self.fd,'install',self.owner,str(new)))
  self.assertNotEqual(self.declaration().read_bytes(),old)
  self.assertIn(str(new),self.declaration().read_text())
 def test_modified_or_unmanaged_declaration_is_preserved(self):
  self.install();self.declaration().write_text('user changed\n')
  for operation in ['install','uninstall']:
   with self.assertRaises(ValueError):self.m.capture_declaration(self.fd,operation,self.owner,str(self.exe))
  self.assertEqual(self.declaration().read_text(),'user changed\n')
  os.unlink(self.store/('capture-'+self.owner+'.json'))
  with self.assertRaises(ValueError):self.install()
 def test_writable_and_untrusted_executable_is_rejected(self):
  self.exe.chmod(0o777)
  with self.assertRaises(ValueError):self.install()
  self.exe.chmod(0o755);os.chown(self.exe,65534,-1)
  with self.assertRaises(ValueError):self.install()
 def test_symlink_executable_and_parent_are_rejected(self):
  link=self.root/'link';link.symlink_to(self.exe)
  with self.assertRaises(OSError):self.m.capture_declaration(self.fd,'install',self.owner,str(link))
  alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
  with self.assertRaises(OSError):self.m.capture_declaration(self.fd,'install',self.owner,str(alias/self.exe.name))
 def test_malformed_receipt_cannot_remove_an_unrelated_file(self):
  self.install();record=self.store/('capture-'+self.owner+'.json');value=json.loads(record.read_text());value['path']=str(self.exe);record.write_text(json.dumps(value))
  with self.assertRaises(ValueError):self.m.capture_declaration(self.fd,'uninstall',self.owner)
  self.assertTrue(self.exe.exists());self.assertTrue(self.declaration().exists())
 def test_missing_executable_legacy_caller_creates_no_declaration(self):
  self.assertFalse(self.m.capture_declaration(self.fd,'install',self.owner));self.assertFalse(self.declaration().exists())
 def test_orphan_capture_lease_can_be_removed_without_shared_input_receipt(self):
  self.install();self.m.STORE=str(self.store)
  payload=json.dumps({'wire_bridge.py':'','session.py':''}).encode()
  result=self.m.main({'operation':'uninstall','owner':self.owner,'payload':base64.b64encode(payload).decode(),'sha256':hashlib.sha256(payload).hexdigest()})
  self.assertEqual(result,{'state':'not-owned','changed':True});self.assertFalse(self.declaration().exists())
 def test_invalid_owner_and_exec_equal_sign_are_rejected(self):
  with self.assertRaises(ValueError):self.m.capture_declaration(self.fd,'install','../escape',str(self.exe))
  special=self.root/'Agent=fixture';special.write_bytes(b'fixture');special.chmod(0o755)
  with self.assertRaises(ValueError):self.m.capture_declaration(self.fd,'install',self.owner,str(special))
 def test_exec_reserved_characters_are_escaped_as_one_argument(self):
  special=self.root/'Agent $value "quote" `tick` %f \\path';special.write_bytes(b'fixture');special.chmod(0o755)
  self.m.capture_declaration(self.fd,'install',self.owner,str(special));text=self.declaration().read_text()
  self.assertIn('\\\\$',text);self.assertIn('\\\\"',text);self.assertIn('\\\\`',text);self.assertIn('%%f',text);self.assertIn('\\\\\\\\path',text)
 def interrupt_receipt(self,executable=None):
  original=self.m.atomic
  def interrupt(fd,name,data,mode):
   if name=='capture-'+self.owner+'.json':raise OSError('simulated interruption before receipt publication')
   return original(fd,name,data,mode)
  self.m.atomic=interrupt
  try:
   with self.assertRaises(OSError):self.m.capture_declaration(self.fd,'install',self.owner,str(executable or self.exe))
  finally:self.m.atomic=original
 def test_interrupted_first_publication_can_retry_and_uninstall(self):
  self.interrupt_receipt();self.assertTrue(self.declaration().exists())
  self.assertFalse((self.store/('capture-'+self.owner+'.json')).exists())
  self.assertFalse(self.install());self.assertTrue(self.m.capture_declaration(self.fd,'uninstall',self.owner))
  self.assertFalse(self.declaration().exists());self.assertFalse(list(self.store.glob('*.pending.json')))
 def test_interrupted_first_publication_can_uninstall_directly(self):
  self.install(self.other);other=self.declaration(self.other).read_bytes();self.interrupt_receipt()
  self.assertTrue(self.m.capture_declaration(self.fd,'uninstall',self.owner))
  self.assertEqual(self.declaration(self.other).read_bytes(),other)
 def test_interrupted_orphan_can_uninstall_through_main_entry(self):
  self.interrupt_receipt();self.m.STORE=str(self.store)
  payload=json.dumps({'wire_bridge.py':'','session.py':''}).encode()
  result=self.m.main({'operation':'uninstall','owner':self.owner,'payload':base64.b64encode(payload).decode(),'sha256':hashlib.sha256(payload).hexdigest()})
  self.assertEqual(result,{'state':'not-owned','changed':True});self.assertFalse(self.declaration().exists())
  self.assertFalse(list(self.store.glob('*.pending.json')))
 def test_interrupted_update_recovers_new_hash_without_claiming_unmanaged_work(self):
  self.install();new=self.root/'replacement';new.write_bytes(b'new');new.chmod(0o755)
  self.interrupt_receipt(new)
  self.assertFalse(self.m.capture_declaration(self.fd,'install',self.owner,str(new)))
  receipt=json.loads((self.store/('capture-'+self.owner+'.json')).read_text())
  self.assertEqual(receipt['sha256'],hashlib.sha256(self.declaration().read_bytes()).hexdigest())
 def test_interruption_before_desktop_publication_is_recoverable(self):
  original=self.m.path_write
  def interrupt(*args):raise OSError('simulated interruption before public rename')
  self.m.path_write=interrupt
  try:
   with self.assertRaises(OSError):self.install()
  finally:self.m.path_write=original
  self.assertFalse(self.declaration().exists());self.assertTrue(self.install())
 def test_interrupted_transaction_preserves_unexpected_public_content(self):
  self.interrupt_receipt();self.declaration().write_text('unrelated manual change\n')
  for operation in ['install','uninstall']:
   with self.assertRaises(ValueError):self.m.capture_declaration(self.fd,operation,self.owner,str(self.exe))
  self.assertEqual(self.declaration().read_text(),'unrelated manual change\n')
 def test_interruption_after_receipt_publication_is_idempotent(self):
  original=self.m.os.unlink;pending='capture-'+self.owner+'.pending.json'
  def interrupt(path,*args,**kwargs):
   if path==pending:raise OSError('simulated interruption before journal removal')
   return original(path,*args,**kwargs)
  self.m.os.unlink=interrupt
  try:
   with self.assertRaises(OSError):self.install()
  finally:self.m.os.unlink=original
  self.assertFalse(self.install());self.assertFalse((self.store/pending).exists())
 def test_invalid_transaction_cannot_adopt_an_unmanaged_declaration(self):
  self.interrupt_receipt();pending=self.store/('capture-'+self.owner+'.pending.json')
  value=json.loads(pending.read_text());value['path']=str(self.exe);pending.write_text(json.dumps(value))
  with self.assertRaises(ValueError):self.m.capture_declaration(self.fd,'uninstall',self.owner)
  self.assertTrue(self.declaration().exists());self.assertTrue(self.exe.exists())
 def test_interruption_inside_receipt_recovery_remains_retryable(self):
  self.interrupt_receipt();original=self.m.atomic
  def interrupt(fd,name,data,mode):
   if name=='capture-'+self.owner+'.json':raise OSError('simulated recovery receipt interruption')
   return original(fd,name,data,mode)
  self.m.atomic=interrupt
  try:
   with self.assertRaises(OSError):self.install()
  finally:self.m.atomic=original
  self.assertTrue((self.store/('capture-'+self.owner+'.pending.json')).exists())
  self.assertTrue(self.m.capture_declaration(self.fd,'uninstall',self.owner));self.assertFalse(self.declaration().exists())
 def test_interruption_inside_recovery_journal_cleanup_remains_retryable(self):
  self.interrupt_receipt();original=self.m.os.unlink;pending='capture-'+self.owner+'.pending.json'
  def interrupt(path,*args,**kwargs):
   if path==pending:raise OSError('simulated recovery journal cleanup interruption')
   return original(path,*args,**kwargs)
  self.m.os.unlink=interrupt
  try:
   with self.assertRaises(OSError):self.install()
  finally:self.m.os.unlink=original
  self.assertTrue((self.store/('capture-'+self.owner+'.json')).exists())
  self.assertFalse(self.install());self.assertFalse((self.store/pending).exists())
 def test_transaction_does_not_override_an_incompatible_receipt(self):
  self.interrupt_receipt();record=self.store/('capture-'+self.owner+'.json')
  value={'version':1,'path':str(self.declaration()),'sha256':'f'*64};record.write_text(json.dumps(value));record.chmod(0o600)
  before=self.declaration().read_bytes()
  with self.assertRaises(ValueError):self.m.capture_declaration(self.fd,'uninstall',self.owner)
  self.assertEqual(self.declaration().read_bytes(),before)
if __name__=='__main__':unittest.main()
