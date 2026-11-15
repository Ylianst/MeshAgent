"""Focused Linux wire/descriptor/barrier contracts, no real desktop required."""
import array,os,pathlib,select,socket,struct,subprocess,sys,tempfile,time,unittest,importlib.util
BRIDGE=pathlib.Path(__file__).resolve().parents[1]/'meshcore/KVM/Linux/kwin-input-bridge/wire_bridge.py'
U=struct.Struct('=I');H=struct.Struct('=II')
MAGIC=0x4d414233;REQUEST=struct.Struct('=6I');REPLY=struct.Struct('=9I')
def register_worker(pid):
 directory=pathlib.Path('/run/meshagent-kwin-workers');directory.mkdir(mode=0o755,exist_ok=True)
 def identity(p):
  fields=pathlib.Path('/proc/%d/stat'%p).read_text().rsplit(')',1)[1].split();return int(fields[1]),int(fields[19])
 parent,start=identity(pid);parent_start=identity(parent)[1]
 path=directory/str(pid);path.write_text('1 %d %d %d %d %d\n'%(pid,start,parent,parent_start,os.getuid()));path.chmod(0o644)
 return path

def packet(obj,op,*values):
 body=struct.pack('='+len(values)*'I',*values);return H.pack(obj,((8+len(body))<<16)|op)+body
CHILD=r'''
import socket,os,struct,array
s=socket.socket(fileno=int(os.environ['WAYLAND_SOCKET']));H=struct.Struct('=II')
def p(obj,op,*v):
 b=struct.pack('='+len(v)*'I',*v);return H.pack(obj,((8+len(b))<<16)|op)+b
name=b'zwp_input_method_v1\0';name+=b'\0'*((-len(name))%4)
body=struct.pack('=II',1,20)+name+struct.pack('=II',1,4)
s.sendall(p(1,1,2)+p(1,0,3)+H.pack(2,((8+len(body))<<16))+body)
buf=b'';fds=[]
while True:
 data,anc,flags,_=s.recvmsg(65536,socket.CMSG_SPACE(64*4))
 if not data:break
 for level,kind,raw in anc:
  a=array.array('i');a.frombytes(raw);fds.extend(a)
 buf+=data
 while len(buf)>=8:
  obj,word=H.unpack_from(buf);size=word>>16;op=word&65535
  if len(buf)<size:break
  body=buf[8:size];buf=buf[size:]
  if obj==4 and op==0:
   ctx=struct.unpack('=I',body)[0];s.sendall(p(ctx,9,5))
  elif obj==5 and op==4:s.sendall(H.pack(ctx,(28<<16)|11)+body)
  elif obj==7 and op==1:
   assert len(fds)==1
   fd=fds.pop(0);payload=os.read(fd,4096);os.close(fd)
   assert payload==b'fd-boundary-dummy'
   reply=os.memfd_create('dummy-reply');os.write(reply,b'fd-reply-dummy');os.lseek(reply,0,0)
   s.sendmsg([p(7,2,123)],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[reply]))]);os.close(reply)
'''
class EndpointTests(unittest.TestCase):
 def test_stale_socket_recovered_but_live_socket_and_file_retained(self):
  spec=importlib.util.spec_from_file_location('bridge',BRIDGE);bridge=importlib.util.module_from_spec(spec);spec.loader.exec_module(bridge)
  with tempfile.TemporaryDirectory() as directory:
   path=directory+'/bridge';endpoint=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);endpoint.bind(path);os.chmod(path,0o600);endpoint.listen(2)
   with self.assertRaises(ValueError):bridge.remove_stale_socket(path)
   self.assertTrue(os.path.exists(path));endpoint.close();bridge.remove_stale_socket(path);self.assertFalse(os.path.exists(path))
   pathlib.Path(path).write_text('preserve')
   with self.assertRaises(ValueError):bridge.remove_stale_socket(path)
   self.assertEqual(pathlib.Path(path).read_text(),'preserve')

class AuthorizationTests(unittest.TestCase):
 def setUp(self):
  spec=importlib.util.spec_from_file_location('bridge_auth',BRIDGE);self.bridge=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.bridge)
  self.record=register_worker(os.getpid())
 def tearDown(self):self.record.unlink(missing_ok=True)
 def test_missing_pidfd_api_rejects_worker_without_exception(self):
  from unittest.mock import patch
  with patch.object(os,'pidfd_open'):
   del os.pidfd_open
   self.assertFalse(self.bridge.worker_authorized(os.getpid(),os.getuid()))
 def test_missing_pidfd_api_rejects_server_without_exception(self):
  from unittest.mock import patch
  left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
  try:
   with patch.object(os,'pidfd_open'):
    del os.pidfd_open
    self.assertFalse(self.bridge.server_authorized(left,os.getpid()))
  finally:left.close();right.close()
 def test_registration_lifetime_fields_and_reconnect(self):
  original=self.record.read_text();values=original.split()
  self.assertTrue(self.bridge.worker_authorized(os.getpid(),os.getuid()))
  for index in [0,1,2,3,4,5]:
   changed=list(values);changed[index]=str(int(changed[index])+1);self.record.write_text(' '.join(changed))
   self.assertFalse(self.bridge.worker_authorized(os.getpid(),os.getuid()),index)
  self.record.write_text(original);self.assertTrue(self.bridge.worker_authorized(os.getpid(),os.getuid()))
 def test_passed_socket_uses_message_sender_not_original_peer(self):
  left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
  left.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
  holder=os.fork()
  if holder==0:
   left.close();right.send(b'x');right.close();os._exit(0)
  right.close()
  try:
   raw,ancillary,flags,_=left.recvmsg(1,socket.CMSG_SPACE(12))
   stale=struct.unpack('=iii',left.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[0]
   sender=struct.unpack('=iii',next(data for level,kind,data in ancillary if level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS))[0]
   self.assertEqual((raw,flags,stale,sender),(b'x',0,os.getpid(),holder))
   self.assertTrue(self.bridge.worker_authorized(stale,os.getuid()))
   self.assertFalse(self.bridge.worker_authorized(sender,os.getuid()))
  finally:left.close();os.waitpid(holder,0)
 def test_unsafe_mode_symlink_and_malformed_records(self):
  original=self.record.read_text();self.record.chmod(0o666)
  self.assertFalse(self.bridge.worker_authorized(os.getpid(),os.getuid()));self.record.chmod(0o644)
  for content in ['garbage','1 2 3',original+' 1','9'*257]:
   self.record.write_text(content);self.assertFalse(self.bridge.worker_authorized(os.getpid(),os.getuid()))
  self.record.unlink();self.record.symlink_to('/etc/passwd')
  self.assertFalse(self.bridge.worker_authorized(os.getpid(),os.getuid()))

class WireTests(unittest.TestCase):
 def setUp(self):
  self.registration=register_worker(os.getpid())
  self.tmp=tempfile.TemporaryDirectory(prefix='meshagent-wire-test-');self.parent,peer=socket.socketpair();self.parent.settimeout(2);self.buffer=b'';self.fds=[]
  env=dict(os.environ,WAYLAND_SOCKET=str(peer.fileno()),XDG_RUNTIME_DIR=self.tmp.name)
  self.proc=subprocess.Popen([sys.executable,str(BRIDGE),sys.executable,'-c',CHILD],pass_fds=[peer.fileno()],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);peer.close()
  self.assertEqual(self.read(),packet(1,1,2));self.assertEqual(self.read(),packet(1,0,3));self.assertEqual(H.unpack_from(self.read())[0],2)
  self.parent.sendall(packet(3,0,1)+packet(1,1,3)+packet(4,0,0xff000001));self.assertEqual(self.read(),packet(0xff000001,9,5))
 def tearDown(self):
  self.parent.close()
  try:self.proc.communicate(timeout=3)
  except subprocess.TimeoutExpired:self.proc.kill();self.proc.communicate();self.fail('Relay failed to exit after EOF')
  for fd in self.fds:os.close(fd)
  self.tmp.cleanup();self.registration.unlink(missing_ok=True)
 def read(self):
  while True:
   if len(self.buffer)>=8:
    _,word=H.unpack_from(self.buffer);size=word>>16
    if len(self.buffer)>=size:out,self.buffer=self.buffer[:size],self.buffer[size:];return out
   data,anc,flags,_=self.parent.recvmsg(65536,socket.CMSG_SPACE(64*4));self.assertTrue(data)
   for level,kind,raw in anc:
    self.assertEqual((level,kind),(socket.SOL_SOCKET,socket.SCM_RIGHTS));a=array.array('i');a.frombytes(raw);self.fds.extend(a)
   self.buffer+=data
 def control(self,want,nonce=123):
  s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(1);s.connect(self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock');s.send(REQUEST.pack(MAGIC,nonce,*want));return s
 def modifiers(self,mask):
  values=(mask,0,0,0) if isinstance(mask,int) else mask
  raw=packet(5,4,55,*values);self.parent.sendall(raw)
  self.assertEqual(self.read(),packet(0xff000001,11,55,*values));self.assertEqual(self.read(),packet(1,0,3))
 def finish(self):self.parent.sendall(packet(3,0,77)+packet(1,1,3))
 def expect_reply(self,c,values,status=1,nonce=123):
  reply=REPLY.unpack(c.recv(REPLY.size));self.assertEqual(reply[:3],(MAGIC,nonce,status));self.assertNotEqual(reply[3:5],(0,0));self.assertEqual(reply[5:],values)

 def epoch(self):
  self.modifiers(4);self.finish()
  with self.control((4,0,0,0),nonce=0) as c:
   self.assertEqual(self.read(),packet(1,0,3));self.finish();reply=REPLY.unpack(c.recv(REPLY.size))
   self.assertEqual(reply[:3],(MAGIC,0,3));return reply[3]|(reply[4]<<32)
 def input_request(self,epoch,op,key,pressed):
  c=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);c.settimeout(1);c.connect(self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock')
  c.send(struct.pack('=12I',MAGIC,789,op,key,pressed,1234,4,0,0,0,epoch&0xffffffff,epoch>>32));return c
 def test_forwarded_key_is_ordered_with_modifiers_and_fresh_ack(self):
  epoch=self.epoch()
  for pressed in [1,0]:
   with self.input_request(epoch,0x4b455931,30,pressed) as c:
    self.assertEqual(self.read(),packet(0xff000001,11,0,4,0,0,0))
    self.assertEqual(self.read(),packet(0xff000001,10,0,1234,30,pressed));self.assertEqual(self.read(),packet(1,0,3))
    self.assertFalse(select.select([c],[],[],.03)[0]);self.finish();self.expect_reply(c,(4,0,0,0),status=4,nonce=789)
 def test_unregistered_same_uid_cannot_inject_or_request_modifier_barrier(self):
  epoch=self.epoch();path=self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock'
  packets=[REQUEST.pack(MAGIC,123,4,0,0,0),struct.pack('=12I',MAGIC,789,0x54585431,0x4e2d,0,1234,4,0,0,0,epoch&0xffffffff,epoch>>32)]
  for raw in packets:
   child=subprocess.run([sys.executable,'-c',"import socket,sys;s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.connect(sys.argv[1]);s.send(bytes.fromhex(sys.argv[2]));assert s.recv(100)==b''",path,raw.hex()],timeout=2)
   self.assertEqual(child.returncode,0)
  self.assertFalse(select.select([self.parent],[],[],.05)[0])
 def test_revoked_registration_cannot_inject(self):
  epoch=self.epoch();self.registration.unlink()
  with self.input_request(epoch,0x54585431,0x4e2d,0) as peer:self.assertEqual(peer.recv(100),b'')
  self.assertFalse(select.select([self.parent],[],[],.05)[0])
 def test_unicode_uses_ordered_standard_keysym_pair(self):
  epoch=self.epoch()
  with self.input_request(epoch,0x54585431,0x4e2d,0) as c:
   self.assertEqual(self.read(),packet(0xff000001,11,0,4,0,0,0))
   self.assertEqual(self.read(),packet(0xff000001,8,0,1234,0x01004e2d,1,0))
   self.assertEqual(self.read(),packet(0xff000001,8,0,1234,0x01004e2d,0,0));self.assertEqual(self.read(),packet(1,0,3));self.finish();self.expect_reply(c,(4,0,0,0),status=4,nonce=789)
 def test_stock_text_commit_retains_current_serial_and_commit_protocol(self):
  epoch=self.epoch();self.parent.sendall(packet(0xff000001,4,99))
  with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as c:
   c.settimeout(1);c.connect(self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock')
   stamp=int(time.monotonic()*1000)&0xffffffff
   c.send(struct.pack('=12I',MAGIC,789,0x434d5431,0x4e2d,0,stamp,4,0,0,0,epoch&0xffffffff,epoch>>32))
   text='中'.encode()+b'\0';body=struct.pack('=II',99,len(text))+text
   self.assertEqual(self.read(),H.pack(0xff000001,((len(body)+8)<<16)|1)+body)
   self.assertEqual(self.read(),packet(1,0,3));self.finish();self.expect_reply(c,(4,0,0,0),status=4,nonce=789)
 def test_stale_context_epoch_and_invalid_unicode_deliver_nothing(self):
  epoch=self.epoch()
  for old,op,key in [(epoch^1,0x4b455931,30),(epoch,0x54585431,0xd800)]:
   with self.input_request(old,op,key,1) as c:self.assertEqual(c.recv(100),b'')
  self.assertFalse(select.select([self.parent],[],[],.03)[0])
 def test_input_worker_exit_releases_only_its_forwarded_key(self):
  epoch=self.epoch();path=self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock'
  raw=struct.pack('=12I',MAGIC,789,0x4b455931,30,1,1234,4,0,0,0,epoch&0xffffffff,epoch>>32)
  child=subprocess.Popen([sys.executable,'-c','import socket,sys;sys.stdin.read(1);s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.connect(sys.argv[1]);s.send(bytes.fromhex(sys.argv[2]));assert len(s.recv(100))==36',path,raw.hex()],stdin=subprocess.PIPE)
  registration=register_worker(child.pid);child.stdin.write(b'1');child.stdin.flush();child.stdin.close()
  try:
   self.assertEqual(self.read(),packet(0xff000001,11,0,4,0,0,0));self.assertEqual(self.read(),packet(0xff000001,10,0,1234,30,1));self.assertEqual(self.read(),packet(1,0,3));self.finish();self.assertEqual(child.wait(timeout=2),0)
   release=self.read();self.assertEqual(H.unpack_from(release),(0xff000001,(24<<16)|10));self.assertEqual(struct.unpack('=4I',release[8:])[2:],(30,0))
  finally:
   if child.poll() is None:child.kill();child.wait()
   registration.unlink(missing_ok=True)
 def test_ack_waits_for_compositor_roundtrip_and_private_id_stays_private(self):
  self.modifiers(4)
  with self.control((4,0,0,0)) as c:
   self.assertFalse(select.select([c],[],[],.05)[0],'Acknowledged before compositor callback')
   self.finish();self.assertEqual(self.read(),packet(1,0,3));self.finish();self.expect_reply(c,(4,0,0,0))
  self.modifiers(0)
  with self.control((0,0,0,0)) as c:
   self.finish();self.assertEqual(self.read(),packet(1,0,3));self.finish();self.expect_reply(c,(0,0,0,0))
 def test_opaque_fragmented_message_and_descriptors_roundtrip(self):
  raw=packet(7,1,99);fd=os.memfd_create('dummy');os.write(fd,b'fd-boundary-dummy');os.lseek(fd,0,0)
  try:self.parent.sendmsg([raw[:3]],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))]);self.parent.sendall(raw[3:])
  finally:os.close(fd)
  self.assertEqual(self.read(),packet(7,2,123));self.assertEqual(len(self.fds),1);self.assertEqual(os.read(self.fds[0],4096),b'fd-reply-dummy')
 def test_wrong_mask_times_out_without_false_ack(self):
  self.modifiers(4);self.finish()
  start=time.monotonic()
  with self.control((2,0,0,0)) as c:self.assertEqual(c.recv(REPLY.size),b'')
  self.assertLess(time.monotonic()-start,.9)
 def test_all_modifier_masks_and_nonce_are_preserved(self):
  values=(4,2,1,3);self.modifiers(values)
  with self.control(values,nonce=0x12345678) as c:
   self.finish();self.assertEqual(self.read(),packet(1,0,3));self.finish();self.expect_reply(c,values,nonce=0x12345678)
 def test_inactive_grab_requires_fresh_compositor_sync(self):
  self.parent.sendall(packet(4,1,0xff000001))
  with self.control((4,0,0,0)) as c:
   self.assertEqual(self.read(),packet(1,0,3));self.assertFalse(select.select([c],[],[],.05)[0]);self.finish();self.expect_reply(c,(4,0,0,0),status=2)
 def test_invalid_control_does_not_disconnect_stock_input_method(self):
  c=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);c.settimeout(1);c.connect(self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock');c.send(REQUEST.pack(0,123,0,0,0,0));self.assertEqual(c.recv(100),b'');c.close()
  self.modifiers(4);self.finish()

class ProtocolBoundaryTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  spec=importlib.util.spec_from_file_location('meshagent_ime_wire',BRIDGE);cls.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.module)
 def test_old_context_callback_cannot_publish_stale_modifiers(self):
  emitted=[];p=self.module.Protocol(emitted.append);p.methods.add(4);p.contexts.add(12);p.active.add(12);p.grabs[5]=12;p.latest=(4,0,0,0);p.reserved=3;p.available=True;p.request_sync();p.schedule();self.assertEqual(emitted,[packet(1,0,3)])
  p.process(packet(4,1,12),False);p.process(packet(3,0,99),False);self.assertIsNone(p.ack);self.assertEqual(p.completed,0)
 def test_truncated_ancillary_closes_received_descriptors(self):
  descriptor=os.memfd_create('dummy-truncation')
  class Fake:
   def setblocking(self,value):pass
   def recvmsg(self,*args):return b'x',[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[descriptor]).tobytes())],socket.MSG_CTRUNC,None
   def close(self):pass
  c=self.module.Channel(Fake())
  with self.assertRaises(ValueError):c.read()
  with self.assertRaises(OSError):os.fstat(descriptor)
  c.close()

class HeadlessWireTests(unittest.TestCase):
 """Use the real owned child against a small compositor protocol fixture."""
 read=WireTests.read
 tearDown=WireTests.tearDown
 control=WireTests.control
 finish=WireTests.finish
 expect_reply=WireTests.expect_reply
 def setUp(self):
  self.registration=register_worker(os.getpid())
  self.tmp=tempfile.TemporaryDirectory(prefix='meshagent-headless-test-');self.parent,peer=socket.socketpair();self.parent.settimeout(2);self.buffer=b'';self.fds=[]
  env=dict(os.environ,WAYLAND_SOCKET=str(peer.fileno()),XDG_RUNTIME_DIR=self.tmp.name)
  self.proc=subprocess.Popen([sys.executable,str(BRIDGE)],pass_fds=[peer.fileno()],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);peer.close()
  self.assertEqual(self.read(),packet(1,1,2));self.assertEqual(self.read(),packet(1,0,3))
  name=b'zwp_input_method_v1\0';name+=b'\0'*((-len(name))%4)
  body=struct.pack('=II',1,20)+name+U.pack(1)
  self.parent.sendall(H.pack(2,((len(body)+8)<<16))+body+packet(3,0,1)+packet(1,1,3))
  bound=self.read();self.assertEqual(H.unpack_from(bound)[0],2);self.assertEqual(U.unpack_from(bound,len(bound)-4)[0],4)
  self.parent.sendall(packet(4,0,0xff000001)+packet(0xff000001,4,99))
 def epoch(self):
  with self.control((0,0,0,0),nonce=0) as c:
   self.assertEqual(self.read(),packet(1,0,3));self.finish();reply=REPLY.unpack(c.recv(REPLY.size))
   self.assertEqual(reply[:3],(MAGIC,0,7));return reply[3]|(reply[4]<<32)
 def test_no_keyboard_grab_or_modifier_interposition(self):
  self.assertFalse(select.select([self.parent],[],[],.04)[0])
  self.epoch()
 def test_active_context_without_serial_reports_pending_not_ready(self):
  self.parent.sendall(packet(4,1,0xff000001))
  self.assertEqual(self.read(),packet(0xff000001,0))
  self.parent.sendall(packet(4,0,0xff000002))
  with self.control((0,0,0,0),nonce=0) as c:
   self.assertEqual(self.read(),packet(1,0,3));self.finish()
   reply=REPLY.unpack(c.recv(REPLY.size))
   self.assertEqual(reply[:3],(MAGIC,0,8))
  self.assertFalse(select.select([self.parent],[],[],.03)[0])
 def test_owned_unicode_shares_keyboard_event_route_with_return(self):
  epoch=self.epoch()
  for scalar,symbol in [(0x41,0x41),(0xe9,0xe9),(0x3a9,0x010003a9),(0x4e2d,0x01004e2d),(0x1f98a,0x0101f98a)]:
   with self.subTest(scalar=scalar),socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as c:
    c.settimeout(1);c.connect(self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock')
    stamp=int(time.monotonic()*1000)&0xffffffff
    c.send(struct.pack('=12I',MAGIC,789,0x434d5431,scalar,0,stamp,4,0,0,0,epoch&0xffffffff,epoch>>32))
    self.assertEqual(self.read(),packet(0xff000001,8,99,stamp,symbol,1,0))
    self.assertEqual(self.read(),packet(0xff000001,8,99,stamp,symbol,0,0))
    self.assertEqual(self.read(),packet(1,0,3));self.assertFalse(select.select([c],[],[],.03)[0])
    self.finish();self.expect_reply(c,(4,0,0,0),status=4,nonce=789)
 def test_owned_control_values_retain_existing_commit_semantics(self):
  epoch=self.epoch()
  for scalar in [0x7f,0x85]:
   with self.subTest(scalar=scalar),socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as c:
    c.settimeout(1);c.connect(self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock')
    stamp=int(time.monotonic()*1000)&0xffffffff
    c.send(struct.pack('=12I',MAGIC,789,0x434d5431,scalar,0,stamp,0,0,0,0,epoch&0xffffffff,epoch>>32))
    text=chr(scalar).encode()+b'\0';body=struct.pack('=II',99,len(text))+text+b'\0'*(-len(text)%4)
    self.assertEqual(self.read(),H.pack(0xff000001,((len(body)+8)<<16)|1)+body)
    self.assertEqual(self.read(),packet(1,0,3));self.finish();self.expect_reply(c,(0,0,0,0),status=4,nonce=789)
 def test_unregistered_same_uid_cannot_inject_owned_unicode(self):
  epoch=self.epoch();path=self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock'
  stamp=int(time.monotonic()*1000)&0xffffffff
  raw=struct.pack('=12I',MAGIC,789,0x434d5431,0x4e2d,0,stamp,0,0,0,0,epoch&0xffffffff,epoch>>32)
  child=subprocess.run([sys.executable,'-c',"import socket,sys;s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.connect(sys.argv[1]);s.send(bytes.fromhex(sys.argv[2]));assert s.recv(100)==b''",path,raw.hex()],timeout=2)
  self.assertEqual(child.returncode,0);self.assertFalse(select.select([self.parent],[],[],.05)[0])
 def test_legacy_protocol_rejected_even_for_registered_worker(self):
  epoch=self.epoch();path=self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock'
  stamp=int(time.monotonic()*1000)&0xffffffff
  requests=[struct.pack('=6I',0x4d414231,0,0,0,0,0),
   struct.pack('=6I',0x4d414231,123,0,0,0,0),
   struct.pack('=12I',0x4d414231,789,0x434d5431,0x4e2d,0,stamp,0,0,0,0,epoch&0xffffffff,epoch>>32)]
  for raw in requests:
   with self.subTest(bytes=len(raw)),socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as peer:
    peer.settimeout(1);peer.connect(path);peer.send(raw)
    self.assertEqual(peer.recv(100),b'');self.assertFalse(select.select([self.parent],[],[],.03)[0])
 def test_expired_commit_is_rejected_before_injection(self):
  epoch=self.epoch()
  with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as c:
   c.settimeout(1);c.connect(self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock')
   stamp=(int(time.monotonic()*1000)-2000)&0xffffffff
   c.send(struct.pack('=12I',MAGIC,789,0x434d5431,0x4e2d,0,stamp,0,0,0,0,epoch&0xffffffff,epoch>>32))
   self.assertEqual(c.recv(1),b'');self.assertFalse(select.select([self.parent],[],[],.03)[0])
 def test_owned_stale_epoch_and_invalid_scalar_deliver_nothing(self):
  epoch=self.epoch()
  for expected_epoch,scalar in [(epoch^1,0x41),(epoch,0x1f),(epoch,0xd800),(epoch,0x110000)]:
   with self.subTest(scalar=scalar),socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as c:
    c.settimeout(1);c.connect(self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock')
    stamp=int(time.monotonic()*1000)&0xffffffff
    c.send(struct.pack('=12I',MAGIC,789,0x434d5431,scalar,0,stamp,0,0,0,0,expected_epoch&0xffffffff,expected_epoch>>32))
    self.assertEqual(c.recv(1),b'');self.assertFalse(select.select([self.parent],[],[],.03)[0])
 def test_replaced_owned_context_rejects_previous_epoch(self):
  epoch=self.epoch();self.parent.sendall(packet(4,1,0xff000001))
  self.assertEqual(self.read(),packet(0xff000001,0))
  self.parent.sendall(packet(4,0,0xff000002)+packet(0xff000002,4,101))
  with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as c:
   c.settimeout(1);c.connect(self.tmp.name+'/meshagent-ime-bridge.'+str(os.getpid())+'.sock')
   stamp=int(time.monotonic()*1000)&0xffffffff
   c.send(struct.pack('=12I',MAGIC,789,0x434d5431,0x41,0,stamp,0,0,0,0,epoch&0xffffffff,epoch>>32))
   self.assertEqual(c.recv(1),b'');self.assertFalse(select.select([self.parent],[],[],.03)[0])
 def test_deactivation_destroys_only_its_context(self):
  self.parent.sendall(packet(4,1,0xff000001));self.assertEqual(self.read(),packet(0xff000001,0))

class ContextRetirementTests(unittest.TestCase):
 def test_destroy_retires_context_and_serial_without_waiting_for_delete_id(self):
  spec=importlib.util.spec_from_file_location('wire_retirement',BRIDGE);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  p=m.Protocol(lambda raw:None);p.methods.add(4);context=0xff000001
  p.process(packet(4,0,context),False);p.process(packet(context,4,99),False)
  p.process(packet(4,1,context),False);p.process(packet(context,0),True)
  self.assertNotIn(context,p.contexts);self.assertNotIn(context,p.serials);self.assertNotIn(context,p.active)
if __name__=='__main__':unittest.main()
