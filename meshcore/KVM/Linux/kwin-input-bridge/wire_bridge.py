#!/usr/bin/python3
"""Agent-owned Wayland input-method-v1 relay; no KWin C++ ABI or input logging.

An existing vendor IME remains the child client, with messages and SCM_RIGHTS
passed through. An empty original selection uses headless_method(), which does
not grab the keyboard or create surfaces. Only the small protocol subset needed
for context identity, modifier ordering and completion is inspected here.

The local native-endian control records are paired with linux_kvm_eis.c. They
are not a network protocol: caller UID, nonce, context epoch and deadlines must
be checked before dispatch, and ambiguous requests must never be replayed.
"""
import array
import collections
import os
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

# Root-issued registrations contain public identity, never a bearer secret.
WORKERS = '/run/meshagent-kwin-workers'

def process_identity(pid):
    with open('/proc/%d/stat' % pid) as source:
        fields = source.read().rsplit(')', 1)[1].split()
    return int(fields[1]), int(fields[19])

def trusted_path(path):
    path = os.path.realpath(path)
    while True:
        info = os.stat(path)
        if info.st_uid != 0 or info.st_mode & 0o022:
            return False
        if path == '/':
            return True
        path = os.path.dirname(path)

def server_authorized(peer, compositor):
    pidfd_open = getattr(os, 'pidfd_open', None)
    if pidfd_open is None:
        return False
    pins = []
    try:
        pid, uid, _ = struct.unpack('=iii', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.getuid() or pid <= 0 or compositor <= 0:
            return False
        pins.append(pidfd_open(pid))
        pins.append(pidfd_open(compositor))
        before = process_identity(pid)
        script = '/usr/local/lib/meshagent-kwin-wire/wire_bridge.py'
        if before[0] != compositor or not trusted_path(script) or not trusted_path('/usr/bin/python3'):
            return False
        with open('/proc/%d/cmdline' % pid, 'rb') as source:
            args = source.read(4096).split(b'\0')
        if args[:3] != [b'/usr/bin/python3', b'-I', script.encode()]:
            return False
        if os.readlink('/proc/%d/exe' % pid) != os.path.realpath('/usr/bin/python3'):
            return False
        return process_identity(pid) == before and not select.select(pins, [], [], 0)[0]
    except (OSError, ValueError, IndexError):
        return False
    finally:
        for fd in pins:
            os.close(fd)

# Authorization is a live kernel-peer-to-root-record match, not possession of an
# epoch or a successful readiness probe. Pin worker and parent lifetimes; absent
# pidfd support, stale/malformed records and UID 0 do not authorize input.
def worker_authorized(pid, uid):
    pidfd_open = getattr(os, 'pidfd_open', None)
    if pidfd_open is None:
        return False
    directory = record = None
    pins = []
    try:
        if not trusted_path('/run'):
            return False
        directory = os.open(WORKERS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_mode & 0o022:
            return False
        record = os.open(str(pid), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(record)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 256:
            return False
        values = os.read(record, 257).decode('ascii').split()
        if len(values) != 6 or any(not value.isdecimal() for value in values):
            return False
        version, worker, start, parent, parent_start, expected_uid = map(int, values)
        if version != 1 or worker != pid or expected_uid != uid or parent <= 0:
            return False
        pins.append(pidfd_open(pid))
        pins.append(pidfd_open(parent))
        if process_identity(pid) != (parent, start) or process_identity(parent)[1] != parent_start:
            return False
        with open('/proc/%d/status' % parent) as status:
            identities = next(line.split()[1:] for line in status if line.startswith('Uid:'))
        if identities != ['0', '0', '0', '0']:
            return False
        return not select.select(pins, [], [], 0)[0]
    except (OSError, ValueError, UnicodeError, IndexError, StopIteration):
        return False
    finally:
        for fd in pins:
            os.close(fd)
        if record is not None:
            os.close(record)
        if directory is not None:
            os.close(directory)

HEADER = struct.Struct('=II')
WORD = struct.Struct('=I')
REQUEST = struct.Struct('=6I')
REPLY = struct.Struct('=9I')
# Keep session.py and linux_kvm_eis.c synchronized. This version excludes
# running pre-authorization relays; the magic itself does not authorize peers.
MAGIC = 0x4d414233
MAX_BYTES = 1024 * 1024
MAX_FDS = 128
MAX_OBJECTS = 128
CONTROL_TIMEOUT = .3


def message(obj, opcode, *values):
    body = struct.pack('=' + 'I' * len(values), *values)
    return HEADER.pack(obj, ((len(body) + 8) << 16) | opcode) + body


class Channel:
    """Bounded Wayland byte/FD queues; ancillary descriptors remain owned here
    until forwarded or closed. Do not detach FDs from their message ordering.
    """
    def __init__(self, connection):
        self.socket = connection
        connection.setblocking(False)
        self.buffer = bytearray()
        self.fds = []
        self.output = collections.deque()
        self.bytes = 0
        self.queued_fds = 0

    def enqueue(self, data, fds=()):
        if not data:
            raise ValueError('Descriptors require stream bytes')
        if self.bytes + len(data) > MAX_BYTES or self.queued_fds + len(fds) > MAX_FDS:
            raise ValueError('Relay output limit')
        self.output.append([data, list(fds)])
        self.bytes += len(data)
        self.queued_fds += len(fds)

    def flush(self):
        if not self.output:
            return
        data, fds = self.output[0]
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))] if fds else []
        try:
            size = self.socket.sendmsg([data], ancillary, socket.MSG_NOSIGNAL)
        except BlockingIOError:
            return
        if not size:
            raise EOFError()
        for descriptor in fds:
            os.close(descriptor)
        self.queued_fds -= len(fds)
        self.bytes -= size
        self.output[0] = [data[size:], []]
        if size == len(data):
            self.output.popleft()

    def read(self):
        data, ancillary, flags, _ = self.socket.recvmsg(
            65536, socket.CMSG_SPACE(MAX_FDS * 4), socket.MSG_CMSG_CLOEXEC)
        received = []
        try:
            for level, kind, raw in ancillary:
                if (level, kind) != (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                    raise ValueError('Unexpected ancillary data')
                descriptors = array.array('i')
                descriptors.frombytes(raw[:len(raw) // 4 * 4])
                received.extend(descriptors)
            if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
                raise ValueError('Truncated ancillary data')
            if not data:
                raise EOFError()
            if len(self.buffer) + len(data) > MAX_BYTES or len(self.fds) + len(received) > MAX_FDS:
                raise ValueError('Relay input limit')
            self.buffer.extend(data)
            self.fds.extend(received)
            received = []
        finally:
            for descriptor in received:
                os.close(descriptor)

    def pop(self):
        if len(self.buffer) < HEADER.size:
            return None
        _, word = HEADER.unpack_from(self.buffer)
        size = word >> 16
        if size < HEADER.size or size % 4:
            raise ValueError('Invalid Wayland message size')
        if len(self.buffer) < size:
            return None
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def close(self):
        for descriptor in self.fds:
            os.close(descriptor)
        self.fds = []
        for _, descriptors in self.output:
            for descriptor in descriptors:
                os.close(descriptor)
        self.output.clear()
        self.socket.close()


class Protocol:
    """Observe IME objects without replacing the vendor's protocol handling.

    A reserved freed object ID belongs only to our sync callbacks; the child
    never sees its delete_id and cannot reuse it. Context generation invalidates
    an outstanding completion after deactivation/replacement. A completed sync
    proves protocol ordering, not that an application accepted the text.
    """
    def __init__(self, send_parent):
        self.send_parent = send_parent
        self.registries = set()
        self.methods = set()
        self.contexts = set()
        self.serials = {}
        self.active = set()
        self.grabs = {}
        self.reserved = None
        self.available = False
        self.generation = 0
        self.latest = None
        self.inflight = None
        self.wanted = False
        self.sent = 0
        self.completed = 0
        self.ack = None
        self.direct = False

    def invalidate(self):
        self.generation += 1
        self.latest = None
        self.ack = None
        self.direct = False

    def has_grab(self):
        return any(context in self.active for context in self.grabs.values())

    def request_sync(self):
        minimum = self.sent + 1
        self.wanted = True
        return minimum

    def schedule(self):
        if not self.wanted or not self.available or not self.methods:
            return
        # An active grab needs a real modifier request from its stock IME.
        if self.has_grab() and self.latest is None:
            return
        self.sent += 1
        self.inflight = (self.generation, self.latest, not self.has_grab(), self.sent)
        self.available = False
        self.wanted = False
        self.send_parent(message(1, 0, self.reserved))

    def process(self, raw, to_parent):
        obj, word = HEADER.unpack_from(raw)
        opcode = word & 65535
        body = raw[8:]
        if to_parent:
            if obj == 1 and opcode == 1 and len(body) == 4:
                self.registries.add(WORD.unpack(body)[0])
            elif obj in self.registries and opcode == 0 and len(body) >= 16:
                length = WORD.unpack_from(body, 4)[0]
                end = 8 + ((length + 3) // 4) * 4
                if 0 < length <= 256 and end + 8 == len(body):
                    interface = body[8:8 + length - 1]
                    version, new = struct.unpack_from('=II', body, end)
                    if interface == b'zwp_input_method_v1' and version >= 1:
                        self.methods.add(new)
            elif obj in self.contexts:
                if opcode == 9 and len(body) == 4:
                    self.grabs[WORD.unpack(body)[0]] = obj
                elif opcode == 11 and len(body) == 20 and obj in self.active:
                    self.latest = struct.unpack('=IIIII', body)[1:]
                    self.wanted = True
                elif opcode == 0 and not body:
                    self.contexts.discard(obj)
                    self.serials.pop(obj, None)
                    self.active.discard(obj)
                    self.invalidate()
        else:
            if obj == 1 and opcode == 1 and len(body) == 4:
                dead = WORD.unpack(body)[0]
                self.registries.discard(dead)
                self.methods.discard(dead)
                self.contexts.discard(dead)
                self.serials.pop(dead, None)
                if dead in self.active:
                    self.active.discard(dead)
                    self.invalidate()
                self.grabs.pop(dead, None)
                if self.reserved is None and 1 < dead < 0xff000000:
                    # The child never receives delete_id, so its allocator
                    # cannot reuse this slot. Only our callbacks use it.
                    self.reserved = dead
                    self.available = True
                    return False
                if dead == self.reserved:
                    self.available = True
                    return False
            elif self.reserved is not None and obj == self.reserved:
                if opcode != 0 or len(body) != 4 or self.inflight is None:
                    raise ValueError('Unexpected private callback')
                generation, snapshot, direct, counter = self.inflight
                self.inflight = None
                if generation == self.generation:
                    self.ack = snapshot
                    self.direct = direct
                    self.completed = counter
                return False
            elif obj in self.methods:
                if opcode == 0 and len(body) == 4:
                    context = WORD.unpack(body)[0]
                    self.contexts.add(context)
                    self.active.add(context)
                    self.invalidate()
                elif opcode == 1 and len(body) == 4:
                    self.active.discard(WORD.unpack(body)[0])
                    self.invalidate()
            elif obj in self.contexts and opcode == 4 and len(body) == 4:
                self.serials[obj] = WORD.unpack(body)[0]
        if any(len(x) > MAX_OBJECTS for x in [self.registries, self.methods, self.contexts, self.grabs]):
            raise ValueError('Protocol object limit')
        return True



def remove_stale_socket(path):
    """Recover our UID's abandoned endpoint without replacing a live peer."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('Unsafe existing bridge endpoint')
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as probe:
        probe.settimeout(.1)
        try:
            probe.connect(path)
        except ConnectionRefusedError:
            if os.lstat(path).st_ino == info.st_ino:
                os.unlink(path)
            return
    raise ValueError('Bridge endpoint is already active')


def headless_method():
    """Standard input-method-v1 client for an originally empty IM selection.

    No surfaces, keyboard grab, input source changes or text logging. Existing
    physical/EIS keys remain untouched. The parent handles authenticated text
    commits and retains all delivery/ownership checks.
    """
    channel = Channel(socket.socket(fileno=int(os.environ['WAYLAND_SOCKET'])))
    registry, callback, next_id = 2, 3, 4
    method = None
    contexts = set()
    channel.enqueue(message(1, 1, registry))
    channel.enqueue(message(1, 0, callback))
    try:
        while True:
            readable, writable, _ = select.select([channel.socket], [channel.socket] if channel.output else [], [])
            if channel.socket in readable:
                channel.read()
                # Only keymap descriptors are delivered to this client. It does
                # not need to map them; KWin retains its authoritative keymap.
                for descriptor in channel.fds:
                    os.close(descriptor)
                channel.fds = []
                while (raw := channel.pop()) is not None:
                    obj, word = HEADER.unpack_from(raw)
                    opcode, body = word & 65535, raw[8:]
                    if obj == 1 and opcode == 0:
                        raise ValueError('Input-method compositor protocol error')
                    if obj == registry and opcode == 0:
                        if len(body) < 12:
                            raise ValueError('Invalid input-method global')
                        name, length = struct.unpack_from('=II', body)
                        end = 8 + (length + 3) // 4 * 4
                        if not 0 < length <= 256 or end + 4 != len(body) or body[8 + length - 1] != 0:
                            raise ValueError('Invalid input-method global name')
                        if body[8:8 + length - 1] == b'zwp_input_method_v1' and method is None:
                            if WORD.unpack_from(body, end)[0] < 1:
                                raise ValueError('Unsupported input-method global')
                            method, next_id = next_id, next_id + 1
                            bind = struct.pack('=II', name, length) + body[8:end] + struct.pack('=II', 1, method)
                            channel.enqueue(HEADER.pack(registry, ((len(bind) + 8) << 16)) + bind)
                    elif obj == method and opcode in (0, 1):
                        if len(body) != 4:
                            raise ValueError('Invalid input-method context')
                        context = WORD.unpack(body)[0]
                        if opcode == 0:
                            if context in contexts or len(contexts) >= 16 or next_id >= 0xff000000:
                                raise ValueError('Input-method context limit')
                            contexts.add(context)
                        elif context in contexts:
                            channel.enqueue(message(context, 0))
                            contexts.remove(context)
            if channel.socket in writable:
                channel.flush()
    finally:
        channel.close()


def main(command):
    """Serve one compositor incarnation and release each worker's owned keys.

    HELLO statuses 3/6/7 describe grab, stock no-grab, and owned commit routes.
    Status 8 is owned commit support without the current text-state serial;
    the native caller must refresh that state before sending its first scalar.
    pidfds prevent a dead worker's held keys surviving a live relay.
    """
    owned_headless = not command
    if not command:
        command = ['/usr/bin/python3', '-I', os.path.realpath(__file__), '--headless-input-method']
    if not os.path.isabs(command[0]):
        raise ValueError('Absolute stock input-method command required')
    runtime = os.environ['XDG_RUNTIME_DIR']
    info = os.lstat(runtime)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Unsafe runtime directory')
    parent = child = listener = process = far = None
    peers = {}
    peers_deadlines = {}
    peer_pids = {}
    owners = {}
    held = {}
    path = runtime + '/meshagent-ime-bridge.' + str(os.getppid()) + '.sock'
    identity = None
    epoch = secrets.randbits(64) or 1
    try:
        parent = Channel(socket.socket(fileno=int(os.environ['WAYLAND_SOCKET'])))
        near, far = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        child = Channel(near)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        remove_stale_socket(path)
        listener.bind(path)
        os.chmod(path, 0o600)
        identity = os.lstat(path).st_ino
        listener.listen(8)
        listener.setblocking(False)
        env = dict(os.environ, WAYLAND_SOCKET=str(far.fileno()))
        process = subprocess.Popen(command, env=env, pass_fds=[far.fileno()])
        far.close()
        far = None
        protocol = Protocol(parent.enqueue)

        def relay(source, destination, to_parent):
            source.read()
            while (raw := source.pop()) is not None:
                if protocol.process(raw, to_parent):
                    destination.enqueue(raw, source.fds)
                    source.fds = []
                # Modifier requests precede their injected sync in this queue.
                protocol.schedule()

        while process.poll() is None:
            now = time.monotonic()
            for peer, request in list(peers.items()):
                if request is not None:
                    nonce, wanted, minimum, deadline, key_request = request
                    status = 0
                    if protocol.completed >= minimum:
                        if nonce == 0:
                            status = (7 if owned_headless else 6) if protocol.direct else 3
                            # Older KWin can activate a newly bound method
                            # before adopting its text state. Tell the native
                            # caller to request that state before sending text.
                            if owned_headless and len(protocol.active) == 1 and not protocol.active.issubset(protocol.serials):
                                status = 8
                        elif key_request == 2:
                            status = 4
                        elif protocol.direct:
                            status = 2
                        elif protocol.ack == wanted:
                            status = 4 if key_request else 1
                    if status:
                        try:
                            peer.send(REPLY.pack(MAGIC, nonce, status, (epoch ^ protocol.generation) & 0xffffffff, (epoch ^ protocol.generation) >> 32, *(protocol.ack or (0, 0, 0, 0) if nonce == 0 else wanted)))
                        except OSError:
                            pass
                        peer.close()
                        del peers[peer]
                        peer_pids.pop(peer, None)
                        continue
                else:
                    deadline = peers_deadlines[peer]
                if now >= deadline:
                    peer.close()
                    del peers[peer]
                    peer_pids.pop(peer, None)
                    peers_deadlines.pop(peer, None)
            readers = [parent.socket, child.socket, listener] + [p for p, request in peers.items() if request is None] + list(owners.values())
            writers = [c.socket for c in [parent, child] if c.output]
            ready, writable, _ = select.select(readers, writers, [], .025)
            for connection in ready:
                if connection is listener:
                    peer, _ = listener.accept()
                    peer.setblocking(False)
                    peer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                    pid, uid, _ = struct.unpack('=iii', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid not in (0, os.getuid()) or len(peers) >= 8:
                        peer.close()
                    else:
                        peers[peer] = None
                        peer_pids[peer] = pid
                        peers_deadlines[peer] = time.monotonic() + CONTROL_TIMEOUT
                elif isinstance(connection, int):
                    dead = next((pid for pid, descriptor in owners.items() if descriptor == connection), None)
                    if dead is not None:
                        for identity, (context, generation) in list(held.items()):
                            if identity[0] == dead:
                                if context in protocol.active and generation == protocol.generation:
                                    parent.enqueue(message(context, 10, 0, int(time.monotonic() * 1000) & 0xffffffff, identity[1], 0))
                                del held[identity]
                        os.close(owners.pop(dead))
                elif connection is parent.socket:
                    relay(parent, child, False)
                elif connection is child.socket:
                    relay(child, parent, True)
                else:
                    raw, ancillary, flags, _ = connection.recvmsg(49, socket.CMSG_SPACE(struct.calcsize('=iii')),
                                                                  socket.MSG_CMSG_CLOEXEC)
                    key_request = len(raw) == 48
                    probe = raw == REQUEST.pack(MAGIC, 0, 0, 0, 0, 0)
                    credentials = []
                    unexpected = False
                    for level, kind, data in ancillary:
                        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                            fds = array.array('i')
                            fds.frombytes(data[:len(data) // fds.itemsize * fds.itemsize])
                            for fd in fds:
                                os.close(fd)
                            unexpected = True
                        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == struct.calcsize('=iii'):
                            credentials.append(struct.unpack('=iii', data))
                        else:
                            unexpected = True
                    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or unexpected or len(credentials) != 1:
                        connection.close()
                        peers.pop(connection, None); peer_pids.pop(connection, None); peers_deadlines.pop(connection, None)
                        continue
                    pid, uid, _ = credentials[0]
                    if not probe and (uid != os.getuid() or not worker_authorized(pid, uid)):
                        connection.close()
                        peers.pop(connection, None); peer_pids.pop(connection, None); peers_deadlines.pop(connection, None)
                        continue
                    if len(raw) not in [REQUEST.size, 48]:
                        connection.close()
                        peers.pop(connection, None)
                        peer_pids.pop(connection, None)
                        peers_deadlines.pop(connection, None)
                        continue
                    if key_request:
                        magic, nonce, operation, keycode, pressed, stamp, *values = struct.unpack('=12I', raw)
                        wanted = values[:4]
                        expected_epoch = values[4] | (values[5] << 32)
                        commit = operation == 0x434d5431
                        contexts = protocol.active if commit else set(protocol.grabs.values()) & protocol.active
                        if magic != MAGIC or expected_epoch != epoch ^ protocol.generation or operation not in [0x4b455931, 0x54585431, 0x434d5431] or (operation == 0x4b455931 and (not 0 < keycode <= 767 or pressed not in [0, 1])) or (operation in [0x54585431, 0x434d5431] and (not 0x20 <= keycode <= 0x10ffff or 0xd800 <= keycode <= 0xdfff)) or len(contexts) != 1 or (not commit and tuple(wanted) != protocol.latest) or (commit and ((int(time.monotonic() * 1000) - stamp) & 0xffffffff) > 1000):
                            connection.close()
                            peers.pop(connection, None)
                            peer_pids.pop(connection, None)
                            peers_deadlines.pop(connection, None)
                            continue
                        context = next(iter(contexts))
                        if commit and context not in protocol.serials:
                            connection.close(); peers.pop(connection, None); peer_pids.pop(connection, None); peers_deadlines.pop(connection, None)
                            continue
                        peer_pids[connection] = pid
                        if operation == 0x4b455931:
                            identity = (pid, keycode)
                            if pressed:
                                if pid not in owners:
                                    if len(owners) >= 16:
                                        connection.close(); peers.pop(connection, None); peer_pids.pop(connection, None)
                                        continue
                                    try:
                                        owners[pid] = os.pidfd_open(pid, 0)
                                    except OSError:
                                        connection.close(); peers.pop(connection, None); peer_pids.pop(connection, None)
                                        continue
                                held[identity] = (context, protocol.generation)
                            else:
                                if held.get(identity) != (context, protocol.generation):
                                    connection.close(); peers.pop(connection, None); peer_pids.pop(connection, None)
                                    continue
                                del held[identity]
                                if not any(owner == pid for owner, key in held):
                                    os.close(owners.pop(pid))
                        # Ordered standard input-method requests bypass KWin's
                        # asynchronous raw-key/IME modifier echo at the lock.
                        if commit and owned_headless and not 0x7f <= keycode < 0xa0:
                            # GTK queues raw keys but applies text commits
                            # during protocol dispatch. A busy client can apply
                            # a later commit before an earlier Return despite
                            # correct compositor/wire ordering. Keep owned
                            # Unicode on the keyboard event route too; physical
                            # Return and stock IME handling retain their roles.
                            keysym = keycode if keycode <= 0xff else 0x01000000 | keycode
                            parent.enqueue(message(context, 8, protocol.serials[context], stamp, keysym, 1, 0))
                            parent.enqueue(message(context, 8, protocol.serials[context], stamp, keysym, 0, 0))
                            key_request = 2
                        elif commit:
                            # Preserve stock IME and control-scalar semantics.
                            # Native EIS excludes DEL/C1 from its Unicode path.
                            text = chr(keycode).encode('utf-8') + b'\0'
                            body = struct.pack('=II', protocol.serials[context], len(text)) + text + b'\0' * (-len(text) % 4)
                            parent.enqueue(HEADER.pack(context, ((len(body) + 8) << 16) | 1) + body)
                            key_request = 2
                        elif operation == 0x4b455931:
                            parent.enqueue(message(context, 11, 0, *wanted))
                            parent.enqueue(message(context, 10, 0, stamp, keycode, pressed))
                        else:
                            parent.enqueue(message(context, 11, 0, *wanted))
                            keysym = keycode if keycode <= 0xff else 0x01000000 | keycode
                            parent.enqueue(message(context, 8, 0, stamp, keysym, 1, 0))
                            parent.enqueue(message(context, 8, 0, stamp, keysym, 0, 0))
                    else:
                        magic, nonce, *wanted = REQUEST.unpack(raw)
                        if magic != MAGIC:
                            connection.close()
                            peers.pop(connection, None)
                            peer_pids.pop(connection, None)
                            peers_deadlines.pop(connection, None)
                            continue
                    minimum = protocol.request_sync()
                    peers[connection] = (nonce, tuple(wanted), minimum, time.monotonic() + CONTROL_TIMEOUT, key_request)
                    peers_deadlines.pop(connection, None)
                    protocol.schedule()
            for channel in [parent, child]:
                if channel.socket in writable:
                    channel.flush()
    finally:
        if parent is not None and 'protocol' in locals():
            for (_, keycode), (context, generation) in held.items():
                if context in protocol.active and generation == protocol.generation:
                    parent.enqueue(message(context, 10, 0, int(time.monotonic() * 1000) & 0xffffffff, keycode, 0))
            deadline = time.monotonic() + .2
            while parent.output and time.monotonic() < deadline:
                try:
                    if select.select([], [parent.socket], [], max(0, deadline - time.monotonic()))[1]:
                        parent.flush()
                except OSError:
                    break
        for descriptor in owners.values():
            os.close(descriptor)
        for peer in peers:
            peer.close()
        for resource in [listener, parent, child, far]:
            if resource is not None:
                resource.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if identity is not None:
            try:
                if os.lstat(path).st_ino == identity:
                    os.unlink(path)
            except FileNotFoundError:
                pass


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SystemExit(0)))
    try:
        if sys.argv[1:] == ['--headless-input-method']:
            headless_method()
        else:
            main(sys.argv[1:])
    except EOFError:
        pass
