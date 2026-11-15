#!/usr/bin/python3
"""KWin profile selection and restoration, always as the desktop's own UID.

The root installer owns shared files; this helper owns only the user's saved
InputMethod choice and managed session hooks. Resolve an inherited vendor IME
again on launch rather than pinning its executable across package updates.
An originally empty choice selects our headless method, not an OSK package.
"""
import importlib.util
import configparser
import fcntl
import json
import os
import re
import pathlib
import secrets
import shlex
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path('/usr/local/lib/meshagent-kwin-wire')
DESKTOP = str(ROOT / 'input-method.desktop')
# MAB3 requires worker authorization. A MAB1 relay may still be running after
# its script was updated; reject its readiness so install replaces that child.
# MAB2 was the old owned-headless marker, so do not reuse it as a protocol.
MAGIC = 0x4d414233


def command(args, **options):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=5, **options).stdout.strip()


def config_home():
    return pathlib.Path(os.environ.get('XDG_CONFIG_HOME', str(pathlib.Path.home() / '.config')))


def state_path():
    return pathlib.Path.home() / '.local/state/meshagent/kwin-wire.json'


def read_owned(path, limit=1024 * 1024):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError('Unsafe session file')
        raw = os.read(descriptor, limit + 1)
        if len(raw) > limit:
            raise ValueError('Session file limit')
        return raw
    finally:
        os.close(descriptor)


def atomic_user(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix='.meshagent-', dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def local_entry(raw):
    group = None
    entries = []
    existed = False
    for line in raw.decode('utf-8').splitlines():
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            group = stripped
            existed |= group == '[Wayland]'
        elif group == '[Wayland]' and stripped.startswith('InputMethod') and '=' in stripped:
            key = stripped.split('=', 1)[0]
            if key != 'InputMethod':
                raise ValueError('Qualified/immutable input-method setting requires review')
            entries.append(line)
    if len(entries) > 1:
        raise ValueError('Ambiguous input-method setting')
    return existed, entries[0] if entries else None


def effective(inherited=False):
    env = dict(os.environ)
    args = ['/usr/bin/kreadconfig6', '--file', 'kwinrc', '--group', 'Wayland', '--key', 'InputMethod']
    if inherited:
        # KConfig may write its own application rc even during a read query.
        # A private writable empty profile avoids a startup warning dialog.
        with tempfile.TemporaryDirectory(prefix='meshagent-kconfig-') as temporary:
            env['XDG_CONFIG_HOME'] = temporary
            return command(args, env=env)
    return command(args, env=env)


def explicit_command(pid=None):
    if pid is None:
        pid = compositor_pid()
    raw = pathlib.Path('/proc/' + str(pid) + '/cmdline').read_bytes()
    if len(raw) > 65536:
        raise ValueError('Compositor command limit')
    values = [part.decode() for part in raw.split(b'\0') if part]
    for index, value in enumerate(values):
        if value.startswith('--inputmethod='):
            return shlex.split(value.split('=', 1)[1])
        if value == '--inputmethod' and index + 1 < len(values):
            return shlex.split(values[index + 1])
    return None


def desktop_for_command(arguments):
    import shutil
    def canonical(values):
        if not values:
            return None
        return [shutil.which(values[0], path='/usr/bin:/bin') or values[0], *values[1:]]
    wanted = canonical(arguments)
    for index, path in enumerate(sorted(pathlib.Path('/usr/share/applications').glob('*.desktop'))):
        if index >= 512:
            break
        if str(path) == DESKTOP or path.stat().st_size > 131072:
            continue
        try:
            parser = configparser.ConfigParser(interpolation=None, strict=False)
            parser.optionxform = str
            parser.read(path, encoding='utf-8')
            if canonical(shlex.split(parser['Desktop Entry'].get('Exec', ''))) == wanted:
                return str(path)
        except (OSError, ValueError, KeyError, configparser.Error):
            continue
    raise ValueError('Explicit stock input method has no matching desktop entry')


def original(state):
    try:
        explicit = explicit_command() if state.get('explicit') else None
    except (OSError, ValueError, subprocess.SubprocessError):
        explicit = None
    if explicit:
        value = desktop_for_command(explicit)
    else:
        value = effective(True) if state['original_line'] is None else state['original_value']
        if not value and state.get('explicit_desktop'):
            value = state['explicit_desktop']
    if value == DESKTOP or '\n' in value or '\0' in value:
        raise ValueError('Recursive/invalid input-method selection')
    return value


def select_method(value):
    command(['/usr/bin/kwriteconfig6', '--file', 'kwinrc', '--group', 'Wayland', '--key', 'InputMethod', value])
    notify_method()


def notify_method():
    # KConfig only notifies dirty keys. Reannounce an already saved choice
    # that KWin missed, without rewriting or disabling that choice. a{saay}
    # is KConfig's group -> list of byte-array keys; omit a string's NUL byte.
    changes = "@a{saay} {'Wayland': [[" + ', '.join(str(value) for value in b'InputMethod') + "]]}"
    command(['/usr/bin/gdbus', 'emit', '--session', '--object-path', '/kwinrc',
             '--signal', 'org.kde.kconfig.notify.ConfigChanged', changes])


def compositor_pid():
    text = command(['/usr/bin/gdbus', 'call', '--session', '--dest', 'org.freedesktop.DBus', '--object-path', '/org/freedesktop/DBus', '--method', 'org.freedesktop.DBus.GetConnectionUnixProcessID', 'org.kde.KWin'])
    match = re.fullmatch(r'\(uint32 ([0-9]+),\)', text)
    if not match or not 0 < int(match[1]) < 2147483648:
        raise ValueError('Invalid compositor owner')
    return int(match[1])


def required_path(pid=None):
    return pathlib.Path(os.environ['XDG_RUNTIME_DIR']) / ('meshagent-ime-bridge.' + str(compositor_pid() if pid is None else pid) + '.required')


# Readiness clients must authenticate the managed instance before sending even
# a probe. Import only root-owned installed validation code and validate peer
# process/launch identity; a socket-owned epoch or matching desktop UID is not proof.
def authenticated_bridge(peer, compositor):
    # Load only installer-owned code; isolated Python does not add script dirs.
    path = ROOT / 'wire_bridge.py'
    resolved = path.resolve()
    for ancestor in [resolved, *resolved.parents]:
        info = ancestor.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            return False
    spec = importlib.util.spec_from_file_location('meshagent_bridge_auth', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.server_authorized(peer, compositor)


def ready(include_pending=False):
    """Probe the live relay without delivering a key or scalar.

    Activation readiness (3/6/7) differs from capability 8, where the native
    first-input path still needs to request current KWin text state. The
    installer can recognize that pending capability without claiming active
    readiness or restarting a healthy authenticated relay.
    """
    path = os.environ['XDG_RUNTIME_DIR'] + '/meshagent-ime-bridge.' + str(compositor_pid()) + '.sock'
    try:
        info = os.lstat(path)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            return False
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
            peer.settimeout(.4)
            peer.connect(path)
            _, uid, _ = struct.unpack('=iii', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.getuid() or not authenticated_bridge(peer, compositor_pid()):
                return False
            peer.send(struct.pack('=6I', MAGIC, 0, 0, 0, 0, 0))
            raw = peer.recv(37)
            statuses = [3, 6, 7, 8] if include_pending else [3, 6, 7]
            return len(raw) == 36 and struct.unpack('=9I', raw)[:3] in [(MAGIC, 0, status) for status in statuses]
    except (OSError, ValueError):
        return False


def load_state():
    state = json.loads(read_owned(state_path(), 16384))
    if state.get('version') != 1 or not isinstance(state.get('group_existed'), bool):
        raise ValueError('Invalid session receipt')
    line = state.get('original_line')
    if line is not None and (not isinstance(line, str) or not line.startswith('InputMethod=') or any(c in line for c in '\r\n\0') or len(line) > 4096):
        raise ValueError('Invalid original setting')
    if not isinstance(state.get('config_home'), str) or not os.path.isabs(state['config_home']) or any(c in state['config_home'] for c in '\r\n\0'):
        raise ValueError('Invalid original config directory')
    if not isinstance(state.get('original_value'), str) or len(state['original_value']) > 4096:
        raise ValueError('Invalid original selection')
    return state


def install():
    config = config_home() / 'kwinrc'
    current = effective()
    if current != DESKTOP:
        raw = read_owned(config) if config.exists() else b''
        group, entry = local_entry(raw)
        explicit = explicit_command()
        state = dict(version=1, group_existed=group, original_line=entry, original_value=current, explicit=bool(explicit), config_home=str(config_home()))
        if explicit:
            state['explicit_desktop'] = desktop_for_command(explicit)
        if current and (not pathlib.Path(current).is_absolute() or not pathlib.Path(current).is_file()):
            raise ValueError('Original input-method desktop file unavailable')
        atomic_user(state_path(), json.dumps(state).encode())
    else:
        state = load_state()
    # available becomes true only after startSession installed KConfigWatcher
    # and selected its input-method command, including the greeter override.
    # A stock desktop without an input method still needs the owned bridge.
    # Selecting it supplies a headless pass-through client, without an OSK or
    # additional packages. Existing nonempty vendor selections keep their relay.
    empty_selection = not current and not explicit_command()
    if empty_selection:
        select_method(DESKTOP)
    deadline = time.monotonic() + 5
    notified = False
    while True:
        try:
            available = command(['/usr/bin/gdbus', 'call', '--session', '--dest', 'org.kde.KWin', '--object-path', '/VirtualKeyboard', '--method', 'org.freedesktop.DBus.Properties.Get', 'org.kde.kwin.VirtualKeyboard', 'available'])
            if 'true' in available:
                break
            if 'false' in available and current == DESKTOP and not notified:
                notified = True
                notify_method()
        except (OSError, subprocess.SubprocessError):
            pass
        if time.monotonic() >= deadline:
            return dict(state='activation-pending', changed=False)
        time.sleep(.05)
    # Advertise the owned no-grab method without probing or replacing a stock
    # IME's current input context. The native side still authenticates
    # the live peer and its capability response before committing text.
    owned_headless = not original(state)
    atomic_user(required_path(), struct.pack('=I', MAGIC + 1 if owned_headless else MAGIC))
    # available describes KWin's configured command, not a listening child.
    # Use the remaining startup budget before reselecting an owned method;
    # doing so immediately can terminate the child we just asked it to start.
    while True:
        if ready():
            return dict(state='active', changed=empty_selection)
        if owned_headless and ready(include_pending=True):
            return dict(state='activation-pending', changed=empty_selection)
        if (current != DESKTOP and not empty_selection) or time.monotonic() >= deadline:
            break
        time.sleep(.05)
    # Login-manager KWin can start with an explicit --inputmethod command.
    # A same-value KConfig write emits no notification. Two quick changes can
    # also coalesce, leaving the command-line stock IME running. Wait until
    # KWin observes a disabled method before restoring our managed selection.
    if current == DESKTOP:
        select_method('')
        deadline = time.monotonic() + 5
        while True:
            try:
                available = command(['/usr/bin/gdbus', 'call', '--session', '--dest', 'org.kde.KWin', '--object-path', '/VirtualKeyboard', '--method', 'org.freedesktop.DBus.Properties.Get', 'org.kde.kwin.VirtualKeyboard', 'available'])
                if 'false' in available:
                    break
            except (OSError, subprocess.SubprocessError):
                pass
            if time.monotonic() >= deadline:
                select_method(DESKTOP)
                return dict(state='activation-pending', changed=True)
            time.sleep(.05)
    select_method(DESKTOP)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if ready():
            return dict(state='active', changed=True)
        if owned_headless and ready(include_pending=True):
            return dict(state='activation-pending', changed=True)
        time.sleep(.05)
    return dict(state='activation-pending', changed=True)


def restore_entry(raw, state):
    """Restore only the owned InputMethod line/group, retaining other settings.
    Do not replace kwinrc wholesale: it also contains unrelated user choices.
    """
    lines = raw.decode('utf-8').splitlines(keepends=True)
    result = []
    index = 0
    while index < len(lines):
        if lines[index].strip() != '[Wayland]':
            result.append(lines[index]); index += 1; continue
        end = index + 1
        while end < len(lines) and not (lines[end].strip().startswith('[') and lines[end].strip().endswith(']')):
            end += 1
        body = [line for line in lines[index + 1:end] if not line.strip().startswith('InputMethod=')]
        if state['original_line'] is not None:
            body.append(state['original_line'] + '\n')
        if state['group_existed'] or any(line.strip() for line in body):
            result.append(lines[index]); result.extend(body)
        elif result and not result[-1].strip():
            result.pop()
        index = end
    return ''.join(result).encode('utf-8')


def bridge_alive():
    runtime = pathlib.Path(os.environ['XDG_RUNTIME_DIR'])
    for path in runtime.glob('meshagent-ime-bridge.*.sock'):
        try:
            info = path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                continue
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
                peer.settimeout(.1)
                peer.connect(str(path))
                if authenticated_bridge(peer, int(path.name.split('.')[1])):
                    return True
        except OSError:
            continue
    return False


def uninstall():
    if not state_path().exists():
        return dict(state='not-owned', changed=False)
    state = load_state()
    if state.get('config_home'):
        os.environ['XDG_CONFIG_HOME'] = state['config_home']
    if effective() != DESKTOP:
        if bridge_alive():
            return dict(state='activation-pending', changed=False)
        state_path().unlink()
        return dict(state='user-changed', changed=False)
    # First notify KWin of the effective original choice; removing our local
    # override afterward preserves the same choice and future vendor defaults.
    if state.get('config_home'):
        os.environ['XDG_CONFIG_HOME'] = state['config_home']
    select_method(original(state))
    deadline = time.monotonic() + 4
    while bridge_alive():
        if time.monotonic() >= deadline:
            return dict(state='activation-pending', changed=True)
        time.sleep(.05)
    config = config_home() / 'kwinrc'
    atomic_user(config, restore_entry(read_owned(config), state), config.stat().st_mode & 0o777)
    for path in pathlib.Path(os.environ['XDG_RUNTIME_DIR']).glob('meshagent-ime-bridge.*.required'):
        try:
            # Legacy markers are recognized only for removal, never readiness
            # or native input routing after upgrading to worker authorization.
            if read_owned(path, 4) in [struct.pack('=I', value) for value in (0x4d414231, 0x4d414232, MAGIC, MAGIC + 1)]:
                path.unlink()
        except (OSError, ValueError):
            pass
    state_path().unlink()
    return dict(state='restored', changed=True)


def launch():
    state = load_state()
    arguments = explicit_command(os.getppid())
    if not arguments:
        selected = original(state)
        if not selected:
            os.execv('/usr/bin/python3', ['/usr/bin/python3', '-I', str(ROOT / 'wire_bridge.py')])
        desktop = pathlib.Path(selected)
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        parser.read(desktop, encoding='utf-8')
        arguments = shlex.split(parser['Desktop Entry']['Exec'])
    if not arguments or any('\0' in value for value in arguments):
        raise ValueError('Invalid stock input-method command')
    if not os.path.isabs(arguments[0]):
        import shutil
        program = shutil.which(arguments[0], path='/usr/bin:/bin')
        if program is None:
            raise ValueError('Stock input-method executable unavailable')
        arguments[0] = program
    os.execv('/usr/bin/python3', ['/usr/bin/python3', '-I', str(ROOT / 'wire_bridge.py'), *arguments])


if __name__ == '__main__':
    try:
        action = sys.argv[1]
        if action == 'launch':
            launch()
        elif action in ['install', 'uninstall']:
            path = state_path().with_suffix('.lock')
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                    raise ValueError('Unsafe session lock')
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                print(json.dumps(install() if action == 'install' else uninstall()))
            finally:
                os.close(descriptor)
        else:
            raise ValueError('Unknown session action')
    except Exception as error:
        print(json.dumps(dict(state='error', changed=None, detail=str(error))), file=sys.stderr)
        raise SystemExit(1)
