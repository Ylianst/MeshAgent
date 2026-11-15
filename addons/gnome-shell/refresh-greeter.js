/* SPDX-License-Identifier: Apache-2.0 */
// Installer-only root action. MESH_ACTIVATION_SOURCE is injected by the source
// generator from the exact fixed activation helper, not supplied by the caller.
(function () {
    const Gio = imports.gi.Gio, GLib = imports.gi.GLib, ByteArray = imports.byteArray;
    let stage = 'arguments';
    function output(state, extra = {}) { print(JSON.stringify(Object.assign({state, changed: false}, extra))); }
    function unpack(v) {
        if (v instanceof GLib.Variant) return unpack(v.deep_unpack());
        if (Array.isArray(v)) return v.map(unpack);
        if (v && typeof v === 'object') { const r = {}; for (const k of Object.keys(v)) r[k] = unpack(v[k]); return r; }
        return v;
    }
    function bytes(path, limit) {
        const [ok, data] = Gio.File.new_for_path(path).load_contents(null);
        if (!ok || data.length > limit) throw Error('Invalid greeter process data');
        return data;
    }
    function text(path, limit) { return ByteArray.toString(bytes(path, limit)); }
    function processUid(pid) {
        const m = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$/m.exec(text('/proc/' + pid + '/status', 65536));
        if (!m || m[1] !== m[2] || m[1] !== m[3] || m[1] !== m[4]) throw Error('Ambiguous greeter process UID');
        return Number(m[1]);
    }
    function processStart(pid) {
        const stat = text('/proc/' + pid + '/stat', 65536), end = stat.lastIndexOf(') ');
        const fields = end < 0 ? [] : stat.substring(end + 2).trim().split(/\s+/);
        if (stat.substring(0, stat.indexOf(' ')) !== String(pid) || fields.length < 20 || !/^\d+$/.test(fields[19])) throw Error('Invalid greeter process incarnation');
        return fields[19];
    }
    try {
        if (ARGV.length !== 4 || !['inspect', 'offer'].includes(ARGV[0]) || !/^[1-9]\d{0,9}$/.test(ARGV[1]) ||
            !/^[1-9]\d{0,9}$/.test(ARGV[2]) || !/^\d{1,22}$/.test(ARGV[3])) throw Error('Invalid greeter target');
        if (new Gio.Credentials().get_unix_user() !== 0) throw Error('Root installer required');
        const pid = Number(ARGV[1]), uid = Number(ARGV[2]), start = ARGV[3];
        if (uid > 4294967294) throw Error('Invalid greeter UID');
        stage = 'account';
        let accounts = text('/etc/passwd', 1048576).split('\n').map(l => l.split(':')).filter(p => p.length === 7 && /^\d+$/.test(p[2]) && Number(p[2]) === uid);
        if (!accounts.length) {
            const lookup = Gio.Subprocess.new(['/usr/bin/timeout', '--kill-after=1s', '3s', '/usr/bin/getent', 'passwd', String(uid)], Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE);
            const [ok, output] = lookup.communicate_utf8(null, null);
            if (ok && lookup.get_successful() && output.length <= 1048576)
                accounts = output.trim().split('\n').map(l => l.split(':')).filter(p => p.length === 7 && /^\d+$/.test(p[2]) && Number(p[2]) === uid);
        }
        if (accounts.length !== 1 || !['gdm', 'Debian-gdm', 'gdm-greeter'].includes(accounts[0][0]) || !accounts[0][5].startsWith('/') || /[\x00-\x1f\x7f]/.test(accounts[0][5])) throw Error('Dedicated GDM account required');
        const account = accounts[0];
        const bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, null);
        function call(dest, path, iface, method, signature, args) {
            return unpack(bus.call_sync(dest, path, iface, method, new GLib.Variant(signature, args), null, Gio.DBusCallFlags.NO_AUTO_START, 2500, null));
        }
        const owner = call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetNameOwner', '(s)', ['org.freedesktop.login1'])[0];
        if (!/^:\d+\.\d+$/.test(owner) || call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetConnectionUnixUser', '(s)', [owner])[0] !== 0) throw Error('Untrusted logind service');
        function props(path, iface) { return call(owner, path, 'org.freedesktop.DBus.Properties', 'GetAll', '(s)', [iface])[0]; }
        function identity() {
            if (processStart(pid) !== start || processUid(pid) !== uid || text('/proc/' + pid + '/comm', 64).trim() !== 'gnome-shell') throw Error('Greeter process changed');
            const directory = Gio.File.new_for_path('/proc').enumerate_children('standard::name', Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null);
            let item, count = 0;
            try {
                while ((item = directory.next_file(null))) {
                    const n = item.get_name(); if (!/^[1-9]\d*$/.test(n)) continue;
                    let comm; try { comm = text('/proc/' + n + '/comm', 64).trim(); } catch (_) { continue; }
                    if (comm === 'gnome-shell' && processUid(n) === uid) ++count;
                }
            } finally { directory.close(null); }
            if (count !== 1) throw Error('Ambiguous GDM Shell processes');
            const seat = props('/org/freedesktop/login1/seat/seat0', 'org.freedesktop.login1.Seat');
            if (!seat.ActiveSession || typeof seat.ActiveSession[0] !== 'string' || !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(seat.ActiveSession[0]) ||
                typeof seat.ActiveSession[1] !== 'string' || !seat.ActiveSession[1].startsWith('/org/freedesktop/login1/session/')) throw Error('No active console greeter');
            const path = seat.ActiveSession[1], p = props(path, 'org.freedesktop.login1.Session');
            if (p.Id !== seat.ActiveSession[0] || !p.User || p.User[0] !== uid || p.Class !== 'greeter' || p.Type !== 'wayland' ||
                !p.Seat || p.Seat[0] !== 'seat0' || p.Active !== true || p.State !== 'active' || p.Remote !== false) throw Error('Active local Wayland GDM greeter required');
            const sessions = call(owner, '/org/freedesktop/login1', 'org.freedesktop.login1.Manager', 'ListSessions', '()', [])[0];
            if (!Array.isArray(sessions)) throw Error('Cannot verify other console sessions');
            for (const row of sessions) {
                if (!Array.isArray(row) || row.length !== 5) throw Error('Invalid session inventory');
                if (row[3] !== 'seat0' || row[4] === path) continue;
                const other = props(row[4], 'org.freedesktop.login1.Session');
                if (typeof other.Class !== 'string' || typeof other.Type !== 'string') throw Error('Unverifiable console session');
                if (other.Class.startsWith('user') && ['wayland', 'x11'].includes(other.Type)) throw Error('User desktop is present on seat0');
            }
            if (processStart(pid) !== start) throw Error('Greeter changed during verification');
            return {id: p.Id, path};
        }
        function needed() {
            const env = {}, allowed = ['DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR', 'DCONF_PROFILE', 'XDG_CONFIG_HOME', 'XDG_DATA_DIRS', 'GSETTINGS_SCHEMA_DIR'];
            const data = bytes('/proc/' + pid + '/environ', 1048576); let offset = 0;
            for (let i = 0; i < data.length; ++i) {
                if (data[i] !== 0) continue;
                const row = ByteArray.toString(data.subarray(offset, i)), equal = row.indexOf('='); offset = i + 1;
                const k = row.substring(0, equal), v = row.substring(equal + 1);
                if (equal < 1 || !allowed.includes(k)) continue;
                if (Object.prototype.hasOwnProperty.call(env, k) || v.length > 16384 || /[\x00-\x1f\x7f]/.test(v)) throw Error('Invalid greeter environment');
                env[k] = v;
            }
            if (offset !== data.length || !env.DBUS_SESSION_BUS_ADDRESS || env.XDG_RUNTIME_DIR !== '/run/user/' + uid) throw Error('Missing greeter bus identity');
            const verifyPid = '(function(){const G=imports.gi.Gio;const b=G.bus_get_sync(G.BusType.SESSION,null);const p=b.call_sync("org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","GetConnectionUnixProcessID",new imports.gi.GLib.Variant("(s)",["org.gnome.Shell"]),null,G.DBusCallFlags.NO_AUTO_START,2500,null).deep_unpack()[0];if(p!==' + pid + ')throw Error("Greeter bus owner changed");})();\n';
            const args = ['/usr/sbin/runuser', '-u', account[0], '--', '/usr/bin/env', '-i', 'HOME=' + account[5], 'USER=' + account[0], 'LOGNAME=' + account[0], 'PATH=/usr/bin:/bin', 'LANG=C.UTF-8'];
            for (const k of allowed) if (env[k] !== undefined) args.push(k + '=' + env[k]);
            args.push('/usr/bin/timeout', '--kill-after=1s', '8s', '/usr/bin/gjs', '-c', verifyPid + MESH_ACTIVATION_SOURCE, 'inspect');
            const child = Gio.Subprocess.new(args, Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE);
            const [ok, stdout] = child.communicate_utf8(null, null);
            if (!ok || !child.get_if_exited() || child.get_exit_status() !== 0) throw Error('Greeter inspection failed');
            const result = JSON.parse(stdout.trim());
            if (result.state === 'active') return false;
            if (result.state !== 'needs-sign-in' || result.configured !== true || result.globallyDisabled) throw Error('Greeter is not prepared for refresh');
            return true;
        }
        stage = 'identity'; const before = identity();
        stage = 'activation'; if (!needed()) { output('not-needed'); return; }
        if (ARGV[0] === 'inspect') { output('greeter-refresh-available', {session: before.id}); return; }
        stage = 'choice';
        let tty; try { tty = Gio.File.new_for_path('/dev/tty').open_readwrite(null); } catch (_) { output('deferred', {reason: 'No controlling terminal; login-screen activation is pending'}); return; }
        let answer = null, expired = false;
        const loop = new GLib.MainLoop(null, false), cancel = new Gio.Cancellable();
        const input = new Gio.DataInputStream({base_stream: tty.get_input_stream()});
        const prompt = 'MeshAgent needs to refresh the login screen to finish remote control setup. No user desktop will be signed out. Type RESTART to approve, or press Enter to do this later: ';
        tty.get_output_stream().write_all(ByteArray.fromString(prompt), null); tty.get_output_stream().flush(null);
        const timer = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 45, () => { expired = true; cancel.cancel(); loop.quit(); return GLib.SOURCE_REMOVE; });
        input.read_line_async(GLib.PRIORITY_DEFAULT, cancel, (stream, result) => {
            try { const [line] = stream.read_line_finish_utf8(result); answer = line; } catch (_) { answer = null; }
            loop.quit();
        });
        loop.run(); if (!expired) GLib.source_remove(timer);
        try { tty.close(null); } catch (_) { /* Cancellation may still be draining. */ }
        if (expired || typeof answer !== 'string' || answer.trim() !== 'RESTART') { output('declined'); return; }
        stage = 'revalidate';
        const after = identity(); if (after.id !== before.id || after.path !== before.path) throw Error('Greeter session changed during choice');
        if (!needed()) { output('not-needed'); return; }
        const final = identity(); if (final.id !== before.id || final.path !== before.path) throw Error('Greeter changed before refresh');
        stage = 'refresh';
        call(owner, final.path, 'org.freedesktop.login1.Session', 'Terminate', '()', []);
        output('greeter-refresh-requested', {session: final.id});
    } catch (error) { output('deferred', {stage, reason: String(error)}); }
})();
