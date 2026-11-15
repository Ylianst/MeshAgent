/* SPDX-License-Identifier: Apache-2.0 */
// Installer-only choice. No settings writes, forced termination or root action.
(function () {
    const Gio = imports.gi.Gio, GLib = imports.gi.GLib;
    const UUID = 'meshagent-console@meshcentral.com';
    const BASE = '/usr/share/gnome-shell/extensions/' + UUID;
    function output(state, extra = {}) { print(JSON.stringify(Object.assign({state, changed: false}, extra))); }
    function unpack(value) {
        if (value instanceof GLib.Variant) return unpack(value.deep_unpack());
        if (Array.isArray(value)) return value.map(unpack);
        if (value && typeof value === 'object') { const result = {}; for (const k of Object.keys(value)) result[k] = unpack(value[k]); return result; }
        return value;
    }
    try {
        if (ARGV.length !== 3 || !/^[1-9]\d{0,9}$/.test(ARGV[0]) || (ARGV[1] !== '-' && !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(ARGV[1])) || !['inspect', 'offer'].includes(ARGV[2])) throw Error('Invalid sign-out target');
        const expectedPid = Number(ARGV[0]), expectedSession = ARGV[1];
        const user = new Gio.Credentials().get_unix_user();
        if (!user || !GLib.getenv('DBUS_SESSION_BUS_ADDRESS')) throw Error('User desktop bus required');
        const sessionBus = Gio.bus_get_sync(Gio.BusType.SESSION, null), systemBus = Gio.bus_get_sync(Gio.BusType.SYSTEM, null);
        function call(bus, destination, path, iface, method, signature, args) {
            return unpack(bus.call_sync(destination, path, iface, method, new GLib.Variant(signature, args), null, Gio.DBusCallFlags.NO_AUTO_START, 2500, null));
        }
        function owner(name) { return call(sessionBus, 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetNameOwner', '(s)', [name])[0]; }
        function properties(path, iface) { return call(systemBus, 'org.freedesktop.login1', path, 'org.freedesktop.DBus.Properties', 'GetAll', '(s)', [iface])[0]; }
        function identity() {
            const shell = owner('org.gnome.Shell'), manager = owner('org.gnome.SessionManager');
            const pid = call(sessionBus, 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetConnectionUnixProcessID', '(s)', [shell])[0];
            if (pid !== expectedPid || !/^:\d+\.\d+$/.test(shell) || !/^:\d+\.\d+$/.test(manager)) throw Error('Desktop bus identity changed');
            const managerUser = call(sessionBus, 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetConnectionUnixUser', '(s)', [manager])[0];
            if (managerUser !== user) throw Error('Session manager belongs to another user');
            const seat = properties('/org/freedesktop/login1/seat/seat0', 'org.freedesktop.login1.Seat');
            if (!seat.ActiveSession || typeof seat.ActiveSession[0] !== 'string' || !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(seat.ActiveSession[0]) ||
                (expectedSession !== '-' && seat.ActiveSession[0] !== expectedSession) || typeof seat.ActiveSession[1] !== 'string' || !seat.ActiveSession[1].startsWith('/org/freedesktop/login1/session/')) throw Error('Desktop is not the active console session');
            const p = properties(seat.ActiveSession[1], 'org.freedesktop.login1.Session');
            const desktop = typeof p.Desktop === 'string' && p.Desktop ? p.Desktop : GLib.getenv('XDG_CURRENT_DESKTOP');
            const desktops = typeof desktop === 'string' ? desktop.toLowerCase().split(':') : [];
            if (p.Id !== seat.ActiveSession[0] || !p.User || p.User[0] !== user || !p.Seat || p.Seat[0] !== 'seat0' ||
                p.Class !== 'user' || p.Type !== 'wayland' || p.State !== 'active' || p.Active !== true || p.Remote !== false || p.LockedHint !== false) throw Error('Active unlocked local Wayland user session required');
            if (!desktops.some(d => ['gnome', 'ubuntu', 'gnome-classic', 'ubuntu-wayland'].includes(d))) throw Error('GNOME console desktop identity required');
            return {shell, manager, path: seat.ActiveSession[1]};
        }
        function needed(target) {
            for (const path of ['/', '/usr', '/usr/share', '/usr/share/gnome-shell', '/usr/share/gnome-shell/extensions', BASE, BASE + '/metadata.json']) {
                const info = Gio.File.new_for_path(path).query_info('standard::type,unix::uid,unix::mode,unix::nlink', Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null);
                const regular = path.endsWith('/metadata.json');
                if (info.get_file_type() !== (regular ? Gio.FileType.REGULAR : Gio.FileType.DIRECTORY) || info.get_attribute_uint32('unix::uid') !== 0 ||
                    (info.get_attribute_uint32('unix::mode') & 0o022) || (regular && info.get_attribute_uint32('unix::nlink') !== 1)) throw Error('Untrusted installed companion');
            }
            const [loaded, bytes] = Gio.File.new_for_path(BASE + '/metadata.json').load_contents(null);
            if (!loaded || bytes.length > 65536) throw Error('Invalid companion metadata');
            const metadata = JSON.parse(imports.byteArray.toString(bytes));
            if (metadata.uuid !== UUID || !Number.isInteger(metadata.version) || metadata.version < 1 || metadata.version > 0xffffffff) throw Error('Invalid companion generation');
            const s = new Gio.Settings({schema_id: 'org.gnome.shell'});
            if (!s.get_strv('enabled-extensions').includes(UUID) || s.get_strv('disabled-extensions').includes(UUID) || s.get_boolean('disable-user-extensions')) return false;
            const resident = call(sessionBus, target.shell, '/org/gnome/Shell', 'org.gnome.Shell.Extensions', 'GetExtensionInfo', '(s)', [UUID])[0];
            return !Object.keys(resident).length || (Number.isInteger(resident.version) && resident.version < metadata.version);
        }
        const before = identity();
        if (!needed(before)) { output('not-needed'); return; }
        if (ARGV[2] === 'inspect') { output('sign-out-available'); return; }
        if (!GLib.file_test('/usr/bin/zenity', GLib.FileTest.IS_EXECUTABLE)) { output('deferred', {reason: 'no-dialog'}); return; }
        const dialog = Gio.Subprocess.new(['/usr/bin/zenity', '--question', '--title=MeshAgent',
            '--text=GNOME needs a new session to finish remote control setup. Remote control may not work until you sign out and sign back in. Save your work before signing out.',
            '--ok-label=Sign Out', '--cancel-label=Later', '--default-cancel', '--timeout=45'], Gio.SubprocessFlags.STDOUT_SILENCE | Gio.SubprocessFlags.STDERR_SILENCE);
        dialog.wait(null);
        if (!dialog.get_if_exited() || dialog.get_exit_status() !== 0) { output('declined'); return; }
        const after = identity();
        if (before.shell !== after.shell || before.manager !== after.manager || before.path !== after.path) throw Error('Session changed while awaiting choice');
        if (!needed(after)) { output('not-needed'); return; }
        // Consent was collected above. Mode 1 skips a duplicate confirmation
        // while retaining GNOME's inhibitor flow; force mode 2 is never used.
        call(sessionBus, after.manager, '/org/gnome/SessionManager', 'org.gnome.SessionManager', 'Logout', '(u)', [1]);
        output('sign-out-requested');
    } catch (error) { output('deferred', {reason: String(error)}); }
})();
