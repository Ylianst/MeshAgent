/* SPDX-License-Identifier: Apache-2.0 */
// Executed as the target session user by the Agent installer/startup helper.
// Fixed UUID and paths; no arbitrary script, extension, or settings key input.
(function () {
    const Gio = imports.gi.Gio;
    const GLib = imports.gi.GLib;
    const UUID = 'meshagent-console@meshcentral.com';
    const BASE = '/usr/share/gnome-shell/extensions/' + UUID;
    let changed = false, stage = 'arguments';
    function output(state, extra = {}) { print(JSON.stringify(Object.assign({state, changed}, extra))); }
    function unpack(value) {
        if (value instanceof GLib.Variant) return unpack(value.deep_unpack());
        if (Array.isArray(value)) return value.map(unpack);
        if (value && typeof value === 'object') {
            const result = {};
            for (const key of Object.keys(value)) result[key] = unpack(value[key]);
            return result;
        }
        return value;
    }
    function trusted(path, directory) {
        const info = Gio.File.new_for_path(path).query_info('standard::type,unix::uid,unix::mode,unix::nlink', Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null);
        if (info.get_file_type() !== (directory ? Gio.FileType.DIRECTORY : Gio.FileType.REGULAR) ||
            info.get_attribute_uint32('unix::uid') !== 0 || (info.get_attribute_uint32('unix::mode') & 0o022) ||
            (!directory && info.get_attribute_uint32('unix::nlink') !== 1)) throw Error('Untrusted companion path');
    }
    try {
        if (ARGV.length !== 1 || !['inspect', 'prepare', 'prepare-greeter', 'inspect-greeter'].includes(ARGV[0])) throw Error('Invalid activation operation');
        const prepare = ARGV[0] === 'prepare' || ARGV[0] === 'prepare-greeter';
        const offline = ARGV[0].endsWith('-greeter');
        stage = 'installed-metadata';
        for (const path of ['/', '/usr', '/usr/share', '/usr/share/gnome-shell', '/usr/share/gnome-shell/extensions', BASE]) trusted(path, true);
        trusted(BASE + '/metadata.json', false);
        const [loaded, bytes] = Gio.File.new_for_path(BASE + '/metadata.json').load_contents(null);
        if (!loaded || bytes.length > 65536) throw Error('Invalid companion metadata size');
        const metadata = JSON.parse(imports.byteArray.toString(bytes));
        if (metadata.uuid !== UUID || !Number.isInteger(metadata.version) || metadata.version < 1 || metadata.version > 0xffffffff)
            throw Error('Invalid installed companion metadata');
        const generation = metadata.version;
        if (!GLib.getenv('DBUS_SESSION_BUS_ADDRESS')) { output('no-session-bus', {generation}); return; }
        stage = 'settings';
        const source = Gio.SettingsSchemaSource.get_default();
        const schema = source && source.lookup('org.gnome.shell', true);
        if (!schema || !schema.has_key('enabled-extensions')) { output('unsupported-settings', {generation}); return; }
        const settings = new Gio.Settings({schema_id: 'org.gnome.shell'});
        const enabled = settings.get_strv('enabled-extensions');
        const disabled = schema.has_key('disabled-extensions') ? settings.get_strv('disabled-extensions') : [];
        const globallyDisabled = schema.has_key('disable-user-extensions') && settings.get_boolean('disable-user-extensions');
        const needsEnable = !enabled.includes(UUID), needsUndisable = disabled.includes(UUID);
        let configured = !needsEnable && !needsUndisable;
        function configure() {
            if (globallyDisabled || (needsEnable && !settings.is_writable('enabled-extensions')) ||
                (needsUndisable && !settings.is_writable('disabled-extensions'))) return 'policy-blocked';
            if (needsEnable || needsUndisable) {
                stage = 'prepare-settings'; settings.delay();
                if ((needsEnable && !settings.set_strv('enabled-extensions', enabled.concat([UUID]))) ||
                    (needsUndisable && !settings.set_strv('disabled-extensions', disabled.filter(id => id !== UUID)))) {
                    settings.revert(); throw Error('Companion settings are not writable');
                }
                changed = null; settings.apply(); Gio.Settings.sync(); changed = true;
                configured = settings.get_strv('enabled-extensions').includes(UUID) &&
                    (!schema.has_key('disabled-extensions') || !settings.get_strv('disabled-extensions').includes(UUID));
                if (!configured) throw Error('Companion settings did not persist');
            }
            return null;
        }
        // Settings-only greeter preparation does not contact or autostart Shell.
        // The root launcher selects the installed GDM account and profile.
        if (offline) {
            let blocked = globallyDisabled ? 'policy-blocked' : null;
            if (prepare && !blocked) blocked = configure();
            output(blocked || (configured ? 'greeter-configured' : 'greeter-unconfigured'), {generation, configured, globallyDisabled});
            return;
        }
        const bus = Gio.bus_get_sync(Gio.BusType.SESSION, null);
        function call(method) {
            return unpack(bus.call_sync('org.gnome.Shell', '/org/gnome/Shell',
                'org.gnome.Shell.Extensions', method, new GLib.Variant('(s)', [UUID]), null,
                Gio.DBusCallFlags.NO_AUTO_START, 2500, null));
        }
        let apiError = null;
        function info() {
            try { const reply = call('GetExtensionInfo'); apiError = null; return reply && reply[0] || {}; }
            catch (error) { apiError = String(error); return {}; }
        }
        function stateOf(resident) {
            if (apiError) return 'extension-api-unavailable';
            if (resident.version > generation) return 'version-conflict';
            if (resident.version === generation && resident.state === 1) return 'active';
            if (!Object.keys(resident).length || resident.version < generation) return 'needs-sign-in';
            if (resident.state === 3 || resident.state === 4) return 'extension-error';
            return 'inactive';
        }
        let resident = info(), state = stateOf(resident);
        if (!prepare || state === 'version-conflict' || state === 'extension-error') {
            output(state, {generation, residentVersion: resident.version || null, configured, globallyDisabled}); return;
        }
        // Never enable every other extension by clearing the global disable flag.
        if (globallyDisabled) {
            output(state === 'active' ? 'active' : 'policy-blocked', {generation, configured, globallyDisabled}); return;
        }
        if (configure() === 'policy-blocked') {
            output('policy-blocked', {generation, configured}); return;
        }
        stage = 'enable-extension';
        if (state !== 'active') {
            try { call('EnableExtension'); } catch (_) { /* Fresh sessions can use the persisted setting. */ }
            for (let attempt = 0; attempt < 6; ++attempt) {
                resident = info(); state = stateOf(resident);
                if (state !== 'inactive' || resident.state !== 8) break;
                GLib.usleep(50000);
            }
        }
        output(state, {generation, residentVersion: resident.version || null, configured});
    } catch (error) { output('error', {stage, detail: String(error)}); }
})();
