/* SPDX-License-Identifier: Apache-2.0 */
// Fixed-purpose GNOME activation launcher. No shell, caller-supplied environment,
// username, command, extension UUID, or logout operation is accepted.
var fs = require('fs');
var greeterNames = ['gdm', 'Debian-gdm', 'gdm-greeter'];
var keys = ['DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR', 'DCONF_PROFILE', 'XDG_CONFIG_HOME', 'XDG_DATA_DIRS', 'GSETTINGS_SCHEMA_DIR', 'WAYLAND_DISPLAY', 'DISPLAY', 'XAUTHORITY', 'XDG_SESSION_ID', 'XDG_CURRENT_DESKTOP'];
function read(path, limit)
{
    var value = fs.readFileSync(path).toString();
    if (value.length > limit) { throw new Error('Session data exceeds limit'); }
    return value;
}
function uid(status)
{
    var match = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$/m.exec(status);
    if (!match || match[1] !== match[2] || match[1] !== match[3] || match[1] !== match[4]) { throw new Error('Ambiguous process identity'); }
    var value = Number(match[1]);
    if (value > 4294967294) { throw new Error('Invalid process identity'); }
    return value;
}
function root()
{
    if (process.platform !== 'linux' || uid(read('/proc/self/status', 65536)) !== 0) { throw new Error('Root Linux installer required'); }
}
function start(pid)
{
    var stat = read('/proc/' + pid + '/stat', 65536), end = stat.lastIndexOf(') ');
    var fields = end < 0 ? [] : stat.substring(end + 2).trim().split(/\s+/);
    if (stat.substring(0, stat.indexOf(' ')) !== pid || fields.length < 20 || !/^\d+$/.test(fields[19])) { throw new Error('Invalid process incarnation'); }
    return fields[19];
}
function account(id)
{
    var rows = read('/etc/passwd', 1048576).split('\n'), found = [];
    for (var i = 0; i < rows.length; ++i)
    {
        var row = rows[i].split(':');
        if (row.length === 7 && /^\d+$/.test(row[2]) && Number(row[2]) === id) { found.push(row); }
    }
    // Modern GDM can publish its greeter through NSS/userdb instead of /etc/passwd.
    if (!found.length && Number.isInteger(id) && id > 0 && id <= 4294967294)
    {
        var child = require('child_process').execFile('/usr/bin/timeout',
            ['timeout', '--kill-after=1s', '3s', '/usr/bin/getent', 'passwd', String(id)],
            { env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' } });
        var data = '', oversized = false, exitCode = null;
        child.stdout.on('data', function (chunk) { if (data.length + chunk.length > 1048576) { oversized = true; } else { data += chunk.toString(); } });
        child.on('exit', function (code) { exitCode = code; });
        child.waitExit();
        if (!oversized && exitCode === 0)
        {
            var entries = data.trim().split('\n');
            for (var n = 0; n < entries.length; ++n)
            {
                var entry = entries[n].split(':');
                if (entry.length === 7 && /^\d+$/.test(entry[2]) && Number(entry[2]) === id) { found.push(entry); }
            }
        }
    }
    if (found.length !== 1 || !/^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$/.test(found[0][0]) ||
        found[0][5].charAt(0) !== '/' || /[\x00-\x1f\x7f]/.test(found[0][5])) { throw new Error('Ambiguous session account'); }
    return { name: found[0][0], home: found[0][5] };
}
function environment(bytes, id)
{
    var entries = [], env = {}, offset = 0;
    if (bytes.length > 1048576) { throw new Error('Session environment exceeds limit'); }
    // Native Agent Buffer.toString() stops at NUL. Split bytes before decoding.
    for (var i = 0; i < bytes.length; ++i)
    {
        if (bytes[i] === 0) { entries.push(bytes.slice(offset, i).toString()); offset = i + 1; }
    }
    if (offset !== bytes.length) { throw new Error('Unterminated session environment'); }
    for (var i = 0; i < entries.length; ++i)
    {
        var equals = entries[i].indexOf('='), key = entries[i].substring(0, equals), value = entries[i].substring(equals + 1);
        if (equals < 1 || keys.indexOf(key) < 0) { continue; }
        if (Object.prototype.hasOwnProperty.call(env, key) || value.length > 16384 || /[\x00-\x1f\x7f]/.test(value)) { throw new Error('Invalid session environment'); }
        env[key] = value;
    }
    if (!env.DBUS_SESSION_BUS_ADDRESS || env.XDG_RUNTIME_DIR !== '/run/user/' + id) { throw new Error('Missing session bus or runtime directory'); }
    return env;
}
function snapshot(pid)
{
    if (typeof pid !== 'string' || !/^[1-9]\d{0,9}$/.test(pid)) { throw new Error('Invalid Shell PID'); }
    var incarnation = start(pid), base = '/proc/' + pid + '/';
    if (read(base + 'comm', 64).trim() !== 'gnome-shell') { throw new Error('Not a GNOME Shell session'); }
    var id = uid(read(base + 'status', 65536));
    if (!id) { throw new Error('Root Shell is not a desktop session'); }
    var user = account(id), env = environment(fs.readFileSync(base + 'environ'), id);
    if (start(pid) !== incarnation || uid(read(base + 'status', 65536)) !== id) { throw new Error('Session changed during discovery'); }
    return { pid: pid, uid: id, start: incarnation, user: user, env: env };
}
function sessions()
{
    root();
    var result = [], pids = fs.readdirSync('/proc');
    for (var i = 0; i < pids.length; ++i)
    {
        if (!/^[1-9]\d{0,9}$/.test(pids[i])) { continue; }
        try { var s = snapshot(pids[i]); result.push({ pid: s.pid, uid: s.uid, start: s.start }); }
        catch (error) { /* Unrelated, departed, or ambiguous processes are ineligible. */ }
    }
    return result;
}
function run(session, operation)
{
    root();
    var signout = operation === 'offer-sign-out' || operation === 'inspect-sign-out';
    if (!signout && operation !== 'inspect' && operation !== 'prepare') { throw new Error('Invalid GNOME session operation'); }
    if (!session || typeof session.start !== 'string') { throw new Error('Expected discovered session'); }
    var s = snapshot(session.pid);
    if (s.uid !== session.uid || s.start !== session.start) { throw new Error('Session changed before activation'); }
    if (signout && s.env.XDG_SESSION_ID !== undefined && !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(s.env.XDG_SESSION_ID))
        return { state: 'deferred', changed: false, reason: 'Invalid Shell session ID' };
    var paths = ['/usr/bin/timeout', '/usr/sbin/runuser', '/usr/bin/env', '/usr/bin/gjs'];
    for (var i = 0; i < paths.length; ++i) { if (!fs.existsSync(paths[i])) { throw new Error('Missing activation prerequisite: ' + paths[i]); } }
    var args = ['timeout', '--kill-after=1s', operation === 'offer-sign-out' ? '60s' : '8s', paths[1], '-u', s.user.name, '--', paths[2], '-i',
        'HOME=' + s.user.home, 'USER=' + s.user.name, 'LOGNAME=' + s.user.name, 'PATH=/usr/bin:/bin', 'LANG=C.UTF-8'];
    for (var i = 0; i < keys.length; ++i) { if (s.env[keys[i]] !== undefined) { args.push(keys[i] + '=' + s.env[keys[i]]); } }
    if (signout) { args.push(paths[3], '-c', require('linux-gnome-signout-source'), s.pid, s.env.XDG_SESSION_ID || '-', operation === 'offer-sign-out' ? 'offer' : 'inspect'); }
    else { args.push(paths[3], '-c', require('linux-gnome-activation-source'), operation); }
    return execute(paths[0], args, { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' });
}
function execute(path, args, env)
{
    var child = require('child_process').execFile(path, args, { env: env });
    var output = '', overflow = false, exit = null;
    child.stdout.on('data', function (data) { if (output.length + data.length > 32768) { overflow = true; } else { output += data.toString(); } });
    // Do not expose the session environment or arbitrary GJS diagnostics to UI.
    child.stderr.on('data', function () {});
    child.on('exit', function (code) { exit = code; });
    child.waitExit();
    if (exit !== 0 || overflow) { return { state: 'launcher-error', changed: null, exitCode: exit, overflow: overflow }; }
    try
    {
        var result = JSON.parse(output.trim());
        if (!result || typeof result.state !== 'string' || (result.changed !== null && typeof result.changed !== 'boolean')) { throw new Error('Invalid helper result'); }
        return result;
    }
    catch (error) { return { state: 'launcher-error', changed: null, detail: 'Invalid activation result' }; }
}
function prepareLogin()
{
    if (process.platform !== 'linux') { throw new Error('Linux session required'); }
    var id = uid(read('/proc/self/status', 65536));
    if (!id) { throw new Error('User session required'); }
    var user = account(id), env = environment(fs.readFileSync('/proc/self/environ'), id);
    env.HOME = user.home; env.USER = user.name; env.LOGNAME = user.name; env.PATH = '/usr/bin:/bin'; env.LANG = 'C.UTF-8';
    if (!fs.existsSync('/usr/bin/timeout') || !fs.existsSync('/usr/bin/gjs')) { throw new Error('Missing GNOME activation prerequisite'); }
    return execute('/usr/bin/timeout', ['timeout', '--kill-after=1s', '8s', '/usr/bin/gjs', '-c', require('linux-gnome-activation-source'), 'prepare'], env);
}
function prepareCurrent()
{
    var found = sessions(), results = [], active = found.length > 0;
    for (var i = 0; i < found.length; ++i)
    {
        var result;
        try { result = run(found[i], 'prepare'); }
        catch (error) { result = { state: 'launcher-error', changed: null, detail: String(error) }; }
        results.push({ session: found[i], result: result });
        if (result.state !== 'active') { active = false; }
    }
    return { state: !found.length ? 'no-running-gnome' : (active ? 'current-sessions-active' : 'activation-pending'), sessions: results };
}
function prepareGreeter()
{
    root();
    var binaries = ['/usr/sbin/gdm3', '/usr/sbin/gdm', '/usr/bin/gdm'], present = false;
    for (var i = 0; i < binaries.length; ++i) { if (fs.existsSync(binaries[i])) { present = true; } }
    if (!present) { return { state: 'not-applicable' }; }
    if (fs.existsSync('/etc/X11/default-display-manager') && binaries.indexOf(read('/etc/X11/default-display-manager', 4096).trim()) < 0)
        return { state: 'not-applicable' };
    var rows = read('/etc/passwd', 1048576).split('\n'), candidates = [];
    for (var i = 0; i < rows.length; ++i)
    {
        var fields = rows[i].split(':');
        if (fields.length === 7 && greeterNames.indexOf(fields[0]) >= 0 && /^[1-9]\d*$/.test(fields[2]))
            candidates.push({ uid: Number(fields[2]), name: fields[0] });
    }
    if (candidates.length > 1) { return { state: 'unsupported-greeter-account' }; }
    var found = sessions(), running = [];
    for (var f = 0; f < found.length; ++f)
    {
        try
        {
            var current = snapshot(found[f].pid);
            if (current.uid === found[f].uid && current.start === found[f].start && greeterNames.indexOf(current.user.name) >= 0) { running.push(found[f]); }
        }
        catch (error) { /* Departed or changed sessions are not activation targets. */ }
    }
    if (running.length) { return { state: 'greeter-running', sessions: running }; }
    // Modern GDM uses a transient account and a private per-seat config home.
    // The owned Shell@gdm startup hook configures that actual account on launch;
    // writing the legacy static gdm home would neither persist nor affect it.
    if (fs.existsSync('/usr/lib/systemd/user/gnome-session@gnome-login.target.d/gnome-login.session.conf'))
        return { state: 'greeter-startup-ready', activation: 'next-greeter', persisted: false };
    if (candidates.length !== 1) { return { state: 'unsupported-greeter-account' }; }
    var target = candidates[0], user = account(target.uid);
    if (user.name !== target.name) { return { state: 'unsupported-greeter-account' }; }
    var profile = '/etc/dconf/profile/' + user.name;
    if (!fs.existsSync(profile)) { profile = '/usr/share/dconf/profile/' + user.name; }
    if (!fs.existsSync(profile)) { return { state: 'unsupported-greeter-profile' }; }
    var lines = read(profile, 65536).split('\n').filter(function (line) { return line.trim() && line.trim().charAt(0) !== '#'; });
    // Do not silently fall back to an unrelated profile or a system-only DB.
    if (!lines.length || lines[0].trim() !== 'user-db:user') { return { state: 'unsupported-greeter-profile' }; }
    var paths = ['/usr/bin/timeout', '/usr/sbin/runuser', '/usr/bin/env', '/usr/bin/dbus-run-session', '/usr/bin/gjs'];
    for (var i = 0; i < paths.length; ++i) { if (!fs.existsSync(paths[i])) { throw new Error('Missing greeter preparation prerequisite: ' + paths[i]); } }
    var args = ['timeout', '--kill-after=1s', '8s', paths[1], '-u', user.name, '--', paths[2], '-i',
        'HOME=' + user.home, 'USER=' + user.name, 'LOGNAME=' + user.name, 'PATH=/usr/bin:/bin', 'LANG=C.UTF-8', 'DCONF_PROFILE=' + user.name,
        paths[3], '--', paths[4], '-c', require('linux-gnome-activation-source'), 'prepare-greeter'];
    var clean = { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' };
    var prepared = execute(paths[0], args, clean);
    if (prepared.state !== 'greeter-configured' || !prepared.configured) { return prepared; }
    // A fresh bus/backend must see the saved setting before readiness is claimed.
    args[args.length - 1] = 'inspect-greeter';
    var verified = execute(paths[0], args, clean);
    if (verified.state !== 'greeter-configured' || !verified.configured || verified.changed !== false)
        return { state: 'greeter-verification-failed', changed: prepared.changed, verification: verified };
    return { state: 'greeter-prepared', uid: target.uid, profile: user.name, changed: prepared.changed, persisted: true };
}
function offerSignOut(current)
{
    root();
    var results = [], rows = current && current.sessions;
    if (!Array.isArray(rows)) { return results; }
    for (var i = 0; i < rows.length; ++i)
    {
        if (!rows[i].result || rows[i].result.state !== 'needs-sign-in' || !rows[i].result.configured || rows[i].result.globallyDisabled) { continue; }
        try { var user = snapshot(rows[i].session.pid).user.name; if (greeterNames.indexOf(user) >= 0) { continue; } }
        catch (error) { /* run() below returns a deferred identity failure. */ }
        var result;
        try { result = run(rows[i].session, 'offer-sign-out'); }
        catch (error) { result = { state: 'deferred', changed: false, reason: String(error) }; }
        results.push({ session: rows[i].session, result: result });
    }
    return results;
}
function refreshGreeter(session, mode)
{
    root();
    if (mode !== 'inspect' && mode !== 'offer') { throw new Error('Invalid greeter refresh operation'); }
    if (!session || typeof session.start !== 'string') { throw new Error('Expected discovered greeter'); }
    var s = snapshot(session.pid);
    if (s.uid !== session.uid || s.start !== session.start || greeterNames.indexOf(s.user.name) < 0)
        return { state: 'deferred', changed: false, reason: 'Greeter identity changed' };
    if (!fs.existsSync('/usr/bin/timeout') || !fs.existsSync('/usr/bin/gjs')) { throw new Error('Missing greeter refresh prerequisite'); }
    return execute('/usr/bin/timeout', ['timeout', '--foreground', '--kill-after=1s', mode === 'offer' ? '60s' : '12s',
        '/usr/bin/gjs', '-c', require('linux-gnome-greeter-source'), mode, s.pid, String(s.uid), s.start], { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' });
}
function offerGreeterRefresh(current)
{
    root();
    var results = [], rows = current && current.sessions;
    if (!Array.isArray(rows)) { return results; }
    for (var i = 0; i < rows.length; ++i)
    {
        if (!rows[i].result || rows[i].result.state !== 'needs-sign-in' || !rows[i].result.configured || rows[i].result.globallyDisabled) { continue; }
        try
        {
            var s = snapshot(rows[i].session.pid);
            if (greeterNames.indexOf(s.user.name) < 0) { continue; }
            results.push({ session: rows[i].session, result: refreshGreeter(rows[i].session, 'offer') });
        }
        catch (error) { results.push({ session: rows[i].session, result: { state: 'deferred', changed: false, reason: String(error) } }); }
    }
    return results;
}
module.exports = { sessions: sessions, run: run, prepareCurrent: prepareCurrent, prepareLogin: prepareLogin, prepareGreeter: prepareGreeter, offerSignOut: offerSignOut, refreshGreeter: refreshGreeter, offerGreeterRefresh: offerGreeterRefresh };
