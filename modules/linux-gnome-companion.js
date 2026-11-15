/* SPDX-License-Identifier: Apache-2.0 */
// Installer ownership and preparation of existing GNOME sessions.
// File ownership, current-session activation, future sign-in preparation and
// greeter preparation are distinct results. A durable files-ready transaction
// must not be reported as a live Shell bridge. The caller handles the explicit
// one-time sign-out choice; remote connections and unattended updates do not.
// Shared service leases and rollback rules are in docs/Wayland-Maintenance.md.
var ROOT = '/usr/share/gnome-shell/extensions/';
var UUID = 'meshagent-console@meshcentral.com';
function digest(bytes) { return require('SHA256Stream').create().syncHash(bytes).toString('hex').toLowerCase(); }
function normalized(service)
{
    if (!service || typeof service.name !== 'string' || !service.name.length || service.name.length > 256 || /[\x00\r\n]/.test(service.name) ||
        typeof service.path !== 'string' || service.path.charAt(0) !== '/' || service.path.length > 4096 || /[\x00-\x1f\x7f=]/.test(service.path))
        throw new Error('Invalid companion service identity');
    var parts = service.path.split('/'), normalized = [];
    for (var i = 0; i < parts.length; ++i)
    {
        if (!parts[i] || parts[i] === '.') { continue; }
        if (parts[i] === '..') { if (!normalized.length) { throw new Error('Invalid companion service path'); } normalized.pop(); }
        else { normalized.push(parts[i]); }
    }
    if (!normalized.length) { throw new Error('Invalid companion executable path'); }
    return { name: service.name.split(' ').join('_'), path: '/' + normalized.join('/') };
}
function identity(service) { var s = normalized(service); return digest(Buffer.from('MeshAgent GNOME service 1\n' + s.name + '\n' + s.path, 'utf8')); }
function failure(stage, result, error)
{
    return { state: 'error', stage: stage, status: result ? result.status : 0,
        errno: result ? result.errno : 0, changed: result ? result.changed : (stage === 'detect' || stage === 'identity' || stage === 'payload' ? false : null),
        backup: result ? result.backup : '', detail: error ? String(error) : '' };
}
function finish(store, result, stage)
{
    if (!result || result.status !== 1) { return failure(stage, result); }
    if (result.backup)
    {
        var committed;
        try { committed = store.commit(result.backup); }
        catch (error) {
            var failed = failure(stage + '-commit', null, error);
            failed.backup = result.backup; failed.currentChanged = result.changed;
            return failed;
        }
        if (!committed || committed.status !== 1)
        {
            var failed = failure(stage + '-commit', committed); failed.backup = result.backup; failed.currentChanged = result.changed;
            return failed;
        }
    }
    return null;
}
function release(store, owner)
{
    var result = store.release(owner);
    return finish(store, result, 'release');
}
function install(service, previous)
{
    var stage = 'detect';
    try
    {
        if (process.platform !== 'linux') { return { state: 'not-applicable' }; }
        var fs = require('fs');
        if (!fs.existsSync('/usr/bin/gnome-shell') && !fs.existsSync(ROOT + UUID)) { return { state: 'not-applicable' }; }
        stage = 'identity';
        var current = normalized(service), old = previous ? normalized(previous) : current;
        var owner = identity(current), prior = identity(old);
        stage = 'payload';
        var assets = require('linux-gnome-companion-assets'), files = [];
        if (assets.uuid !== UUID || typeof assets.version !== 'number' || assets.version < 1 || assets.version > 4294967295 || assets.version !== Math.floor(assets.version))
            throw new Error('Invalid companion generation');
        var names = ['metadata.json', 'protocol.js', 'extension.js'];
        for (var i = 0; i < names.length; ++i)
        {
            var asset = assets.files[names[i]], bytes = Buffer.from(asset.data, 'base64');
            if (asset.encoding !== 'base64' || bytes.length !== asset.bytes || digest(bytes) !== asset.sha256)
                throw new Error('Invalid companion asset: ' + names[i]);
            files.push(bytes);
        }
        var metadata = JSON.parse(files[0].toString());
        if (metadata.uuid !== UUID || metadata.version !== assets.version) { throw new Error('Companion metadata generation mismatch'); }
        stage = 'acquire';
        var store = require('_gnome-companion-store');
        var result = store.acquire(owner, assets.version, files[0], files[1], files[2]);
        var error = finish(store, result, stage);
        if (error) { return error; }
        stage = 'startup-install';
        var startup = require('linux-gnome-startup'), startupResult = startup.install(owner, current.path);
        error = finish(store, startupResult, stage);
        if (error) { error.activeOwner = owner; return error; }
        if (prior !== owner)
        {
            stage = 'startup-transfer'; error = finish(store, startup.remove(prior, old.path), stage);
            if (error) { error.activeOwner = owner; return error; }
            stage = 'transfer'; error = release(store, prior);
            if (error) { error.stage = 'transfer-' + error.stage; error.activeOwner = owner; return error; }
        }
        // Never roll back durable ownership because a desktop activation failed.
        // Greeter coverage and sign-out consent still need final qualification.
        var currentSessions;
        try { currentSessions = require('linux-gnome-session').prepareCurrent(); }
        catch (activationError) { currentSessions = { state: 'activation-pending', detail: String(activationError), sessions: [] }; }
        var greeter;
        try { greeter = require('linux-gnome-session').prepareGreeter(); }
        catch (greeterError) { greeter = { state: 'activation-pending', detail: String(greeterError) }; }
        return { state: 'files-ready', changed: result.changed, activation: 'pending', owner: owner, startup: 'ready', currentSessions: currentSessions, greeter: greeter };
    }
    catch (error) { return failure(stage, null, error); }
}
function uninstall(service)
{
    var stage = 'detect';
    try
    {
        if (process.platform !== 'linux') { return { state: 'not-applicable' }; }
        var fs = require('fs');
        stage = 'identity'; var current = normalized(service), owner = identity(current);
        stage = 'startup-remove';
        var store = require('_gnome-companion-store');
        var error = finish(store, require('linux-gnome-startup').remove(owner, current.path), stage);
        if (error) { return error; }
        if (!fs.existsSync(ROOT + UUID)) { return { state: 'not-applicable' }; }
        stage = 'release'; var error = release(require('_gnome-companion-store'), owner);
        if (error) { return error; }
        return { state: fs.existsSync(ROOT + UUID) ? 'files-retained' : 'files-removed' };
    }
    catch (error) { return failure(stage, null, error); }
}
module.exports = { install: install, uninstall: uninstall };
