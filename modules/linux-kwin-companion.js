/* SPDX-License-Identifier: Apache-2.0 */
// Installer boundary: verify embedded fixed assets here, then delegate shared
// root-owned files/leases to install.py and session choices to session.py.
// Service identity includes the executable path so one Agent service cannot
// uninstall another service's relay. This does not move the Agent directory.
function identity(service)
{
    if (!service || typeof service.name !== 'string' || !service.name.length || service.name.length > 256 || /[\x00\r\n]/.test(service.name) ||
        typeof service.path !== 'string' || service.path.charAt(0) !== '/' || /[\x00-\x1f\x7f]/.test(service.path)) { throw new Error('Invalid KWin companion owner'); }
    var parts = service.path.split('/'), path = [];
    for (var i = 0; i < parts.length; ++i) {
        if (!parts[i] || parts[i] === '.') { continue; }
        if (parts[i] === '..') { if (!path.length) { throw new Error('Invalid owner path'); } path.pop(); }
        else { path.push(parts[i]); }
    }
    if (!path.length) { throw new Error('Invalid owner path'); }
    return require('SHA256Stream').create().syncHash(Buffer.from('MeshAgent KWin service 1\n' + service.name.split(' ').join('_') + '\n/' + path.join('/'))).toString('hex').toLowerCase();
}
function run(operation, service)
{
    if (process.platform !== 'linux') { return { state: 'not-applicable', changed: false }; }
    var fs = require('fs');
    if (operation === 'install' && !fs.existsSync('/usr/bin/kwin_wayland')) { return { state: 'not-applicable', changed: false }; }
    var owner = identity(service);
    if (operation === 'uninstall' && !fs.existsSync('/var/lib/meshagent-kwin-wire/owners.json') && !fs.existsSync('/var/lib/meshagent-kwin/owners.json') && !fs.existsSync('/var/lib/meshagent-kwin-wire/capture-' + owner + '.json') && !fs.existsSync('/var/lib/meshagent-kwin-wire/capture-' + owner + '.pending.json')) { return { state: 'not-owned', changed: false }; }
    var assets = require('linux-kwin-companion-assets');
    var bytes = Buffer.from(assets.payload, 'base64');
    if (bytes.length !== assets.bytes || require('SHA256Stream').create().syncHash(bytes).toString('hex').toLowerCase() !== assets.sha256) { throw new Error('Invalid KWin companion payload'); }
    var request = JSON.stringify({ operation: operation, owner: owner, capture_executable: service.path, payload: assets.payload, sha256: assets.sha256 });
    var child = require('child_process').execFile('/usr/bin/timeout', ['timeout', '--foreground', '--kill-after=2s', '30s',
        '/usr/bin/python3', '-c', assets.helper, request], { env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' } });
    var output = '', overflow = false, exit = null;
    child.stdout.on('data', function (data) { if (output.length + data.length > 32768) { overflow = true; } else { output += data.toString(); } });
    child.stderr.on('data', function () {});
    child.on('exit', function (code) { exit = code; });
    child.waitExit();
    if (exit !== 0 || overflow) { return { state: 'error', changed: null, detail: 'KWin helper failed', exitCode: exit }; }
    var result = JSON.parse(output.trim());
    if (!result || typeof result.state !== 'string') { throw new Error('Invalid KWin helper result'); }
    return result;
}
function install(service, previous)
{
    var result = run('install', service);
    if (result.state === 'files-ready' && previous && identity(previous) !== identity(service)) {
        var transfer = run('uninstall', previous);
        if (transfer.state !== 'retained' && transfer.state !== 'not-owned') { result.transfer = transfer; }
    }
    return result;
}
module.exports = { install: install, uninstall: function (service) { return run('uninstall', service); } };
