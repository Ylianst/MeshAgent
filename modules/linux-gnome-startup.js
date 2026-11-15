/* SPDX-License-Identifier: Apache-2.0 */
// Each installed service owns one fixed-directory startup entry. The public
// entry runs as the session user; private Agent enrollment directories stay private.
// Preserve exact known launcher formats when changing this entry after release.
var launch = "var code=1;try{var r=require('linux-gnome-session').prepareLogin();if(r.state==='active'){code=0;}else{console.log('GNOME remote control activation: '+r.state);}}catch(e){console.log('GNOME remote control activation failed');}process.exit(code);";
function legacyContent(path)
{
    if (typeof path !== 'string' || path.charAt(0) !== '/' || path.length > 4096 || /[\x00-\x1f\x7f=]/.test(path)) { throw new Error('Invalid installed Agent path'); }
    // Exec quoting is decoded after Desktop Entry string escaping. Percent is
    // a separate field-code grammar and must be doubled even inside quotes.
    var quoted = '"' + path.replace(/[%]/g, '%%').replace(/[\\"`$]/g, function (c) { return '\\' + c; }) + '"';
    // GLib checks the executable before field-code expansion. A fixed env
    // executable lets literal %% in the Agent path expand as an argument.
    var exec = '/usr/bin/env -- ' + quoted.replace(/\\/g, '\\\\') + ' -b64exec ' + Buffer.from(launch, 'utf8').toString('base64');
    return Buffer.from('# MeshAgent GNOME autostart 1\n[Desktop Entry]\nType=Application\nName=MeshAgent GNOME activation\nExec=' + exec +
        '\nOnlyShowIn=GNOME;\nNoDisplay=true\nTerminal=false\nX-GNOME-Autostart-enabled=true\n', 'utf8');
}
function content(path)
{
    // Keep identity/path validation and migration bound to this service, even
    // though the launcher no longer executes its private installed binary.
    legacyContent(path);
    var source = require('linux-gnome-activation-source');
    if (typeof source !== 'string' || !source.length) { throw new Error('Missing GNOME activation source'); }
    var code = "eval(imports.byteArray.toString(imports.gi.GLib.base64_decode('" + Buffer.from(source, 'utf8').toString('base64') + "')));";
    var exec = '/usr/bin/timeout --kill-after=1s 8s /usr/bin/gjs -c "' + code + '" prepare';
    var bytes = Buffer.from('# MeshAgent GNOME autostart 2\n[Desktop Entry]\nType=Application\nName=MeshAgent GNOME activation\nExec=' + exec +
        '\nOnlyShowIn=GNOME;\nNoDisplay=true\nTerminal=false\nX-GNOME-Autostart-enabled=true\nX-MeshAgent-Service=' + Buffer.from(path, 'utf8').toString('base64') + '\n', 'utf8');
    if (bytes.length > 32768) { throw new Error('GNOME activation entry exceeds native bound'); }
    return bytes;
}
function greeterContent(path)
{
    legacyContent(path);
    var source = require('linux-gnome-activation-source');
    var code = "eval(imports.byteArray.toString(imports.gi.GLib.base64_decode('" + Buffer.from(source, 'utf8').toString('base64') + "')));";
    // Prepare only the GDM Shell instance before it reads extension settings.
    // Failure must never fail the compositor or prevent local login.
    return Buffer.from('# MeshAgent GNOME greeter activation 1\n[Service]\nExecStartPre=-/usr/bin/timeout --kill-after=1s 8s /usr/bin/gjs -c "' + code + '" prepare-greeter\n# Service=' + Buffer.from(path,'utf8').toString('base64') + '\n','utf8');
}
function installGreeter(store,owner,path,result)
{
    if (!result || result.status !== 1) { return result; }
    var greeter = store.greeterStartupInstall(owner,greeterContent(path));
    if (greeter && result.changed) { greeter.changed = true; }
    return greeter;
}
function install(owner, path)
{
    var store = require('_gnome-companion-store'), bytes = content(path);
    var result = store.autostartInstall(owner, bytes);
    if (!result || result.status !== 0) { return installGreeter(store,owner,path,result); }
    // Only the exact previous Agent launcher may be migrated. Edited entries,
    // symlinks, bad ownership/modes, and hard links remain native refusals.
    var previous = store.autostartRemove(owner, legacyContent(path));
    if (!previous || previous.status !== 1) { return previous; }
    result = store.autostartInstall(owner, bytes);
    if (result && previous.changed) { result.changed = true; }
    return installGreeter(store,owner,path,result);
}
function remove(owner, path)
{
    var store = require('_gnome-companion-store');
    var result = store.autostartRemove(owner, content(path));
    if (result && result.status === 0) { result = store.autostartRemove(owner, legacyContent(path)); }
    if (!result || result.status !== 1) { return result; }
    var greeter = store.greeterStartupRemove(owner,greeterContent(path));
    if (greeter && result.changed) { greeter.changed = true; }
    return greeter;
}
module.exports = { install: install, remove: remove };
