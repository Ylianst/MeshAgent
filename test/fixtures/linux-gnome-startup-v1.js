/* SPDX-License-Identifier: Apache-2.0 */
// Each installed service owns one fixed-directory startup entry. Stable launch
// code avoids changing the entry when its embedded activation implementation changes.
var launch = "var code=1;try{var r=require('linux-gnome-session').prepareLogin();if(r.state==='active'){code=0;}else{console.log('GNOME remote control activation: '+r.state);}}catch(e){console.log('GNOME remote control activation failed');}process.exit(code);";
function content(path)
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
function install(owner, path) { return require('_gnome-companion-store').autostartInstall(owner, content(path)); }
function remove(owner, path) { return require('_gnome-companion-store').autostartRemove(owner, content(path)); }
module.exports = { install: install, remove: remove };
