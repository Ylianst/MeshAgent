/*
Copyright 2018 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

var promise = require('promise');

if (process.platform == 'linux' || process.platform == 'darwin' || process.platform == 'freebsd')
{
    function findPath(app)
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = '';
        child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
        if (process.platform == 'linux' || process.platform == 'freebsd')
        {
            child.stdin.write("whereis " + app + " | awk '{ print $2 }'\nexit\n");
        }
        else
        {
            child.stdin.write("whereis " + app + "\nexit\n");
        }
        child.waitExit();
        child.stdout.str = child.stdout.str.trim();
        if (process.platform == 'freebsd' && child.stdout.str == '' && require('fs').existsSync('/usr/local/bin/' + app)) { return ('/usr/local/bin/' + app); }
        return (child.stdout.str == '' ? null : child.stdout.str);
    }
}

function Toaster()
{
    this._ObjectID = 'toaster';
    this.Toast = function Toast(title, caption, tsid)
    {
        var retVal = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        retVal.title = title;
        retVal.caption = caption;

        switch (process.platform)
        {
            case 'win32':
                {
                    var cid;
                    retVal.options = { env: { _title: title, _caption: caption } };
                    for (var c1e in process.env)
                    {
                        retVal.options.env[c1e] = process.env[c1e];
                    }
                    try
                    {
                        retVal.options.uid = tsid == null ? require('user-sessions').consoleUid() : tsid;
                        if (retVal.options.uid == (cid = require('user-sessions').getProcessOwnerName(process.pid).tsid))
                        {
                            delete retVal.options.uid;
                        }
                        else
                        {
                            if(tsid != null && cid != 0)
                            {
                                retVal._rej('Insufficient permission to display toast as uid: ' + tsid);
                                return (retVal);
                            }
                            retVal.options.type = require('child_process').SpawnTypes.USER;
                        }
                    }
                    catch (ee)
                    {
                        retVal._rej('Cannot display user notification when a user is not logged in');
                        return (retVal);
                    }

                    retVal.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['powershell', '-noprofile', '-nologo', '-command', '-'], retVal.options);
                    retVal.child.descriptorMetadata = 'toaster';
                    retVal.child.toast = retVal;
                    retVal.child.stdout.stdin = retVal.child.stdin;
                    retVal.child.stderr.stdin = retVal.child.stdin;
                    retVal.child.stdout.on('data', function (c) { if (c.toString().includes('<DISMISSED>')) { this.stdin.write('exit\n'); } });
                    retVal.child.stderr.once('data', function (c) { this.stdin.write('$objBalloon.dispose();exit\n'); });
                    retVal.child.stdin.write('[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")\r\n');
                    retVal.child.stdin.write('$objBalloon = New-Object System.Windows.Forms.NotifyIcon\r\n');
                    retVal.child.stdin.write('$objBalloon.Icon = [System.Drawing.SystemIcons]::Information\r\n');
                    retVal.child.stdin.write('$objBalloon.Visible = $True\r\n');
                    retVal.child.stdin.write('Register-ObjectEvent -InputObject $objBalloon -EventName BalloonTipClosed -Action { $objBalloon.dispose();Write-Host "<`DISMISSED`>" }')
                    retVal.child.stdin.write('$objBalloon.ShowBalloonTip(10000, $env:_title, $env:_caption, 0)\r\n');
                    retVal.child.timeout = setTimeout(function (c)
                    {
                        c.timeout = null;
                        c.stdin.write('$objBalloon.dispose();exit\n');
                    }, 10000, retVal.child);
                    retVal.child.on('exit', function ()
                    {
                        if (this.timeout != null) { clearTimeout(this.timeout); }
                        this.toast._res('DISMISSED');
                    });
                    
                    return (retVal);
                }
                break;
	        case 'freebsd':
            case 'linux':
                {
                    try
                    {
                        retVal.consoleUid = require('user-sessions').consoleUid();
                        retVal.xinfo = require('monitor-info').getXInfo(retVal.consoleUid);
			            retVal.username = require('user-sessions').getUsername(retVal.consoleUid);
                    }
                    catch (xxe)
                    {
                        retVal._rej(xxe);
                        return (retVal);
                    }

                    if (require('message-box').zenity)
                    {
                        if (process.platform == 'linux' && !require('linux-dbus').hasService('org.freedesktop.Notifications'))
                        {

                            // No D-Bus service to handle notifications, so we must fake a notification with ZENITY --info
                            if (require('message-box').zenity.timeout)
                            {
                                // Timeout Supported
                                retVal.child = require('child_process').execFile(require('message-box').zenity.path, ['zenity', '--info', '--title=' + retVal.title, '--text=' + retVal.caption, '--timeout=5'], { uid: retVal.consoleUid, env: { XAUTHORITY: retVal.xinfo.xauthority, DISPLAY: retVal.xinfo.display } });
                            }
                            else
                            {
                                // No Timeout Support, so we must fake it
                                retVal.child = require('child_process').execFile(require('message-box').zenity.path, ['zenity', '--info', '--title=' + retVal.title, '--text=' + retVal.caption], { uid: retVal.consoleUid, env: { XAUTHORITY: retVal.xinfo.xauthority, DISPLAY: retVal.xinfo.display } });
                                retVal.child.timeout = setTimeout(function (c) { c.timeout = null; c.kill(); }, 5000, retVal.child);
                            }
                            retVal.child.descriptorMetadata = 'toaster (zenity/messagebox)'
                        }                        
                        else if (require('message-box').zenity.broken || require('message-box').zenity.version[0] < 3 || (require('message-box').zenity.version[0] == 3 && require('message-box').zenity.version[1] < 10))
                        {

                            // ZENITY Notification is broken
                            if (require('message-box').notifysend)
                            {
                                // Using notify-send
                                if (require('user-sessions').whoami() == 'root')
                                {
                                    // We're root, so we must run in correct context
                                    var xdg = require('user-sessions').findEnv(retVal.consoleUid, 'XDG_RUNTIME_DIR'); if (xdg == null) { xdg = ''; }
                                    retVal.child = require('child_process').execFile('/bin/sh', ['sh']);
                                    retVal.child.stdin.write('su - ' + retVal.username + ' -c "export DISPLAY=' + retVal.xinfo.display + '; export XDG_RUNTIME_DIR=' + xdg + '; notify-send \'' + retVal.title + '\' \'' + retVal.caption + '\'"\nexit\n');
                                }
                                else
                                {
                                    // We're a regular user, so we don't need to do anything special
                                    retVal.child = require('child_process').execFile(require('message-box').notifysend.path, ['notify-send', retVal.title, retVal.caption]);
                                }
                                retVal.child.descriptorMetadata = 'toaster (notify-send)'
                            }
                            else
                            {
                                // Faking notification with ZENITY --info
                                if (require('message-box').zenity.timeout)
                                {
                                    // Timeout Supported
                                    retVal.child = require('child_process').execFile(require('message-box').zenity.path, ['zenity', '--info', '--title=' + retVal.title, '--text=' + retVal.caption, '--timeout=5'], { uid: retVal.consoleUid, env: { XAUTHORITY: retVal.xinfo.xauthority, DISPLAY: retVal.xinfo.display } });
                                }
                                else
                                {
                                    // No Timeout Support, so we must fake it
                                    retVal.child = require('child_process').execFile(require('message-box').zenity.path, ['zenity', '--info', '--title=' + retVal.title, '--text=' + retVal.caption], { uid: retVal.consoleUid, env: { XAUTHORITY: retVal.xinfo.xauthority, DISPLAY: retVal.xinfo.display } });
                                    retVal.child.timeout = setTimeout(function (c) { c.timeout = null; c.kill(); }, 5000, retVal.child);
                                }
                                retVal.child.descriptorMetadata = 'toaster (zenity/messagebox)'
                            }
                        }
                        else
                        {

                            // Use ZENITY Notification
                            retVal.child = require('child_process').execFile(require('message-box').zenity.path, ['zenity', '--notification', '--title=' + title, '--text=' + caption, '--timeout=5'], { uid: retVal.consoleUid, env: { XAUTHORITY: retVal.xinfo.xauthority, DISPLAY: retVal.xinfo.display } });                   
                            retVal.child.descriptorMetadata = 'toaster (zenity/notification)'
                        }
                        retVal.child.parent = retVal;
                        retVal.child.stderr.str = '';
                        retVal.child.stderr.on('data', function (chunk) { this.str += chunk.toString();  });
                        retVal.child.stdout.on('data', function (chunk) { });
                        retVal.child.on('exit', function (code)
                        {
                            if (this.timeout) { clearTimeout(this.timeout); }
                            this.parent._res('DISMISSED');
                        });
                    }
                    else
                    {
                        util = findPath('kdialog');
                        if (util) 
			            {
                            // use KDIALOG
                            var xdg = require('user-sessions').findEnv(retVal.consoleUid, 'XDG_RUNTIME_DIR'); if (xdg == null) { xdg = ''; }
                            if (!retVal.xinfo || !retVal.xinfo.display || !retVal.xinfo.xauthority)
                            {
                                retVal._rej('Internal Error');
                                return (retVal);
                            }
		
                            retVal._notify = require('child_process').execFile(util, ['kdialog', '--title', retVal.title, '--passivepopup', retVal.caption, '5'], { uid: retVal.consoleUid, env: { DISPLAY: retVal.xinfo.display, XAUTHORITY: retVal.xinfo.xauthority, XDG_RUNTIME_DIR: xdg } });
                            retVal._notify.descriptorMetadata = 'toaster (kdialog)'
                            retVal._notify.parent = retVal;
                            retVal._notify.stdout.on('data', function (chunk) { });
                            retVal._notify.stderr.on('data', function (chunk) { });
                            retVal._notify.on('exit', function (code) { this.parent._res('DISMISSED'); });
                        }
                        else
                        {
                            if (require('message-box').notifysend)
                            {
                                // Using notify-send
                                if (require('user-sessions').whoami() == 'root')
                                {
                                    // We're root, so we must run in correct context
                                    var xdg = require('user-sessions').findEnv(retVal.consoleUid, 'XDG_RUNTIME_DIR'); if (xdg == null) { xdg = ''; }
                                    retVal.child = require('child_process').execFile('/bin/sh', ['sh']);
                                    retVal.child.stdin.write('su - ' + retVal.username + ' -c "export DISPLAY=' + retVal.xinfo.display + '; export XDG_RUNTIME_DIR=' + xdg + '; notify-send \'' + retVal.title + '\' \'' + retVal.caption + '\'"\nexit\n');
                                }
                                else
                                {
                                    // We're a regular user, so we don't need to do anything special
                                    retVal.child = require('child_process').execFile(require('message-box').notifysend.path, ['notify-send', retVal.title, retVal.caption]);
                                }
                                retVal.child.descriptorMetadata = 'toaster (notify-send)'
                            }
                            else if (require('message-box').xmessage)
                            {
                                retVal._mb = require('message-box').create(title, caption, 5, 'OK');
                                retVal._mb.ret = retVal;
                                retVal._mb.then(function () { this.ret._res('DISMISSED'); }, function () { this.ret._res('DISMISSED'); });
                            }
                            else
                            {
                                retVal._rej('Zenity/KDialog/xmessage not found');
                            }
                        }
                    }
                }
                break;
            case 'darwin':
                retVal._toast = require('message-box').notify(title, caption);
                retVal._toast.parent = retVal;
                retVal._toast.then(function (v) { this.parent._res(v); }, function (e) { this.parent._rej(e); });
                break;
        }

        return (retVal);
    };
    if(process.platform == 'win32')
    {
        this._containerToast = function _containerToast(caption, title)
        {
            var toast;
            var balloon;

            try
            {
                toast = require('win-console');
                balloon = toast.SetTrayIcon({ szInfo: caption, szInfoTitle: title, balloonOnly: true });
                balloon.on('ToastDismissed', function () { process.exit(); });
            }
            catch(e)
            {
                process.exit();
            }
            try
            {
                require('child-container').message({ status: 'ok', pid: process.pid});
            }
            catch(ee)
            {
                process.exit();
            }
            var t = setTimeout(function (b) { b.remove(); process.exit(); }, 7000, balloon);
        }
    }
}

module.exports = new Toaster();
if (process.platform == 'linux' && !require('linux-dbus').hasService)
{
    require('linux-dbus').hasService = function hasService(name)
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stdin.write('cat /usr/share/dbus-1/services/*.service | grep "' + name + '" | awk -F= \'{ if( $2=="' + name + '" ) { print $2; } }\'\nexit\n');
        child.waitExit();
        return (child.stdout.str.trim() != '');
    };
}