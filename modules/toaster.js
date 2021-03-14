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

function stdparser(c)
{
    if (this.str == null) { this.str = ''; }
    this.str += c.toString();
}

if (process.platform == 'linux' || process.platform == 'darwin' || process.platform == 'freebsd')
{
    function findPath(app)
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.on('data', stdparser);
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
        //var retVal = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        var weakRet = WeakReference(new promise(promise.defaultInit));
        if (title == 'MeshCentral') { try { title = require('MeshAgent').displayName; } catch (x) { } }

        weakRet.object.title = title;
        weakRet.object.caption = caption;

        switch (process.platform)
        {
            case 'win32':
                {
                    var cid;
                    weakRet.object.options = { env: { _title: title, _caption: caption } };
                    for (var c1e in process.env)
                    {
                        weakRet.object.options.env[c1e] = process.env[c1e];
                    }
                    try
                    {
                        weakRet.object.options.uid = tsid == null ? require('user-sessions').consoleUid() : tsid;
                        if (weakRet.object.options.uid == (cid = require('user-sessions').getProcessOwnerName(process.pid).tsid))
                        {
                            delete weakRet.object.options.uid;
                        }
                        else
                        {
                            if(tsid != null && cid != 0)
                            {
                                weakRet.object.reject('Insufficient permission to display toast as uid: ' + tsid);
                                return (weakRet.object);
                            }
                            weakRet.object.options.type = require('child_process').SpawnTypes.USER;
                        }
                    }
                    catch (ee)
                    {
                        weakRet.object.reject('Cannot display user notification when a user is not logged in');
                        return (weakRet.object);
                    }

                    
                    weakRet.object.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['powershell', '-noprofile', '-nologo', '-command', '-'], weakRet.object.options);
                    weakRet.object.child.weak = weakRet;
                    weakRet.object.child.descriptorMetadata = 'toaster';
                    weakRet.object.child.stdout.on('data', function (c) { if (c.toString().includes('<DISMISSED>')) { this.parent.stdin.write('exit\n'); } });
                    weakRet.object.child.stderr.once('data', function (c) { this.parent.stdin.write('$objBalloon.dispose();exit\n'); });
                    weakRet.object.child.stdin.write('[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")\r\n');
                    weakRet.object.child.stdin.write('$objBalloon = New-Object System.Windows.Forms.NotifyIcon\r\n');
                    weakRet.object.child.stdin.write('$objBalloon.Icon = [System.Drawing.SystemIcons]::Information\r\n');
                    weakRet.object.child.stdin.write('$objBalloon.Visible = $True\r\n');
                    weakRet.object.child.stdin.write('Register-ObjectEvent -InputObject $objBalloon -EventName BalloonTipClosed -Action { $objBalloon.dispose();Write-Host "<`DISMISSED`>" }')
                    weakRet.object.child.stdin.write('$objBalloon.ShowBalloonTip(10000, $env:_title, $env:_caption, 0)\r\n');
                    weakRet.object.child.timeout = setTimeout(function (c)
                    {
                        c.timeout = null;
                        c.stdin.write('$objBalloon.dispose();exit\n');
                    }, 10000, weakRet.object.child);
                    weakRet.object.child.on('exit', function ()
                    {
                        if (this.weak.isAlive())
                        {
                            var p = this.weak.object;
                            if (p.child.timeout != null) { clearTimeout(p.child.timeout); }
                            p.resolve('DISMISSED');
                            p.child = null;
                            this.weak = null;
                        }
                    });
                    
                    return (weakRet.object);
                }
                break;
	        case 'freebsd':
            case 'linux':
                {
                    try
                    {
                        weakRet.object.consoleUid = require('user-sessions').consoleUid();
                        weakRet.object.xinfo = require('monitor-info').getXInfo(weakRet.object.consoleUid);
                        weakRet.object.username = require('user-sessions').getUsername(weakRet.object.consoleUid);
                    }
                    catch (xxe)
                    {
                        weakRet.object.reject(xxe);
                        return (weakRet.object);
                    }

                    if (require('message-box').zenity)
                    {
                        if (process.platform == 'linux' && !require('linux-dbus').hasService('org.freedesktop.Notifications'))
                        {
                            // No D-Bus service to handle notifications, so we must fake a notification with ZENITY --info
                            if (require('message-box').zenity.timeout)
                            {
                                // Timeout Supported
                                weakRet.object.child = require('child_process').execFile(require('message-box').zenity.path, ['zenity', '--info', '--title=' + weakRet.object.title, '--text=' + weakRet.object.caption, '--timeout=5'], { uid: weakRet.object.consoleUid, env: { XAUTHORITY: weakRet.object.xinfo.xauthority, DISPLAY: weakRet.object.xinfo.display } });
                            }
                            else
                            {
                                // No Timeout Support, so we must fake it
                                weakRet.object.child = require('child_process').execFile(require('message-box').zenity.path, ['zenity', '--info', '--title=' + weakRet.object.title, '--text=' + weakRet.object.caption], { uid: weakRet.object.consoleUid, env: { XAUTHORITY: weakRet.object.xinfo.xauthority, DISPLAY: weakRet.object.xinfo.display } });
                                weakRet.object.child.timeout = setTimeout(function (c) { c.timeout = null; c.kill(); }, 5000, weakRet.object.child);
                            }
                            weakRet.object.child.descriptorMetadata = 'toaster (zenity/messagebox)'
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
                                    var xdg = require('user-sessions').findEnv(weakRet.object.consoleUid, 'XDG_RUNTIME_DIR'); if (xdg == null) { xdg = ''; }
                                    weakRet.object.child = require('child_process').execFile('/bin/sh', ['sh']);
                                    weakRet.object.child.stdin.write('su - ' + weakRet.object.username + ' -c "export DISPLAY=' + weakRet.object.xinfo.display + '; export XDG_RUNTIME_DIR=' + xdg + '; notify-send \'' + weakRet.object.title + '\' \'' + weakRet.object.caption + '\'"\nexit\n');
                                }
                                else
                                {
                                    // We're a regular user, so we don't need to do anything special
                                    weakRet.object.child = require('child_process').execFile(require('message-box').notifysend.path, ['notify-send', weakRet.object.title, weakRet.object.caption]);
                                }
                                weakRet.object.child.descriptorMetadata = 'toaster (notify-send)'
                            }
                            else
                            {
                                // Faking notification with ZENITY --info
                                if (require('message-box').zenity.timeout)
                                {
                                    // Timeout Supported
                                    weakRet.object._mb = require('message-box').create(weakRet.object.title, weakRet.object.caption, 5, 1);
                                    weakRet.object._mb.weak = weakRet;
                                    weakRet.object._mb.then(function () { this.weak.object.resolve('DISMISSED'); }, function (e) { this.weak.object.resolve('DISMISSED'); });
                                    return (weakRet.object);
                                }
                                else
                                {
                                    // No Timeout Support, so we must fake it
                                    weakRet.object.child = require('child_process').execFile(require('message-box').zenity.path, ['zenity', '--info', '--title=' + weakRet.object.title, '--text=' + weakRet.object.caption], { uid: weakRet.object.consoleUid, env: { XAUTHORITY: weakRet.object.xinfo.xauthority, DISPLAY: weakRet.object.xinfo.display } });
                                    weakRet.object.child.timeout = setTimeout(function (c) { c.timeout = null; c.kill(); }, 5000, weakRet.object.child);
                                }
                                weakRet.object.child.descriptorMetadata = 'toaster (zenity/messagebox)'
                            }
                        }
                        else
                        {
                            // Use ZENITY Notification
                            weakRet.object.child = require('child_process').execFile(require('message-box').zenity.path, ['zenity', '--notification', '--title=' + title, '--text=' + caption, '--timeout=5'], { uid: weakRet.object.consoleUid, env: { XAUTHORITY: weakRet.object.xinfo.xauthority, DISPLAY: weakRet.object.xinfo.display } });
                            weakRet.object.child.descriptorMetadata = 'toaster (zenity/notification)'
                        }
                        weakRet.object.child.weak = weakRet;
                        weakRet.object.child.stderr.str = '';
                        weakRet.object.child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                        weakRet.object.child.stdout.on('data', function (chunk) { });
                        weakRet.object.child.on('exit', function (code)
                        {
                            if (this.timeout) { clearTimeout(this.timeout); }
                            this.weak.object.resolve('DISMISSED');
                        });
                    }
                    else
                    {
                        util = findPath('kdialog');
                        if (util) 
			            {
                            // use KDIALOG
                            var xdg = require('user-sessions').findEnv(weakRet.object.consoleUid, 'XDG_RUNTIME_DIR'); if (xdg == null) { xdg = ''; }
                            if (!weakRet.object.xinfo || !weakRet.object.xinfo.display || !weakRet.object.xinfo.xauthority)
                            {
                                weakRet.object.reject('Internal Error');
                                return (weakRet.object);
                            }
		
                            weakRet.object._notify = require('child_process').execFile(util, ['kdialog', '--title', weakRet.object.title, '--passivepopup', weakRet.object.caption, '5'], { uid: weakRet.object.consoleUid, env: { DISPLAY: weakRet.object.xinfo.display, XAUTHORITY: weakRet.object.xinfo.xauthority, XDG_RUNTIME_DIR: xdg } });
                            weakRet.object._notify.descriptorMetadata = 'toaster (kdialog)'
                            weakRet.object._notify.weak = weakRet;
                            weakRet.object._notify.stdout.on('data', function (chunk) { });
                            weakRet.object._notify.stderr.on('data', function (chunk) { });
                            weakRet.object._notify.on('exit', function (code) { this.weak.object.resolve('DISMISSED'); });
                        }
                        else
                        {
                            if (require('message-box').notifysend)
                            {
                                // Using notify-send
                                if (require('user-sessions').whoami() == 'root')
                                {
                                    // We're root, so we must run in correct context
                                    var xdg = require('user-sessions').findEnv(weakRet.object.consoleUid, 'XDG_RUNTIME_DIR'); if (xdg == null) { xdg = ''; }
                                    weakRet.object.child = require('child_process').execFile('/bin/sh', ['sh']);
                                    weakRet.object.child.stdin.write('su - ' + weakRet.object.username + ' -c "export DISPLAY=' + weakRet.object.xinfo.display + '; export XDG_RUNTIME_DIR=' + xdg + '; notify-send \'' + weakRet.object.title + '\' \'' + weakRet.object.caption + '\'"\nexit\n');
                                }
                                else
                                {
                                    // We're a regular user, so we don't need to do anything special
                                    weakRet.object.child = require('child_process').execFile(require('message-box').notifysend.path, ['notify-send', weakRet.object.title, weakRet.object.caption]);
                                }
                                weakRet.object.child.descriptorMetadata = 'toaster (notify-send)'
                            }
                            else if (require('message-box').xmessage)
                            {
                                weakRet.object._mb = require('message-box').create(title, caption, 5, 'OK');
                                weakRet.object._mb.weak = weakRet;
                                weakRet.object._mb.then(function () { this.ret.resolve('DISMISSED'); }, function () { this.weak.object.resolve('DISMISSED'); });
                            }
                            else
                            {
                                weakRet.object.reject('Zenity/KDialog/xmessage not found');
                            }
                        }
                    }
                }
                break;
            case 'darwin':
                weakRet.object._toast = require('message-box').notify(title, caption);
                weakRet.object._toast.weak = weakRet;
                weakRet.object._toast.then(function (v) { this.weak.object.resolve(v); }, function (e) { this.weak.object.reject(e); });
                break;
        }

        return (weakRet.object);
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
        child.stderr.str = ''; child.stderr.on('data', stdparser);
        child.stdout.str = ''; child.stdout.on('data', stdparser);
        child.stdin.write('cat /usr/share/dbus-1/services/*.service | grep "' + name + '" | awk -F= \'{ if( $2=="' + name + '" ) { print $2; } }\'\nexit\n');
        child.waitExit();
        return (child.stdout.str.trim() != '');
    };
}