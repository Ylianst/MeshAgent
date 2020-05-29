/*
Copyright 2020 Intel Corporation

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


const MB_OK                     = 0x00000000;
const MB_OKCANCEL               = 0x00000001;
const MB_ABORTRETRYIGNORE       = 0x00000002;
const MB_YESNOCANCEL            = 0x00000003;
const MB_YESNO                  = 0x00000004;
const MB_RETRYCANCEL            = 0x00000005;
const MB_TOPMOST                = 0x00040000;
const MB_SETFOREGROUND          = 0x00010000;
const MB_SYSTEMMODAL            = 0x00001000;

const MB_DEFBUTTON1             = 0x00000000;
const MB_DEFBUTTON2             = 0x00000100;
const MB_DEFBUTTON3             = 0x00000200;
const MB_ICONHAND               = 0x00000010;
const MB_ICONQUESTION           = 0x00000020;
const MB_ICONEXCLAMATION        = 0x00000030;
const MB_ICONASTERISK           = 0x00000040;

const IDOK     = 1;
const IDCANCEL = 2;
const IDABORT  = 3;
const IDRETRY  = 4;
const IDIGNORE = 5;
const IDYES    = 6;
const IDNO     = 7;
const WM_CLOSE = 0x0010;

var promise = require('promise');

function messageBox()
{
    this._ObjectID = 'message-box';
    this.create = function create(title, caption, timeout, layout, sid)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.options = { launch: { module: 'message-box', method: 'slave', args: [] } };
        ret.title = title;
        ret.caption = caption;
        ret.timeout = timeout;
        ret.layout = layout;

        //ret.options._debugIPC = true;
        //ret.options._ipcInteger = 1500;

        try
        {
            ret.options.uid = sid == null ? require('user-sessions').consoleUid() : sid;
            if (ret.options.uid == require('user-sessions').getProcessOwnerName(process.pid).tsid) { delete ret.options.uid; }
        }
        catch (ee)
        {
            ret._rej('No logged on users');
            return (ret);
        }

        ret._ipc = require('child-container').create(ret.options);
        ret._ipc.master = ret;
        ret._ipc.on('ready', function ()
        {
            this.descriptorMetadata = 'message-box';
            if (this.master.timeout != null) { this.master._timeout = setTimeout(function (mstr) { mstr._ipc.exit(); }, this.master.timeout * 1000, this.master); }
            if (this.master.layout == null)
            {
                this.message({ command: 'YESNO', caption: this.master.caption, title: this.master.title });
            }
            else
            {
                this.message({ command: 'ALERT', caption: this.master.caption, title: this.master.title });
            }
        });
        ret._ipc.on('message', function (msg)
        {
            try
            {
                switch(msg.command)
                {
                    case 'response':
                        if (this.master._timeout) { clearTimeout(this.master._timeout); this.master._timeout = null; }
                        if (msg.response == IDYES || msg.response == IDOK)
                        {
                            this.master._res();
                        }
                        else
                        {
                            this.master._rej(msg.response);
                        }
                        break;
                    default:
                        break;
                }
            }
            catch(ff)
            {
            }
        });
        ret._ipc.on('exit', function (c) { this.master._rej('child exited with code: ' + c); });
        ret.close = function close()
        {
            ret._ipc.exit();
        };
        return (ret);
    };
    this.slave = function()
    {
        var master = require('child-container');
        master.on('message', function (msg)
        {
            switch(msg.command)
            {
                case 'YESNO':
                case 'ALERT':
                    this.GM = require('_GenericMarshal');
                    this.user32 = this.GM.CreateNativeProxy('user32.dll');
                    this.user32.CreateMethod('MessageBoxA');
                    layout = msg.command == 'YESNO' ? (MB_YESNO | MB_DEFBUTTON2 | MB_ICONEXCLAMATION | MB_TOPMOST | MB_SYSTEMMODAL) : (MB_OK | MB_DEFBUTTON2 | MB_ICONEXCLAMATION | MB_TOPMOST | MB_SYSTEMMODAL);
                    this.user32.MessageBoxA.async(0, this.GM.CreateVariable(msg.caption), this.GM.CreateVariable(msg.title), layout)
                        .then(function (r)
                        {
                            try
                            {
                                switch(r.Val)
                                {
                                    case IDOK:
                                    case IDCANCEL:
                                    case IDABORT:
                                    case IDRETRY:
                                    case IDIGNORE:
                                    case IDYES:
                                        this.that.message({command: 'response', response: r.Val});
                                        break;
                                    default:
                                        this.that.message({command: 'response', response: IDNO});
                                        break;
                                }
                            }
                            catch(ff)
                            {
                            }
                            process.exit();
                        }, function () { process.exit(); }).parentPromise.that = this;
                    break;
                default:
                    break;
            }
        });
    }
}


function linux_messageBox()
{
    this._ObjectID = 'message-box';
    Object.defineProperty(this, 'zenity',
        {
            value: (function ()
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write("whereis zenity | awk '{ print $2 }'\nexit\n");
                child.waitExit();
                var location = child.stdout.str.trim();
                if (location == '' && require('fs').existsSync('/usr/local/bin/zenity')) { location = '/usr/local/bin/zenity'; }
                if (location == '') { return (null); }

                var ret = { path: location, timeout: child.stdout.str.trim() == '' ? false : true };
                Object.defineProperty(ret, "timeout", {
                    get: function ()
                    {
                        var uid, xinfo;
                        try
                        {
                            uid = require('user-sessions').consoleUid();
                            xinfo = require('monitor-info').getXInfo(uid);
                        }
                        catch (e)
                        {
                            uid = 0;
                            xinfo = require('monitor-info').getXInfo(0);
                        }
                        if (xinfo == null) { return (false); }
                        var child = require('child_process').execFile('/bin/sh', ['sh'], { uid: uid, env: { XAUTHORITY: xinfo.xauthority ? xinfo.xauthority : "", DISPLAY: xinfo.display } });
                        child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                        child.stdin.write(location + ' --help-all | grep timeout\nexit\n');
                        child.stderr.on('data', function (e) { });
                        child.waitExit();
                        return (child.stdout.str.trim() == '' ? false : true);
                    }
                });

                Object.defineProperty(ret, "version", {
                    get: function ()
                    {
                        var uid, xinfo;
                        try
                        {
                            uid = require('user-sessions').consoleUid();
                            xinfo = require('monitor-info').getXInfo(uid);
                        }
                        catch (e)
                        {
                            uid = 0;
                            xinfo = require('monitor-info').getXInfo(0);
                        }
                        if (xinfo == null) { return (false); }

                        var child = require('child_process').execFile('/bin/sh', ['sh'], { uid: uid, env: { XAUTHORITY: xinfo.xauthority ? xinfo.xauthority : "", DISPLAY: xinfo.display } });
                        child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                        child.stdin.write(location + ' --version | awk -F. \'{ printf "[%s, %s]\\n", $1, $2; } \'\nexit\n');
                        child.waitExit();

                        try
                        {
                            return (JSON.parse(child.stdout.str.trim()));
                        }
                        catch (e)
                        {
                            return ([2, 16]);
                        }
                    }
                });
                return (ret);
            })()
        });
    if (!this.zenity)
    {
        Object.defineProperty(this, 'kdialog',
            {
                value: (function ()
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    child.stdin.write("whereis kdialog | awk '{ print $2 }'\nexit\n");
                    child.waitExit();
                    return (child.stdout.str.trim() == '' ? null : { path: child.stdout.str.trim() });
                })()
            });
        Object.defineProperty(this, 'xmessage',
            {
                value: (function ()
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    child.stdin.write("whereis xmessage | awk '{ print $2 }'\nexit\n");
                    child.waitExit();
                    return (child.stdout.str.trim() == '' ? null : { path: child.stdout.str.trim() });
                })()
            });
    }
    else
    {
        Object.defineProperty(this, 'notifysend',
            {
                value: (function ()
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    child.stdin.write("whereis notify-send | awk '{ print $2 }'\nexit\n");
                    child.waitExit();
                    return (child.stdout.str.trim() == '' ? null : { path: child.stdout.str.trim() });
                })()
            });
    }

    this.create = function create(title, caption, timeout, layout)
    {
        if (timeout == null) { timeout = 10; }
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        var uid;    
        var xinfo;
        var min = require('user-sessions').minUid();

        try
        {
            uid = require('user-sessions').consoleUid();
            xinfo = require('monitor-info').getXInfo(uid);
        }
        catch(e)
        {
            uid = 0;
            xinfo = require('monitor-info').getXInfo(0);
        }

        if (xinfo == null || (uid != 0 && uid < min))
        {
            ret._rej('This system cannot display a user dialog box when a user is not logged in');
            return (ret);
        }

        if (this.zenity)
        {
            // GNOME/ZENITY
            if (this.zenity.timeout)
            {
                ret.child = require('child_process').execFile(this.zenity.path, ['zenity', layout==null?'--question':'--warning', '--title=' + title, '--text=' + caption, '--timeout=' + timeout], { uid: uid, env: { XAUTHORITY: xinfo.xauthority ? xinfo.xauthority : "", DISPLAY: xinfo.display } });
            }
            else
            {
                ret.child = require('child_process').execFile(this.zenity.path, ['zenity', layout == null ? '--question' : '--warning', '--title=' + title, '--text=' + caption], { uid: uid, env: { XAUTHORITY: xinfo.xauthority ? xinfo.xauthority : "", DISPLAY: xinfo.display } });
                ret.child.timeout = setTimeout(function (c)
                {
                    c.timeout = null;
                    c.promise._rej('timeout');
                    c.kill();
                }, timeout * 1000, ret.child);
            }
            ret.child.descriptorMetadata = 'zenity, message-box'
            ret.child.promise = ret;
            ret.child.stderr.on('data', function (chunk) { });
            ret.child.stdout.on('data', function (chunk) { });
            ret.child.on('exit', function (code)
            {
                if (this.timeout) { clearTimeout(this.timeout); }
                switch (code)
                {
                    case 0:
                        this.promise._res();
                        break;
                    case 1:
                        this.promise._rej('denied');
                        break;
                    default:
                        this.promise._rej('timeout');
                        break;
                }
            });
        }
        else if(this.kdialog)
        {
            if (process.platform != 'freebsd' && process.env['DISPLAY'])
            {
                ret.child = require('child_process').execFile(this.kdialog.path, ['kdialog', '--title', title, layout==null?'--yesno':'--msgbox', caption]);
                ret.child.promise = ret;
            }
            else
            {
                var xdg = require('user-sessions').findEnv(uid, 'XDG_RUNTIME_DIR'); if (xdg == null) { xdg = ''; }
                if (!xinfo || !xinfo.display || !xinfo.xauthority) { ret._rej('Interal Error, could not determine X11/XDG env'); return (ret); }
                ret.child = require('child_process').execFile(this.kdialog.path, ['kdialog', '--title', title, layout == null ? '--yesno' : '--msgbox', caption], { uid: uid, env: { DISPLAY: xinfo.display, XAUTHORITY: xinfo.xauthority, XDG_RUNTIME_DIR: xdg } });
                ret.child.promise = ret;
            }
            ret.child.descriptorMetadata = 'kdialog, message-box'
            ret.child.timeout = setTimeout(function (c)
            {
                c.timeout = null;
                c.kill();
            }, timeout * 1000, ret.child);
            ret.child.stdout.on('data', function (chunk) { });
            ret.child.stderr.on('data', function (chunk) { });
            ret.child.on('exit', function (code)
            {
                if (this.timeout)
                {
                    clearTimeout(this.timeout);
                    switch (code)
                    {
                        case 0:
                            this.promise._res();
                            break;
                        case 1:
                            this.promise._rej('denied');
                            break;
                        default:
                            this.promise._rej('timeout');
                            break;
                    }
                }
                else
                {
                    this.promise._rej('timeout');
                }
            });
        }
        else if (this.xmessage)
        {
            // title, caption, timeout, layout
            ret.child = require('child_process').execFile(this.xmessage.path, ['xmessage', '-center', '-buttons', layout == null ? 'No:1,Yes:2' : 'OK:2', '-timeout', timeout.toString(), '-default', layout==null?'No':'OK', '-title', title, caption], { uid: uid, env: { XAUTHORITY: xinfo.xauthority ? xinfo.xauthority : "", DISPLAY: xinfo.display } });
            ret.child.stdout.on('data', function (c) {  });
            ret.child.stderr.on('data', function (c) {  });
            ret.child.descriptorMetadata = 'xmessage, message-box'
            ret.child.promise = ret;
            ret.child.on('exit', function (code)
            {
                switch(code)
                {
                    case 2:
                        this.promise._res();
                        break;
                    case 1:
                        this.promise._rej('denied');
                        break;
                    default:
                        this.promise._rej('timeout');
                        break;
                }
            });
        }
        else
        {
            ret._rej('Unable to create dialog box');
        }

        ret.close = function close()
        {
            if (this.timeout) { clearTimeout(this.timeout); }
            if (this.child)
            {
                this._rej('denied');
                this.child.kill();
            }
        }
        return (ret);
    };
}

if (process.platform == 'darwin')
{
    function translateObject(obj)
    {
        var j = JSON.stringify(obj);
        var b = Buffer.alloc(j.length + 4);
        b.writeUInt32LE(j.length + 4);
        Buffer.from(j).copy(b, 4);
        return (b);
    }
}

function macos_messageBox()
{
    this._ObjectID = 'message-box';
    this._initIPCBase = function _initIPCBase()
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });

        try
        {
            ret.uid = require('user-sessions').consoleUid();
        }
        catch (e)
        {
            ret._rej(e);
            return (ret);
        }

        ret.path = '/var/tmp/' + process.execPath.split('/').pop() + '_ev';
        var n;

        try
        {
            n = require('tls').generateRandomInteger('1', '99999');
        }
        catch (e)
        {
            n = 0;
        }
        while (require('fs').existsSync(ret.path + n))
        {
            try {
                n = require('tls').generateRandomInteger('1', '99999');
            }
            catch (e) {
                ++n;
            }
        }
        ret.path = ret.path + n;
        ret.tmpServiceName = 'meshNotificationServer' + n;
        return (ret);
    };
    
    this.create = function create(title, caption, timeout, layout)
    {
        // Start Local Server
        var ret = this._initIPCBase();
        ret.title = title; ret.caption = caption; ret.timeout = timeout;
        if (layout == null)
        {
            ret.layout = ['Yes', 'No'];
        }
        else if(typeof(layout)!='object')
        {
            ret.layout = ['OK'];
        }
        else
        {
            ret.layout = layout;
            Object.defineProperty(ret.layout, "user", { value: true });
        }
        ret.server = this.startMessageServer(ret);
        ret.server.ret = ret;
        ret.server.on('connection', function (c)
        {
            this._connection = c;
            c.promise = this.ret;
            c.on('data', function (buffer)
            {
                if (buffer.len < 4 || buffer.readUInt32LE(0) > buffer.len) { this.unshift(buffer); }
                var p = JSON.parse(buffer.slice(4, buffer.readUInt32LE(0)).toString());
                switch (p.command)
                {
                    case 'ERROR':
                        this.promise._rej(p.reason);
                        break;
                    case 'DIALOG':
                        if (p.timeout)
                        {
                            this.promise._rej('TIMEOUT');
                        }
                        else
                        {
                            if (p.button == 'Yes' || p.button == 'OK' || this.promise.layout.user)
                            {
                                this.promise._res(p.button);
                            }
                            else
                            {
                                this.promise._rej('denied');
                            }
                        }
                        break;
                }
                this.promise.server.close();
            });
            for (var x in this.ret.layout)
            {
                this.ret.layout[x] = '"' + this.ret.layout[x] + '"';
            }
            c.write(translateObject({ command: 'DIALOG', title: this.ret.title, caption: this.ret.caption, icon: 'caution', buttons: this.ret.layout, buttonDefault: this.ret.layout[this.ret.layout.length-1], timeout: this.ret.timeout }));
        });
        ret.close = function close()
        {
            if (this.server) { this.server.close(); }
        };
        return (ret);
    };
    this.lock = function lock()
    {
        // Start Local Server
        var ret = this._initIPCBase();
        ret.server = this.startMessageServer(ret);
        ret.server.ret = ret;
        ret.server.on('connection', function (c)
        {
            this._connection = c;
            c.promise = this.ret;
            c.on('data', function (buffer)
            {
                if (buffer.len < 4 || buffer.readUInt32LE(0) > buffer.len) { this.unshift(buffer); }
                var p = JSON.parse(buffer.slice(4, buffer.readUInt32LE(0)).toString());
                switch (p.command)
                {
                    case 'ERROR':
                        this.promise._rej(p.reason);
                        break;
                    case 'LOCK':
                        this.promise._res();
                        break;
                }
            });
            c.write(translateObject({ command: 'LOCK' }));
        });

        return (ret);
    };
    this.notify = function notify(title, caption)
    {
        // Start Local Server
        var ret = this._initIPCBase();
        ret.title = title; ret.caption = caption; 
        ret.server = this.startMessageServer(ret);
        ret.server.ret = ret;
        ret.server.on('connection', function (c)
        {
            this._connection = c;
            c.promise = this.ret;
            c.on('data', function (buffer)
            {
                if (buffer.len < 4 || buffer.readUInt32LE(0) > buffer.len) { this.unshift(buffer); }
                var p = JSON.parse(buffer.slice(4, buffer.readUInt32LE(0)).toString());
                switch (p.command)
                {
                    case 'ERROR':
                        this.promise._rej(p.reason);
                        break;
                    case 'NOTIFY':

                        this.promise._res();
                        break;
                }
            });
            c.write(translateObject({ command: 'NOTIFY', title: this.ret.title, caption: this.ret.caption }));
        });

        return (ret);
    };
    this.startClient = function startClient(options)
    {
        // Create the Client
        options.osversion = require('service-manager').getOSVersion();
        options.uid = require('user-sessions').consoleUid();
        this.client = require('net').createConnection(options);
        this.client._options = options;
        this.client.on('data', function (buffer)
        {
            if (buffer.len < 4 || buffer.readUInt32LE(0) > buffer.len) { this.unshift(buffer); }
            var p = JSON.parse(buffer.slice(4, buffer.readUInt32LE(0)).toString());
            switch (p.command)
            {
                case 'LOCK':
                    this._shell = require('child_process').execFile('/bin/sh', ['sh']);
                    this._shell.stdout.str = ''; this._shell.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    this._shell.stderr.str = ''; this._shell.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                    this._shell.stdin.write('/System/Library/CoreServices/Menu\\ Extras/User.menu/Contents/Resources/CGSession -suspend\nexit\n');
                    this._shell.waitExit();
                    if (this._shell.stderr.str != '')
                    {
                        this.end(translateObject({ command: 'ERROR', reason: this._shell.stderr.str }));
                    }
                    else
                    {
                        this.end(translateObject({ command: 'LOCK', status: 0 }));
                    }
                    break;
                case 'NOTIFY':
                    this._shell = require('child_process').execFile('/bin/sh', ['sh']);
                    this._shell.stdout.str = ''; this._shell.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    this._shell.stderr.str = ''; this._shell.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                    this._shell.stdin.write('osascript -e \'tell current application to display notification "' + p.caption + '" with title "' + p.title + '"\'\nexit\n');
                    this._shell.waitExit();
                    if (this._shell.stderr.str != '')
                    {
                        this.end(translateObject({ command: 'ERROR', reason: this._shell.stderr.str }));
                    }
                    else
                    {
                        this.end(translateObject({ command: 'NOTIFY', status: 0 }));
                    }
                    break;
                case 'DIALOG':
                    var timeout = p.timeout ? (' giving up after ' + p.timeout) : '';
                    var icon = p.icon ? ('with icon ' + p.icon) : '';

                    var buttons = p.buttons ? ('buttons {' + p.buttons.toString() + '}') : '';
                    if (p.buttonDefault != null)
                    {
                        buttons += (' default button ' + p.buttonDefault)
                    }
                    this._shell = require('child_process').execFile('/bin/sh', ['sh']);
                    this._shell.that = this;
                    this._shell.stdout.str = ''; this._shell.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    this._shell.stderr.str = ''; this._shell.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                    this._shell.stdin.write('osascript -e \'tell current application to display dialog "' + p.caption + '" with title "' + p.title + '" ' + icon + ' ' + buttons + timeout + '\' | awk \'{ c=split($0, tokens, ","); split(tokens[1], val, ":"); if(c==1) { print val[2] } else { split(tokens[2], gu, ":"); if(gu[2]=="true") { print "_TIMEOUT_" } else { print val[2]  }  } }\'\nexit\n');
                    this._shell.on('exit', function ()
                    {
                        if (this.stderr.str != '' && !this.stderr.str.includes('OpenGL'))
                        {
                            this.that.end(translateObject({ command: 'ERROR', reason: this.stderr.str }));
                        }
                        else
                        {
                            if (this.stdout.str.trim() == '_TIMEOUT_')
                            {
                                this.that.end(translateObject({ command: 'DIALOG', timeout: true }));
                            }
                            else
                            {
                                this.that.end(translateObject({ command: 'DIALOG', button: this.stdout.str.trim() }));
                            }
                        }
                        this.that._shell = null;
                    });
                    this.on('close', function ()
                    {
                        if (this._shell) { this._shell.kill(); }
                    });

                    //this._shell.waitExit();
                    //if (this._shell.stderr.str != '' && !this._shell.stderr.str.includes('OpenGL'))
                    //{
                    //    this.end(translateObject({ command: 'ERROR', reason: this._shell.stderr.str }));
                    //}
                    //else
                    //{
                    //    if (this._shell.stdout.str.trim() == '_TIMEOUT_')
                    //    {
                    //        this.end(translateObject({ command: 'DIALOG', timeout: true }));
                    //    }
                    //    else
                    //    {
                    //        this.end(translateObject({ command: 'DIALOG', button: this._shell.stdout.str.trim() }));
                    //    }
                    //}
                    break;
                default:
                    break;
            }
        });
        this.client.on('error', function () { this.uninstall(); }).on('end', function () { this.uninstall(); });
        this.client.uninstall = function ()
        {
            // Need to uninstall ourselves
            var child = require('child_process').execFile(process.execPath, [process.execPath.split('/').pop(), '-exec', "var s=require('service-manager').manager.getLaunchAgent('" + this._options.service + "', " + this._options.uid + "); s.unload(); require('fs').unlinkSync(s.plist);process.exit();"], { detached: true, type: require('child_process').SpawnTypes.DETACHED });
            child.waitExit();
        };
        return (this.client);
    };
    this.startMessageServer = function startMessageServer(options)
    {
        if (require('fs').existsSync(options.path)) { require('fs').unlinkSync(options.path); }
        options.writableAll = true;

        var ret = require('net').createServer();
        ret.uid = require('user-sessions').consoleUid();
        ret.osversion = require('service-manager').getOSVersion();
        ret._options = options;
        ret.timer = setTimeout(function (obj)
        {
            obj.close();
            obj._options._rej('Connection timeout');
        }, 5000, ret);
        ret.listen(options);
        ret.on('connection', function (c)
        {
            clearTimeout(this.timer);
        });
        ret.on('~', function ()
        {
            require('fs').unlinkSync(this._options.path);
        });

        require('service-manager').manager.installLaunchAgent(
            {
                name: options.tmpServiceName, servicePath: process.execPath, startType: 'AUTO_START', uid: ret.uid,
                sessionTypes: ['Aqua'], parameters: ['-exec', "require('message-box').startClient({ path: '" + options.path + "', service: '" + options.tmpServiceName + "' }).on('end', function () { process.exit(); }).on('error', function () { process.exit(); });"]
            });
        require('service-manager').manager.getLaunchAgent(options.tmpServiceName, ret.uid).load();

        return (ret);
    };
}


switch(process.platform)
{
    case 'win32':
        module.exports = new messageBox();
        break;
    case 'linux':
    case 'freebsd':
        module.exports = new linux_messageBox();
        break;
    case 'darwin':
        module.exports = new macos_messageBox();
        break;
}






