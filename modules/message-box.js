/*
Copyright 2019 Intel Corporation

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


const MB_OK = 0x00000000;
const MB_OKCANCEL                = 0x00000001;
const MB_ABORTRETRYIGNORE        = 0x00000002;
const MB_YESNOCANCEL             = 0x00000003;
const MB_YESNO                   = 0x00000004;
const MB_RETRYCANCEL             = 0x00000005;

const MB_DEFBUTTON1              = 0x00000000;
const MB_DEFBUTTON2              = 0x00000100;
const MB_DEFBUTTON3              = 0x00000200;
const MB_ICONHAND                = 0x00000010;
const MB_ICONQUESTION            = 0x00000020;
const MB_ICONEXCLAMATION         = 0x00000030;
const MB_ICONASTERISK            = 0x00000040;

const IDOK     = 1;
const IDCANCEL = 2;
const IDABORT  = 3;
const IDRETRY  = 4;
const IDIGNORE = 5;
const IDYES    = 6;
const IDNO     = 7;

var promise = require('promise');
var childScript = "\
        require('ScriptContainer').on('data', function (j)\
        {\
            switch(j.command)\
            {\
                case 'messageBox':\
                    if(process.platform == 'win32')\
                    {\
                        var GM = require('_GenericMarshal');\
                        var user32 = GM.CreateNativeProxy('user32.dll');\
                        user32.CreateMethod('MessageBoxA');\
                        user32.MessageBoxA.async(0, GM.CreateVariable(j.caption), GM.CreateVariable(j.title), " + (MB_YESNO | MB_DEFBUTTON2 | MB_ICONEXCLAMATION).toString() + ").then(\
                        function(r)\
                        {\
                            if(r.Val == " + IDYES.toString() + ")\
                            {\
                                require('ScriptContainer').send(" + IDYES.toString() + ");\
                            }\
                            else\
                            {\
                                require('ScriptContainer').send(" + IDNO.toString() + ");\
                            }\
                            process.exit();\
                        });\
                    }\
                    break;\
            }\
        });\
    ";

function messageBox()
{
    this._ObjectID = 'message-box';
    this.create = function create(title, caption, timeout)
    {
        var GM = require('_GenericMarshal');
        var kernel32 = GM.CreateNativeProxy('kernel32.dll');
        kernel32.CreateMethod('ProcessIdToSessionId');
        var psid = GM.CreateVariable(4);
        if (kernel32.ProcessIdToSessionId(process.pid, psid).Val == 0)
        {
            ret._rej('Internal Error');
            return (ret);
        }

        if (timeout == null) { timeout = 10; }
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        var options = { executionTimeout: timeout };

        try
        {
            options.sessionId = require('user-sessions').consoleUid();
            if (options.sessionId == psid.toBuffer().readUInt32LE()) { delete options.sessionId; }
        }
        catch(ee)
        {
            ret._rej('No logged on users');
            return (ret);
        }
        ret._title = title;
        ret._caption = caption;
        ret._container = require('ScriptContainer').Create(options);
        ret._container.promise = ret;
        ret._container.on('data', function (j)
        {
            if(j == IDYES)
            {
                this.promise._res();
            }
            else
            {
                this.promise._rej('Denied');
            }
        });
        ret._container.on('exit', function ()
        {
            this.promise._rej('Timeout');
        });
        ret._container.ExecuteString(childScript);
        ret._container.send({ command: 'messageBox', caption: caption, title: title });
        return (ret);
    };
}


function linux_messageBox()
{
    this._ObjectID = 'message-box';
    this.create = function create(title, caption, timeout)
    {
        if (timeout == null) { timeout = 10; }
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        var zenity = '', kdialog = '';
        var uid = require('user-sessions').consoleUid();
        var xinfo = require('monitor-info').getXInfo(uid);
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = '';
        child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
        child.stdin.write("whereis zenity | awk '{ print $2 }'\nexit\n");
        child.waitExit();
        zenity = child.stdout.str.trim();
        if (zenity != '')
        {
            // GNOME/ZENITY
            ret.child = require('child_process').execFile(zenity, ['zenity', '--question', '--title=' + title, '--text=' + caption, '--timeout=' + timeout], { uid: uid, env: { XAUTHORITY: xinfo.xauthority, DISPLAY: xinfo.display } });
            ret.child.promise = ret;
            ret.child.stderr.on('data', function (chunk) { });
            ret.child.stdout.on('data', function (chunk) { });
            ret.child.on('exit', function (code)
            {
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
        else
        {
            child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("whereis kdialog | awk '{ print $2 }'\nexit\n");
            child.waitExit();
            kdialog = child.stdout.str.trim();
            if (kdialog == '') { ret._rej('Platform not supported (zenity or kdialog not found)'); return (ret); }
            if (process.env['DISPLAY'])
            {
                ret.child = require('child_process').execFile(kdialog, ['kdialog', '--title', title, '--yesno', caption]);
                ret.child.promise = ret;
            }
            else
            {
                var xdg = require('user-sessions').findEnv(uid, 'XDG_RUNTIME_DIR');
                if (!xinfo || !xinfo.display || !xinfo.xauthority || !xdg) { ret._rej('Interal Error, could not determine X11/XDG env'); return (ret); }
                ret.child = require('child_process').execFile(kdialog, ['kdialog', '--title', title, '--yesno', caption], { uid: uid, env: { DISPLAY: xinfo.display, XAUTHORITY: xinfo.xauthority, XDG_RUNTIME_DIR: xdg } });
                ret.child.promise = ret;
            }
            ret.child.stdout.on('data', function (chunk) { });
            ret.child.stderr.on('data', function (chunk) { });
            ret.child.on('exit', function (code)
            {
                switch (code) {
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
        return (ret);


        console.log(child.stdout.str.trim() == '');

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
    this._initMessageServer = function _initMessageServer()
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        
        try
        {
            ret.uid = require('user-sessions').consoleUid();
        }
        catch(e)
        {
            ret._rej(e);
            return (ret);
        }

        ret.ipcpath = '/var/tmp/' + process.execPath.split('/').pop() + '_ev';
        var n;

        try
        {
            n = require('tls').generateRandomInteger('1', '99999');
        }
        catch(e)
        {
            n = 0;
        }
        while (require('fs').existsSync(ret.ipcpath + n))
        {
            try
            {
                n = require('tls').generateRandomInteger('1', '99999');
            }
            catch (e)
            {
                ++n;
            }
        }
        ret.ipcpath = ret.ipcpath + n;
        ret.tmpServiceName = 'meshNotificationServer' + n;
        require('service-manager').manager.installLaunchAgent(
            {
                name: tmpServiceName, servicePath: process.execPath, startType: 'AUTO_START',
                sessionTypes: ['Aqua'], parameters: ['-exec', "require('message-box').startServer({path: '" + ret.ipcpath + ", service: '" + ret.tmpServiceName + "'}).on('close', function(){process.exit();});"]
            });
        require('service-manager').getLaunchAgent(ret.tmpServiceName).load(ret.uid);

        return (ret);
    };




    this.create = function create(title, caption, timeout)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.ipcpath = '/var/tmp/' + process.execPath.split('/').pop() + '_ev';

        var n = 0;
        while (require('fs').existsSync(ret.ipcpath + n)) { ++n; }
        ret.ipcpath += n;

        ret.title = title;
        ret.caption = caption;

        //ToDo: Install the message server

        this.startServer({ path: ret.ipcpath });

        // Create the Client
        ret.client = require('net').createConnection({ path: ret.ipcpath }, function ()
        {
            var b = translateObject({ command: 'DIALOG', title: ret.title, caption: ret.caption, icon: 'caution', buttons: ['"Yes"', '"No"'], buttonDefault: 2, timeout: timeout });
            this.write(b);
        });
        ret.client.promise = ret;
        ret.client.on('data', function (buffer)
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
                        this.promise._res(p.button);
                    }
                    break;
            }
        });
        ret.client.on('end', function ()
        {
            this.promise._rej('Message Server abruptly disconnected');
        });
        ret.finally(function () { console.log('finally'); });
        return (ret);
    };
    this.notify = function notify(title, caption)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.ipcpath = '/var/tmp/' + process.execPath.split('/').pop() + '_ev';

        var n = 0;
        while (require('fs').existsSync(ret.ipcPath + n)) { ++n; }
        ret.ipcpath += n;

        ret.title = title;
        ret.caption = caption;

        //ToDo: Install the message server
        
        this.startServer({ path: ret.ipcpath });

        // Create the Client
        ret.client = require('net').createConnection({ path: ret.ipcpath }, function ()
        {
            var b = translateObject({ command: 'NOTIFY', title: ret.title, caption: ret.caption });
            this.write(b);
        });
        ret.client.promise = ret;
        ret.client.on('data', function (buffer)
        {
            if (buffer.len < 4 || buffer.readUInt32LE(0) > buffer.len) { this.unshift(buffer); }
            var p = JSON.parse(buffer.slice(4, buffer.readUInt32LE(0)).toString());
            switch(p.command)
            {
                case 'ERROR':
                    this.promise._rej(p.reason);
                    break;
                case 'NOTIFY':
                    this.promise._res();
                    break;
            }
        });
        ret.client.on('end', function ()
        {
            this.promise._rej('Message Server abruptly disconnected');
        });

        return (ret);
    };
    this.startServer = function startServer(options)
    {
        if (require('fs').existsSync(options.path)) { require('fs').unlinkSync(options.path); }

        this._messageServer = require('net').createServer();
        this._messageServer.uid = require('user-sessions').consoleUid();
        this._messageServer._options = options;
        this._messageServer.timer = setTimeout(function (obj)
        {
            obj.close();
        }, 5000, this._messageServer);
        this._messageServer.listen(options);
        this._messageServer.on('connection', function (c)
        {
            this._client = c;
            this._client.timer = this.timer;
            this._client.on('data', function (buffer)
            {
                if (buffer.length < 4) { this.unshift(buffer); }
                if (buffer.length < buffer.readUInt32LE(0)) { this.unshift(buffer); }
                var p = JSON.parse(buffer.slice(4, buffer.readUInt32LE(0)).toString().trim());
                clearTimeout(this.timer);
                switch (p.command)
                {
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
                        this._shell.stdout.str = ''; this._shell.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                        this._shell.stderr.str = ''; this._shell.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                        this._shell.stdin.write('osascript -e \'tell current application to display dialog "' + p.caption + '" with title "' + p.title + '" ' + icon + ' ' + buttons + timeout + '\' | awk \'{ c=split($0, tokens, ","); split(tokens[1], val, ":"); if(c==1) { print val[2] } else { split(tokens[2], gu, ":"); if(gu[2]=="true") { print "_TIMEOUT_" } else { print val[2]  }  } }\'\nexit\n');
                        this._shell.waitExit();
                        if (this._shell.stderr.str != '')
                        {
                            this.end(translateObject({ command: 'ERROR', reason: this._shell.stderr.str }));
                        }
                        else
                        {
                            if (this._shell.stdout.str.trim() == '_TIMEOUT_')
                            {
                                this.end(translateObject({ command: 'DIALOG', timeout: true }));
                            }
                            else
                            {
                                this.end(translateObject({ command: 'DIALOG', button: this._shell.stdout.str.trim() }));
                            }
                        }
                        break;
                    default:
                        break;
                }
            });
        });

        this._messageServer.on('~', function ()
        {
            //attachDebugger({ webport: 9998, wait: 1 }).then(console.log);
            try
            {
                require('fs').unlinkSync(this._options.path);
            }
            catch (e)
            {
            }

            // Need to uninstall ourselves
            var osVersion = require('service-manager').getOSVersion();
            var s;
            
            try
            {
                s = require('service-manager').manager.getLaunchAgent(this._options.service);
            }
            catch(ee)
            {
                return; // Nothing to do if the service doesn't exist
            }

            var child = require('child_process').execFile('/bin/sh', ['sh'], { detached: true });
            if (osVersion.compareTo('10.10') < 0)
            {
                // Just unload
                child.stdin.write('launchctl unload ' + s.plist + '\nrm ' + s.plist + '\nexit\n');
            }
            else
            {
                // Use bootout
                child.stdin.write('launchctl bootout gui/' + this.uid + ' ' + s.plist + '\nrm ' + s.plist + '\nexit\n');
            }
            child.waitExit();
        });

        return (this._messageServer);
    };
}


switch(process.platform)
{
    case 'win32':
        module.exports = new messageBox();
        break;
    case 'linux':
        module.exports = new linux_messageBox();
        break;
    case 'darwin':
        module.exports = new macos_messageBox();
        break;
}






