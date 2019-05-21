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

function macos_messageBox()
{
    this._ObjectID = 'message-box';
    this.create = function create(title, caption, timeout)
    {
    };
    this.notify = function notify(title, caption)
    {
    };
    this.startServer = function startServer(options)
    {
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

        break;
}






