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
        if (timeout == null) { timeout = 10; }
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret._title = title;
        ret._caption = caption;

        ret._container = require('ScriptContainer').Create(timeout, ContainerPermissions.DEFAULT);
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
        var zenity = '';
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = '';
        child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
        child.stdin.write("whereis zenity | awk '{ print $2 }'\nexit\n");
        child.waitExit();
        zenity = child.stdout.str.trim();
        if (zenity == '') { throw ('Zenity not installed'); }
        var uid = require('user-sessions').consoleUid();
        var xinfo = require('monitor-info').getXInfo(uid);
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.child = require('child_process').execFile(zenity, ['zenity', '--question', '--title=' + title, '--text=' + caption, '--timeout=' + timeout], { uid: uid, env: { XAUTHORITY: xinfo.xauthority, DISPLAY: xinfo.display } });
        ret.child.promise = ret;
        ret.child.stderr.on('data', function (chunk) { });
        ret.child.stdout.on('data', function (chunk) { });
        ret.child.on('exit', function (code)
        {
            switch(code)
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

        return (ret);


        console.log(child.stdout.str.trim() == '');

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
}






