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

var toasters = {};

function Toaster()
{
    this._ObjectID = 'toaster';
    this.Toast = function Toast(title, caption)
    {
        var retVal = {};
        var emitter = require('events').inherits(retVal);
        emitter.createEvent('Dismissed');

        retVal.title = title;
        retVal.caption = caption;

        if (process.platform == 'win32')
        {
            emitter.createEvent('Clicked');
            var GM = require('_GenericMarshal');
            var kernel32 = GM.CreateNativeProxy('kernel32.dll');
            kernel32.CreateMethod('ProcessIdToSessionId');
            var psid = GM.CreateVariable(4);
            var consoleUid = require('user-sessions').consoleUid();
            if (kernel32.ProcessIdToSessionId(process.pid, psid).Val == 0)
            {
                throw ('Internal Error');
            }

            if (consoleUid == psid.toBuffer().readUInt32LE())
            {
                // We are running on the physical console
                retVal._child = require('ScriptContainer').Create({ processIsolation: true });
            }
            else
            {
                // We need so spawn the ScriptContainer into the correct session
                retVal._child = require('ScriptContainer').Create({ processIsolation: true, sessionId: consoleUid });
            }
            retVal._child.parent = retVal;
            retVal._child.on('exit', function (code) { this.parent.emit('Dismissed'); delete this.parent._child; });
            retVal._child.addModule('win-console', getJSModule('win-console'));
            retVal._child.addModule('win-message-pump', getJSModule('win-message-pump'));

            var str = "\
                    try{\
                    var toast = require('win-console');\
                    var balloon = toast.SetTrayIcon({ szInfo: '" + caption + "', szInfoTitle: '" + title + "', balloonOnly: true });\
                    balloon.on('ToastDismissed', function(){process.exit();});\
                    }\
                    catch(e)\
                    {\
                        require('ScriptContainer').send(e);\
                    }\
                        require('ScriptContainer').send('done');\
                    ";
            retVal._child.ExecuteString(str);
            toasters[retVal._hashCode()] = retVal;
            retVal.on('Dismissed', function () { delete toasters[this._hashCode()]; });
            console.log('Returning');
            return (retVal);
        }
        else
        {
            if(!require('fs').existsSync('/usr/bin/notify-send'))
            {
                throw ('Toast not supported on this platform');
            }
            if (process.env['DISPLAY'])
            {
                // DISPLAY is set, so we good to go
                retVal._notify = require('child_process').execFile('/usr/bin/notify-send', ['notify-send', retVal.title, retVal.caption]);
            }
            else
            {
                // We need to find the DISPLAY to use
                var consoleUid = require('user-sessions').consoleUid();
                var username = require('user-sessions').getUsername(consoleUid);
                var display = require('monitor-info').getXInfo(consoleUid).display;
                retVal._notify = require('child_process').execFile('/bin/sh', ['sh']);
                retVal._notify.stdin.write('su - ' + username + ' -c "DISPLAY=' + display + ' notify-send \'' + retVal.title + '\' \'' + retVal.caption + '\'"\n');
                retVal._notify.stdin.write('exit\n');
            }
            retVal._notify.stdout.on('data', function (chunk) { });
            retVal._notify.waitExit();

            // NOTIFY-SEND has a bug where timeouts don't work, so the default is 10 seconds
            retVal._timeout = setTimeout(function onFakeDismissed(obj)
            {
                obj.emit('Dismissed');
            }, 10000, retVal);

            toasters[retVal._hashCode()] = retVal;
            retVal.on('Dismissed', function () { delete toasters[this._hashCode()]; });

            return (retVal);
        }
    };
}

module.exports = new Toaster();