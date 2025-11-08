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

function desktopLock()
{
    this._ObjectID = 'desktop-lock';
    this.lock = function lock()
    {
        switch(process.platform)
        {
            case 'win32':
                var child = require('child_process').execFile(process.env['windir'] + '\\system32\\cmd.exe', ['/c', 'RunDll32.exe user32.dll,LockWorkStation'], { type: require('user-sessions').isRoot()?1:undefined });                
                child.waitExit();
                break;
            case 'linux':
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write('loginctl lock-sessions\nexit\n');
                child.waitExit();
                if (child.stderr.str != '') { throw ('Failed'); }
                break;
            case 'darwin':
                return(require('message-box').lock());
                break;
            default:
                throw ('Not supported on ' + process.platform);
                break;
        }
    };
}

module.exports = new desktopLock();
