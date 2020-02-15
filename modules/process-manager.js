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


var GM = require('_GenericMarshal');

// Used on Windows and Linux to get information about running processes
function processManager() {
    this._ObjectID = 'process-manager'; // Used for debugging, allows you to get the object type at runtime.
    
    // Setup the platform specific calls.
    switch (process.platform)
    {
        case 'win32':
            this._kernel32 = GM.CreateNativeProxy('kernel32.dll');
            this._kernel32.CreateMethod('GetLastError');
            this._kernel32.CreateMethod('CreateToolhelp32Snapshot');
            this._kernel32.CreateMethod('Process32FirstW');
            this._kernel32.CreateMethod('Process32NextW');
            break;
	case 'freebsd':
        case 'linux':
        case 'darwin':
            this._childProcess = require('child_process');
            break;
        default:
            throw (process.platform + ' not supported');
            break;
    }
    this.enumerateProcesses = function enumerateProcesses()
    {
        var promise = require('promise');
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.callback = function callback(ps)
        {
            callback.prom._res(ps);
        }
        ret.callback.prom = ret;
        this.getProcesses(ret.callback);
        return (ret);
    }
    // Return a object of: pid -> process information.
    this.getProcesses = function getProcesses(callback)
    {
        switch(process.platform)
        {
            default:
                throw ('Enumerating processes on ' + process.platform + ' not supported');
                break;
            case 'win32': // Windows processes
                var pid;
                var retVal = {};
                var h = this._kernel32.CreateToolhelp32Snapshot(2, 0);
                var info = GM.CreateVariable(GM.PointerSize==8 ? 568 : 556);
                info.toBuffer().writeUInt32LE(info._size, 0);
                var nextProcess = this._kernel32.Process32FirstW(h, info);
                while (nextProcess.Val) 
                {
                    pid = info.Deref(8, 4).toBuffer().readUInt32LE(0);
                    retVal[pid] = { pid: pid, cmd: info.Deref(GM.PointerSize == 4 ? 36 : 44, 260).Wide2UTF8 };
                    try
                    {
                        retVal[pid].user = require('user-sessions').getProcessOwnerName(pid).name;
                    }
                    catch(ee)
                    {
                    }
                    
                    nextProcess = this._kernel32.Process32NextW(h, info);
                }
                if (callback) { callback.apply(this, [retVal]); }
                break;
            case 'linux': // Linux processes
                var p = require('child_process').execFile('/bin/sh', ['sh']);
                p.stdout.str = ''; p.stdout.on('data', function (c) { this.str += c.toString(); });
                p.stderr.str = ''; p.stderr.on('data', function (c) { this.str += c.toString(); });
                p.stdin.write('ps -ax -o pid -o user:99 -o command | tr ' + "'\\n' '\\t' | awk -F" + '"\\t" \'{ printf "{"; for(i=2;i<NF;++i) { split($i,tok," "); pid=tok[1]; user=tok[2]; cmd=substr($i,length(tok[1])+102); gsub(/\\\\/,"\\\\\\\\&",cmd); gsub(/"/,"\\\\\\\\&",cmd); gsub(/^[ ]+/,"",cmd); printf "%s\\"%s\\":{\\"pid\\":\\"%s\\",\\"user\\":\\"%s\\",\\"cmd\\":\\"%s\\"}",(i!=2?",":""),pid,pid,user,cmd; } printf "}"; }\'\nexit\n');
                p.waitExit();

                if (callback)
                {
                    p.args = [];
                    for (var i = 1; i < arguments.length; ++i) { p.args.push(arguments[i]); }

                    p.args.unshift(JSON.parse(p.stdout.str));
                    callback.apply(this, p.args);
                }

                break;
            case 'darwin':
            case 'freebsd':
                var p = require('child_process').execFile('/bin/sh', ['sh']);
                p.stdout.str = ''; p.stdout.on('data', function (c) { this.str += c.toString(); });
                p.stderr.str = ''; p.stderr.on('data', function (c) { this.str += c.toString(); });
                p.stdin.write('ps -axo pid -o user -o command | tr ' + "'\\n' '\\t' | awk -F" + '"\\t" \'{ printf "{"; for(i=2;i<NF;++i) { gsub(/^[ ]+/,"",$i); split($i,tok," "); pid=tok[1]; user=tok[2]; cmd=substr($i,length(tok[1])+length(tok[2])+2); gsub(/\\\\/,"\\\\\\\\&",cmd); gsub(/"/,"\\\\\\\\&",cmd); gsub(/^[ ]+/,"",cmd); printf "%s\\"%s\\":{\\"pid\\":\\"%s\\",\\"user\\":\\"%s\\",\\"cmd\\":\\"%s\\"}",(i!=2?",":""),pid,pid,user,cmd; } printf "}"; }\'\nexit\n');
                p.waitExit();

                if (callback)
                {
                    p.args = [];
                    for (var i = 1; i < arguments.length; ++i) { p.args.push(arguments[i]); }

                    p.args.unshift(JSON.parse(p.stdout.str));
                    callback.apply(this, p.args);
                }

                break;
        }
    };

    // Get information about a specific process on Linux
    this.getProcessInfo = function getProcessInfo(pid)
    {
        switch(process.platform)
        {
            default:
                throw ('getProcessInfo() not supported for ' + process.platform);
                break;
            case 'linux':
                var status = require('fs').readFileSync('/proc/' + pid + '/status');
                var info = {};
                var lines = status.toString().split('\n');
                for(var i=0;i<lines.length;++i)
                {
                    var tokens = lines[i].split(':');
                    if (tokens.length > 1) { tokens[1] = tokens[1].trim(); }
                    info[tokens[0]] = tokens[1];
                }
                return (info);
                break;
        }
    };

    if(process.platform != 'win32')
    {
        Object.defineProperty(this, '_pgrep', {
            value: (function ()
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = '';
                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write("whereis pgrep | awk '{ print $2 }'\nexit\n");
                child.waitExit();
                return (child.stdout.str.trim());
            })()
        });

        if (this._pgrep != '')
        {
            this.getProcess = function getProcess(cmd)
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write("pgrep gnome-session | tr '\\n' '\\t' |" + ' awk -F"\\t" \'{ printf "["; for(i=1;i<NF;++i) { if(i>1) { printf ","; } printf "%d", $i; } printf "]"; }\'');
                child.stdin.write('\nexit\n');
                child.waitExit();
                if (child.stderr.str != '') { throw (child.stderr.str.trim()); }
                if (child.stdout.str.trim() == '') { throw (cmd + ' not found'); }

                return (JSON.parse(child.stdout.str.trim()));
            };
        }

        this.getProcessEx = function getProcessEx(cmd)
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
            child.stdin.write('ps -ax -o pid -o command | grep ' + cmd + " | tr '\\n' '\\t' | awk -F" + '"\\t" \'{ printf "["; for(i=1;i<NF;++i) { split($i,r," "); if(r[2]!="grep") { if(i>1) { printf ","; } printf "%s", r[1]; } } printf "]"; }\'');
            child.stdin.write('\nexit\n');
            child.waitExit();

            if (child.stdout.str.trim() == '')
            {
                throw (cmd + ' not found');
            }
            else
            {
                return (JSON.parse(child.stdout.str.trim()));
            }
        }
    }
}

module.exports = new processManager();
