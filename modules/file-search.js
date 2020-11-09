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

var promise = require('promise');

function filesearch()
{
    this._ObjectID = 'fileSearch';
    switch (process.platform)
    {
        case 'win32':
            this.find = function find(root, criteria)
            {
                var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
                require('events').EventEmitter.call(ret, true)
                    .createEvent('result')
                    .createEvent('end');
                ret.server = require('net').createServer();
                ret.server.promise = ret;
                ret._clientpath = 'mesh-' + require('uuid/v4')();
                ret.path = '\\\\.\\pipe\\' + ret._clientpath;
                try { ret.server.listen({ path: ret.path }); } catch (e) { throw ('SearchError: Cannot create connection'); }
                ret.server.on('connection', function (c)
                {
                    console.info1('Powershell Search Client connected...');
                    c.str = '';
                    this._connection = c;
                    c.parent = this;
                    c.on('end', function ()
                    {
                        var last = this.str.trim();
                        if (last != '') { this.parent.promise.emit('result', lines.shift()); }
                        console.info1('Powershell Search Client disconnected');
                        this.end(); 
                        this.parent._connection = null;
                        this.parent.promise.emit('end');
                        this.parent.promise._res();
                    });
                    c.on('data', function (chunk)
                    {
                        this.str += chunk.toString();
                        var lines = this.str.split('\r\n');
                        while (lines.length > 1)
                        {
                            this.parent.promise.emit('result', lines.shift());
                        }
                        this.str = lines[0];
                    });
                });

                ret.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['powershell']);
                ret.child.stdout.on('data', function (c) { /*console.log('stdout: ' + c.toString());*/ });
                ret.child.stdin.write('[reflection.Assembly]::LoadWithPartialName("system.core")\r\n');
                ret.child.stdin.write('$pipe = new-object System.IO.Pipes.NamedPipeClientStream(".", "' + ret._clientpath + '", 3);\r\n');
                ret.child.stdin.write('$pipe.Connect(); \r\n');
                ret.child.stdin.write('$sw = new-object System.IO.StreamWriter($pipe);\r\n');
                ret.child.stdin.write('Get-ChildItem -Path ' + root.split('\\').join('\\\\') + ' -Include ' + (Array.isArray(criteria)?criteria.join(','):criteria) + ' -File -Recurse -ErrorAction SilentlyContinue |');
                ret.child.stdin.write(' ForEach-Object -Process { $sw.WriteLine($_.FullName); $sw.Flush(); }\r\n');
                ret.child.stdin.write('exit\r\n');

                return (ret);
            };
            break;
        default:
            this.find = function find(root, criteria)
            {
                var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
                require('events').EventEmitter.call(ret, true)
                    .createEvent('result')
                    .createEvent('end');
                var searchArgs = ['find', root];
                if(process.platform == 'linux') 
                {
                    searchArgs.push('-type');
                    searchArgs.push('f');
                    searchArgs.push('(');
                }
                if (Array.isArray(criteria))
                {
                    searchArgs.push('-name');
                    searchArgs.push(criteria.shift());

                    while(criteria.length>0)
                    {
                        searchArgs.push('-o');
                        searchArgs.push('-name');
                        searchArgs.push(criteria.shift());
                    }
                }
                else
                {
                    searchArgs.push('-name');
                    searchArgs.push(criteria);
                }
                if (process.platform == 'linux') { searchArgs.push(')'); }
                ret.child = require('child_process').execFile('/usr/bin/find', searchArgs);
                if (ret.child == null)
                {
                    ret._res();
                    return (ret);
                }
                ret.child.stdout.str = ''; ret.child.stdout.p = ret;
                ret.child.stdout.on('data', function (c)
                {
                    this.str += c.toString();
                    var lines = this.str.split('\n');
                    while (lines.length > 1)
                    {
                        this.p.emit('result', lines.shift());
                    }
                    this.str = lines.pop();
                });
                ret.child.stderr.on('data', function (c) { });
                ret.child.on('exit', function (c)
                {
                    if (this.stdout.str.trim() != '') { this.stdout.p.emit('result', this.stdout.str.trim()); }
                    this.stdout.p.emit('end');
                    this.stdout.p._res();
                });
                return (ret);
            };
            break;
    }
}

module.exports = new filesearch();