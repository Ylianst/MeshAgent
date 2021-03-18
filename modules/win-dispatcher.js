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

function emptyhandler()
{
}
function stdparser(c)
{
    this.str += c.toString();
}
function ConnectionHandler2(s)
{
    if (this.parent.isAlive())
    {
        this.parent.object._control = s;
        this.parent.object._control._parent = this;
        this.close();
        this.parent.object.invoke = function (method, args)
        {
            var d, h = Buffer.alloc(4);
            d = Buffer.from(JSON.stringify({ command: 'invoke', value: { method: method, args: args } }));
            h.writeUInt32LE(d.length + 4);
            this._control.write(h);
            this._control.write(d);
        };
    }
}
function ConnectionHandler1(s)
{
    this.parent.object._client = s;
    this.parent.object._client._parent = this;
    this.close();
    var d, h = Buffer.alloc(4);
    s.descriptorMetadata = 'win-dispatcher, ' + this.parent.object.options.launch.module + '.' + this.parent.object.options.launch.method + '()';

    for (var m in this.parent.object.options.modules)
    {
        d = Buffer.from(JSON.stringify({ command: 'addModule', value: { name: this.parent.object.options.modules[m].name, js: this.parent.object.options.modules[m].script } }));
        h.writeUInt32LE(d.length + 4);
        s.write(h);
        s.write(d);
    }
    d = Buffer.from(JSON.stringify({ command: 'launch', value: { split: this.parent.object.options.launch.split ? true : false, module: this.parent.object.options.launch.module, method: this.parent.object.options.launch.method, args: this.parent.object.options.launch.args } }));
    h.writeUInt32LE(d.length + 4);
    s.write(h);
    s.write(d);
    this.parent.object.emit('connection', s);
}
function dispatch(options)
{
    if (!options || !options.modules || !options.launch || !options.launch.module || !options.launch.method || !options.launch.args) { throw ('Invalid Parameters'); }

    var ipcInteger
    var ret = { _ObjectID: 'dispatch', options: options };
    require('events').EventEmitter.call(ret, true).createEvent('connection');

    ret._ipc = require('net').createServer(); ret._ipc.parent = WeakReference(ret);
    ret._ipc2 = require('net').createServer(); ret._ipc2.parent = WeakReference(ret);
    ret._ipc.on('close', emptyhandler);
    ret._ipc2.on('close', emptyhandler);

    while (true)
    {
        ipcInteger = require('tls').generateRandomInteger('1000', '9999');
        ret._ipcPath = '\\\\.\\pipe\\taskRedirection-' + ipcInteger;
        
        try
        {
            ret._ipc.listen({ path: ret._ipcPath, writableAll: true });
            ret._ipc2.listen({ path: ret._ipcPath + 'C', writableAll: true });
            break;
        }
        catch (x)
        {
        }
    }
    var str = Buffer.from("require('win-console').hide();require('win-dispatcher').connect('" + ipcInteger + "');").toString('base64');
    ret._ipc2.once('connection', ConnectionHandler2);
    ret._ipc.once('connection', ConnectionHandler1);

    var taskoptions = { env: { _target: process.execPath, _args: '-b64exec ' + str, _user: '"' + options.user + '"' } };
    for (var c1e in process.env)
    {
        taskoptions.env[c1e] = process.env[c1e];
    }

    var child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['powershell', '-noprofile', '-nologo', '-command', '-'], taskoptions);
    child.stderr.on('data', stdparser);
    child.stdout.on('data', stdparser);
    child.stdin.write('SCHTASKS /CREATE /F /TN MeshUserTask /SC ONCE /ST 00:00 ');
    if (options.user)
    {
        child.stdin.write('/RU $env:_user ');
    }
    else
    {
        if (require('user-sessions').getProcessOwnerName(process.pid).tsid == 0)
        {
            // LocalSystem
            child.stdin.write('/RU SYSTEM ');
        }
    }
    child.stdin.write('/TR "$env:_target $env:_args"\r\n');
    child.stdin.write('$ts = New-Object -ComObject Schedule.service\r\n');
    child.stdin.write('$ts.connect()\r\n');
    child.stdin.write('$tsfolder = $ts.getfolder("\\")\r\n');
    child.stdin.write('$task = $tsfolder.GetTask("MeshUserTask")\r\n');
    child.stdin.write('$taskdef = $task.Definition\r\n');
    child.stdin.write('$taskdef.Settings.StopIfGoingOnBatteries = $false\r\n');
    child.stdin.write('$taskdef.Settings.DisallowStartIfOnBatteries = $false\r\n');
    child.stdin.write('$taskdef.Actions.Item(1).Path = $env:_target\r\n');
    child.stdin.write('$taskdef.Actions.Item(1).Arguments = $env:_args\r\n');
    child.stdin.write('$tsfolder.RegisterTaskDefinition($task.Name, $taskdef, 4, $null, $null, $null)\r\n');

    child.stdin.write('SCHTASKS /RUN /TN MeshUserTask\r\n');
    child.stdin.write('SCHTASKS /DELETE /F /TN MeshUserTask\r\nexit\r\n');

    child.waitExit();

    return (ret);
}

function connect(ipc)
{
    var ipcPath = '\\\\.\\pipe\\taskRedirection-' + ipc;
    global.ipc2Client = require('net').createConnection({ path: ipcPath + 'C' }, function ()
    {
        this.on('data', function (c)
        {
            var cLen = c.readUInt32LE(0);
            if (cLen > c.length)
            {
                this.unshift(c);
                return;
            }
            var cmd = JSON.parse(c.slice(4, cLen).toString());
            switch (cmd.command)
            {
                case 'invoke':
                    global._proxyStream[cmd.value.method].apply(global._proxyStream, cmd.value.args);
                    break;
            }

            if (cLen < c.length) { this.unshift(c.slice(cLen)); }
        });
    });
    global.ipcClient = require('net').createConnection({ path: ipcPath }, function ()
    {
        this.on('close', function () { process.exit(); });
        this.on('data', function (c)
        {
            var cLen = c.readUInt32LE(0);
            if (cLen > c.length)
            {
                this.unshift(c);
                return;
            }
            var cmd = JSON.parse(c.slice(4, cLen).toString());
            switch (cmd.command)
            {
                case 'addModule':
                    addModule(cmd.value.name, cmd.value.js);
                    break;
                case 'launch':
                    var obj = require(cmd.value.module);
                    global._proxyStream = obj[cmd.value.method].apply(obj, cmd.value.args);
                    if (cmd.value.split)
                    {
                        global._proxyStream.out.pipe(this, { end: false });
                        this.pipe(global._proxyStream.in, { end: false });
                        global._proxyStream.out.on('end', function () { process.exit(); });
                    }
                    else
                    {
                        global._proxyStream.pipe(this, { end: false });
                        this.pipe(global._proxyStream, { end: false });
                        global._proxyStream.on('end', function () { process.exit(); });
                    }
                    this.on('end', function () { process.exit(); });
                    break;
            }

            if (cLen < c.length) { this.unshift(c.slice(cLen)); }
        });
    });
    global.ipcClient.on('error', function () { process.exit(); });
    global.ipc2Client.on('error', function () { process.exit(); });
}

module.exports = { dispatch: dispatch, connect: connect };

