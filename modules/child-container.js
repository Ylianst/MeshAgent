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


function childContainer()
{
    this._ObjectID = 'child-container';
    this.create = function create(options)
    {
        if (!options || !options.launch || !options.launch.module || !options.launch.method || !options.launch.args) { throw ('Invalid Parameters'); }

        var ipcInteger;

        var ret = { options: options };
        require('events').EventEmitter.call(ret, true)
            .createEvent('ready')
            .createEvent('message')
            .createEvent('exit')
            .addMethod('disconnect', function ()
            {
                console.log('Disconnect child =>');
                this._client.end();
            })
            .addMethod('message', function (msg)
            {
                this.send({ command: 'message', value: msg });
            })
            .addMethod('exit', function (code)
            {
                this.send({ command: 'exit', value: code });
            })
            .addMethod('send', function (obj)
            {
                if (!this._client) { throw ('Not Connected'); }
                var d, h = Buffer.alloc(4);

                d = Buffer.from(JSON.stringify(obj));
                h.writeUInt32LE(d.length + 4);
                this._client.write(h);
                this._client.write(d);
            });

        ret._ipc = require('net').createServer(); ret._ipc.parent = ret;       
        ret._ipc.on('close', function () { console.log('Child Container Process Closed'); });

        while (true)
        {
            if (options._debugIPC && options._ipcInteger != null)
            { ipcInteger = options._ipcInteger; }
            else
            {
                ipcInteger = require('tls').generateRandomInteger('1000', '9999');
            }
            ret._ipcPath = '\\\\.\\pipe\\taskRedirection-' + ipcInteger;

            try
            {
                ret._ipc.listen({ path: ret._ipcPath, writableAll: true });
                break;
            }
            catch (x)
            {
                if(options._ipcInteger != null)
                {
                    console.log('DebugError: Unable to bind to IPC channel: ' + ipcInteger);
                    return (ret);
                }
            }
        }
        var script = Buffer.from("console.log('CHILD/START');require('child-container').connect('" + ipcInteger + "');").toString('base64');
        ret._ipc.once('connection', function onConnect(s)
        {
            this.parent._client = s;
            this.parent._client._parent = this;
            var data;
            for (var m in this.parent.options.modules)
            {
                data = { command: 'addModule', value: { name: this.parent.options.modules[m].name, js: this.parent.options.modules[m].script } };
                this.parent.send(data);
            }
            
            data = { command: 'launch', value: { module: this.parent.options.launch.module, method: this.parent.options.launch.method, args: this.parent.options.launch.args } };
            this.parent.send(data);
            s.once('close', function ()
            {
                console.log('close emitted');
                require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: 'close emitted'});
            });
            s.on('data', function (c)
            {
                var cLen;
                if (c.length < 4 || (cLen = c.readUInt32LE(0)) > c.length) { this.unshift(c); return; }
                var cmd = JSON.parse(c.slice(4, cLen).toString());
                switch (cmd.command)
                {
                    case 'message':
                        this._parent.parent.emit('message', cmd.value);
                        break;
                     default:
                        break;
                }

                if (cLen < c.length) { this.unshift(c.slice(cLen)); }
            });
            this.parent.emit('ready');
        });

        if (options._debugIPC)
        {
            console.log('-b64exec ' + script);
            return (ret);
        }

        // Spawn the child
        if(options.user && process.platform == 'win32')
        {
            // Use Task Scheduler
            var parms = '/C SCHTASKS /CREATE /F /TN MeshUserTask /SC ONCE /ST 00:00 ';
            parms += ('/RU ' + options.user + ' ');
            parms += ('/TR "\\"' + process.execPath + '\\" -b64exec ' + script + '"');

            var child = require('child_process').execFile(process.env['windir'] + '\\system32\\cmd.exe', [parms]);
            child.stderr.on('data', function (c) { });
            child.stdout.on('data', function (c) { });
            child.waitExit();

            child = require('child_process').execFile(process.env['windir'] + '\\system32\\cmd.exe', ['cmd']);
            child.stderr.on('data', function (c) { });
            child.stdout.on('data', function (c) { });
            child.stdin.write('SCHTASKS /RUN /TN MeshUserTask\r\n');
            child.stdin.write('SCHTASKS /DELETE /F /TN MeshUserTask\r\nexit\r\n');
            child.waitExit();
        }
        else
        {
            var child_options = {};
            if(options.uid != null)
            {
                var tsid;
                if ((tsid = require('user-sessions').getProcessOwnerName(process.pid).tsid) == 0)
                {
                    // We are running as LocalSystem
                    child_options.uid = options.uid;
                    child_options.type = require('child_process').SpawnTypes.USER;
                }
                else
                {
                    // We won't be able to switch session IDs, so check to make sure we are running as this sid
                    if (options.sid != tsid) { throw ('Insufficient permission to run as this user'); }
                }
            }
            ret._proc = require('child_process').execFile(process.execPath, [process.execPath.split(process.platform == 'win32' ? '\\' : '/').pop(), '-b64exec', script], child_options);
            ret._proc.parent = ret;
            ret._proc.stdout.on('data', function (c) { });
            ret._proc.stderr.on('data', function (c) { });
            ret._proc.on('exit', function (code)
            {
                this.parent.emit('exit', code);
            });
        }
        return (ret);
    }
    this.connect = function (ipcNumber)
    {
        var ipcPath = '\\\\.\\pipe\\taskRedirection-' + ipcNumber;
        this._ipcClient = require('net').createConnection({ path: ipcPath }, function ()
        {
            this.on('close', function () { process._exit(0); });
            this.on('data', function (c)
            {
                var cLen;
                if (c.length < 4 || (cLen = c.readUInt32LE(0)) > c.length) { this.unshift(c); return; }

                var cmd = JSON.parse(c.slice(4, cLen).toString());
                switch (cmd.command)
                {
                    case 'addModule':
                        addModule(cmd.value.name, cmd.value.js);
                        break;
                    case 'launch':
                        var obj = require(cmd.value.module);
                        this._result = obj[cmd.value.method].apply(obj, cmd.value.args);
                        this.on('end', function () { process.exit(); });
                        break;
                    case 'message':
                        this._parent.emit('message', cmd.value);
                        break;
                    case '_disconnect':
                        console.log('Disconnecting...');
                        this.end();
                        break;
                    case 'exit':
                        try
                        {
                            this._parent.emit('exit');
                        }
                        catch (ee)
                        { }
                        process._exit(0);
                        break;
                }

                if (cLen < c.length) { this.unshift(c.slice(cLen)); }
            });
        });
        this._ipcClient._parent = this;

        require('events').EventEmitter.call(this, true)
            .createEvent('message')
            .createEvent('exit')
            .addMethod('message', function (msg)
            {
                this.send({ command: 'message', value: msg });
            })
            .addMethod('send', function (data)
            {
                if (!this._ipcClient) { throw ('Not Connected'); }
                var d, h = Buffer.alloc(4);

                d = Buffer.from(JSON.stringify(data));
                h.writeUInt32LE(d.length + 4);
                this._ipcClient.write(h);
                this._ipcClient.write(d);
            });
    };
}


module.exports = new childContainer();