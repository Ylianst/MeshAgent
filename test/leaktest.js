/*
Copyright 2022 Intel Corporation
@author Bryan Roe

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
var processes = [];
//setModulePath('../modules');

if (process.platform == 'win32')
{
    global.kernel32 = require('_GenericMarshal').CreateNativeProxy('kernel32.dll');
    global.kernel32.CreateMethod('GetCurrentProcess');
    global.kernel32.CreateMethod('GetProcessHandleCount');
}

function getHandleCount()
{
    if (process.platform != 'win32') { return (0); }

    var h = global.kernel32.GetCurrentProcess();
    var c = require('_GenericMarshal').CreateVariable(4);

    global.kernel32.GetProcessHandleCount(h, c);
    return (c.toBuffer().readUInt32LE());
}


console.log('Leak Test Started:');
if (process.platform == 'win32')
{
    console.log('   dispatch = Start Windows Dispatcher');
    console.log('   wmi = Use WMI to create Task');
    console.log('   ps = Win-Virtual-Terminal test');
    console.log('   reg = win-reg test');
    console.log('   user = Windows User ID test');
}

console.log('   server = Start IPC Server');
console.log('   client = Start IPC Client');
console.log('   start = Spawn Child Process');
console.log('   end = Close spawned process');
console.log('   exit = Exit Test');
console.log('   Current Handle Count => ' + getHandleCount());
console.log('\n');
process.stdin.on('data', function (c)
{
    if (c.toString() == null) { return; }
    switch(c.toString().trim().toUpperCase())
    {
        case 'VERBOSE':
            console.setInfoLevel(1);
            console.info1('SetInfoLevel');
            break;
        case 'START':
            startProcess();
            break;
        case 'END':
            endProcess();
            break
        case 'EXIT':
            process.exit();
            break;
        case 'DISPATCH':
            startDispatch();
            break;
        case 'SERVER':
            startServer();
            break;
        case 'CLIENT':
            startClient();
            break;
        case 'WMI':
            wmiTest();
            break;
        case 'USER':
            userTest();
            break;
        case 'REG':
            regTest();
            break;
        case 'PS':
            console.log('PS Capable = ' + require('win-virtual-terminal').PowerShellCapable());
            console.log('ConPTY = ' + require('win-virtual-terminal').supported);
            break;
    }
});

function regTest()
{
    var reg = require('win-registry');
    console.log('   Current Handle Count => ' + getHandleCount());
    //var entries = require('win-registry').QueryKey(require('win-registry').HKEY.Users);
    var key = reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Control\\Safeboot\\Network\\AltMeshAgent');
    console.log('   Current Handle Count => ' + getHandleCount());

}

function userTest()
{
    var user, domain = null;

    if (require('user-sessions').getProcessOwnerName(process.pid).tsid == 0)
    {
        console.log('A');
        user = 'SYSTEM'
    }
    else
    {
        var info = require('user-sessions').getProcessOwnerName(process.pid);
        user = info.name;
        domain = info.domain;
        console.log(user, domain);
    }


    console.log('   Current Handle Count => ' + getHandleCount());
    var userID = require('win-registry').usernameToUserKey({ user: user, domain: domain });
    console.log('   Current Handle Count => ' + getHandleCount());

}
function wmiTest()
{
    console.log('   Current Handle Count => ' + getHandleCount());

    var str = Buffer.from("console.log('hi');").toString('base64');
    var user = null;
    var domain = null;

    if (require('user-sessions').getProcessOwnerName(process.pid).tsid == 0)
    {
        user = 'SYSTEM'
    }
    else
    {
        var info = require('user-sessions').getProcessOwnerName(process.pid);
        user = info.name;
        domain = info.domain;
    }


    var task = { name: 'MeshUserTask', user: user, domain: domain, execPath: process.execPath, arguments: ['-b64exec ' + str] };
    try
    {
        require('win-tasks').addTask(task);
        //require('win-tasks').getTask({ name: 'MeshUserTask' }).run();
        //require('win-tasks').deleteTask('MeshUserTask');
    }
    catch(x)
    {

    }
    console.log('   Current Handle Count => ' + getHandleCount());
}

function startClient()
{
    var ret = new promise(promise.defaultInit);
    console.log('   Current Handle Count => ' + getHandleCount());

    var path = processes.length > 0 ? processes.peek()._ipcPath : null;
    //var path = '\\\\.\\pipe\\taskRedirection-1000';
    if (path != null)
    {
        ret.ipcClient = require('net').createConnection({ path: path }, function ()
        {
            console.log('Client Connection OK');
            this.on('close', function ()
            {
                console.log('CLIENT CLOSED');
                _debug();
            });
            this.on('data', function (c) { });
        });
        ret.kill = function ()
        {
            console.log('ENDING client');
            ret.ipcClient.end();
        };
        processes.push(ret);
    }
    else
    {
        console.log('No Server');
    }
    console.log('   Current Handle Count => ' + getHandleCount());
}

function startServer()
{
    console.log('   Current Handle Count => ' + getHandleCount());

    var ipcInteger;
    var ret = new promise(promise.defaultInit);
    ret._ipc = require('net').createServer(); ret._ipc.parent = ret;
    ret._ipc.on('close', function () { });
    ret._ipc.on('connection', function (c)
    {
        this.parent._connection = c;
        c.on('data', function (b) { console.log(b.toString()); });
    });

    while (true)
    {
        ipcInteger = require('tls').generateRandomInteger('1000', '9999');
        //ipcInteger = 1000;
        ret._ipcPath = process.platform == 'win32' ? ('\\\\.\\pipe\\taskRedirection-' + ipcInteger) : ipcInteger.toString();

        try
        {
            ret._ipc.listen({ path: ret._ipcPath, writableAll: true });
            break;
        }
        catch (x)
        {
        }
    }
    ret.kill = function ()
    {
        this._ipc.close();
    };
    processes.push(ret);
    console.log('   Current Handle Count => ' + getHandleCount());
}

function endProcess()
{
    if (processes.length > 0)
    {
        processes.pop().kill();
    }
    else
    {
        console.log('No Processes');
    }
    console.log('HandleCount => ' + getHandleCount());
}
function startProcess()
{
    var c = require('child_process').execFile(process.execPath, [process.execPath, "-exec", "console.log('Started');"]);
    c.stdout.on('data', function (b) { console.log(b.toString()); });
    c.on('exit', function () { console.log('Process Exited...'); });
    processes.push(c);
    console.log('HandleCount => ' + getHandleCount());
}
function startDispatch()
{
    var p = new promise(promise.defaultInit);
    p.dispatcher = require('win-dispatcher').dispatch({ modules: [{ name: 'test_stream', script: getJSModule('test_stream') }], launch: { module: 'test_stream', method: 'start', args: [] } });
    p.dispatcher.promise = p;
    p.dispatcher.on('connection', function (c) { console.log('CONNECTED'); if (this.promise.completed) { c.end(); } else { c.on('end', function () { console.log('ENDED'); }); this.promise.resolve(c); } });
    p.kill = function ()
    {
        console.log('Calling kill');
        this.dispatcher.invoke('kill', []);
    };
    processes.push(p);
    p.then(function (c)
    {
        this.connection = c;
        c.on('data', function (b) { console.log(b.toString()); });
    });




    //p._dispatcher = require('win-dispatcher').dispatch({ modules: [{ name: 'win-virtual-terminal', script: getJSModule('win-virtual-terminal') }], launch: { module: 'win-virtual-terminal', method: 'Start', args: [80, 25] } });
    //p._dispatcher.httprequest = this.httprequest;
    //p._dispatcher.on('connection', function (c)
    //{
    //    console.log('TERMINAL CONNECTED');
    //    p.term = c;
    //    c.on('data', function (x) { process.stdout.write(x); });
    //});

}