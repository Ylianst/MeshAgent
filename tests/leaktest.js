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
var duplex = require('stream').Duplex;
var promise = require('promise');
var http = require('https');
var processes = [];

//setModulePath('../modules');

var sample = new duplex(
    {
        'write': function (chunk, flush)
        {
            console.log(chunk.toString());
            flush();
            return (true);
        },
        'final': function (flush)
        {
        }                   
    });
var sample2 = new duplex(
    {
        'write': function (chunk, flush)
        {
            console.log(chunk.toString());
            flush();
            return (true);
        },
        'final': function (flush)
        {
        }
    });
function sample_final()
{
    console.log('Sample was finalized');
}
function sample2_final()
{
    console.log('Sample2 was finalized');
}
sample.once('~', sample_final);
sample2.once('~', sample2_final);

if (process.platform == 'win32')
{
    global.kernel32 = require('_GenericMarshal').CreateNativeProxy('kernel32.dll');
    global.kernel32.CreateMethod('GetCurrentProcess');
    global.kernel32.CreateMethod('GetProcessHandleCount');
}

function empty_function()
{
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
        case 'PIPE':
            console.displayStreamPipeMessages = 1;
            break;
        case 'FINAL':
            console.displayFinalizerMessages = 1;
            break;
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
        case 'ENDDISPATCH':
            stopDispatch();
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
        case 'WSS':
            global.wsserver = require('http').createServer();
            global.wsserver.on('upgrade', wss_OnUpgrade);
            global.wsserver.listen();
            console.log('Web Socket Server on port: ' + global.wsserver.address().port);
            break;
        case 'WSS4433':
            console.log('Generating Cert...');
            var cert = require('tls').generateCertificate('test', { certType: 2, noUsages: 1 });
            global.wsserver = require('https').createServer({ pfx: cert, passphrase: 'test' });
            global.wsserver.on('upgrade', wss_OnUpgrade);
            global.wsserver.listen({ port: 4433 });
            console.log('Web Socket Server on port: ' + global.wsserver.address().port);
            break;
        case 'WSC':
            webSocketClientTest(global.wsserver != null ? global.wsserver.address().port : 4433);
            break;
        case 'TUNEND':
            global.tun.end();
            //_debug();
            global.tun.unpipe();
            if (global.ipc) { global.ipc.unpipe(); }
            global.tun = null;
            global.ipc = null;
            //sample.unpipe();
            break;
        case 'GC':
            _debugGC();
            break;
        case 'SAMPLE':
            sample.unpipe();
            sample = null;
            break;
        case 'SAMPLEPIPE':
            sample.pipe(sample2);
            console.log('Sample Piped to Sample2');
            break;
    }
});

function wss_OnUpgrade(msg, sck, head)
{
    switch (msg.url)
    {
        case '/tunnel':
            this.cws = sck.upgradeWebSocket();
            this.cws.on('end', function () { console.log('Client WebSocket CLOSED'); });
            console.log('Accepted Client WebSocket');
            break;
    }
}
function req_finalized()
{
    console.log('Client Request Finalized');
}
function ws_finalized()
{
    console.log('Client WebSocket finalized');
}
function req_ws_upgrade(response, s, head) 
{
    console.log('Client Web Socket Connected', s._ObjectID);
    s.once('~', ws_finalized);

    global.tun = s;

    ////_debug();
    //sample.pipe(s);
    //s.pipe(sample);
    ////_debug();
    ////global.req = null;
}
function webSocketClientTest(port)
{
    console.log('Initiating WebSocket');

    var woptions = http.parseUri('wss://127.0.0.1:' + port + '/tunnel');
    woptions.rejectUnauthorized = 0;

    var req = http.request(woptions);
    req.on('upgrade', req_ws_upgrade);
    req.once('~', req_finalized);
    req.end();

}

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

            if(global.tun!=null)
            {
                global.ipc = this;
                console.log('Piping Together Stuff');
                global.tun.pipe(this);
                this.pipe(global.tun);
            }
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

function timeouthandler()
{
    console.log('Connection => ', global.connection_ref.eval());
    //_debugGC();
}

function _data(b)
{
    console.log(b.toString());
}
function _close()
{
    console.log('Client Closed');
    global._t = setTimeout(timeouthandler, 2000);
}
function _f()
{
    console.log('Connection Finalized');
}

function server_connection (c)
{
    //this.parent._connection = c;
    global.connection_ref = require('events')._refCountPointer(c);
    console.log('Connection => ', global.connection_ref.eval());
    c.on('data', _data);
    c.on('close', _close);
    c.on('~', _f);
    global.serverc = c;
}

function server_closed()
{

}

function startServer()
{
    console.log('   Current Handle Count => ' + getHandleCount());

    var ipcInteger;
    var ret = new promise(promise.defaultInit);
    ret._ipc = require('net').createServer(); ret._ipc.parent = ret;
    ret._ipc.on('close', server_closed);
    ret._ipc.on('connection', server_connection);

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
        this._ipc._connection.parent = null;
        this._ipc._connection = null;
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

function startDispatch_kill()
{
    console.log('Calling kill');
    this.dispatcher.invoke('kill', []);
}

function startDispatch_then()
{
    this.connection = c;
    c.on('data', function (b) { console.log(b.toString()); });

}

function dispatch_Ondata(x)
{
    process.stdout.write(x);
}
function dispatch_OnFinal()
{
    console.log('Client Connection Finalized');
}
function dispatch_OnEnd()
{
    console.log('Connected Ended');
}
function startDispatch_connect(c)
{
    console.log('TERMINAL CONNECTED');

    //console.logReferenceCount(c);
    this.term = c;
    //c.on('data', dispatch_Ondata);
    c.on('~', dispatch_OnFinal);
    //c.on('end', dispatch_OnEnd);

    c.pipe(sample);
}
function startDispatch_final()
{
    console.log('Dispatcher Finalized');
}

function startDispatch()
{
    var p = new promise(promise.defaultInit);

    //p.dispatcher = require('win-dispatcher').dispatch({ modules: [{ name: 'test_stream', script: getJSModule('test_stream') }], launch: { module: 'test_stream', method: 'start', args: [] } });
    //p.dispatcher.promise = p;
    //p.dispatcher.on('connection', function (c) { console.log('CONNECTED'); if (this.promise.completed) { c.end(); } else { c.on('end', function () { console.log('ENDED'); }); this.promise.resolve(c); } });
    //p.kill = startDispatch_kill;

    //processes.push(p);
    //p.then(startDispatch_then);

    p._dispatcher = require('win-dispatcher').dispatch({ modules: [{ name: 'win-virtual-terminal', script: getJSModule('win-virtual-terminal') }], launch: { module: 'win-virtual-terminal', method: 'Start', args: [80, 25] } });
    p._dispatcher.httprequest = this.httprequest;
    p._dispatcher.on('connection', startDispatch_connect);
    p._dispatcher.on('~', startDispatch_final);
    processes.push(p);
}
function stopDispatch()
{
    var p = processes.shift();
    if(p!=null)
    {
        console.log('Ending Connection');
        p._dispatcher.term.end();
        p._dispatcher.term.unpipe();
        p._dispatcher.term = null;
        p._dispatcher = null;
    }


}
