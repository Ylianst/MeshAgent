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


// action:
//      msg
//          type:
//               console
//               tunnel
//               messagebox
//               ps
//               pskill
//               services
//               serviceStop
//               serviceStart
//               serviceRestart
//               deskBackground
//               openUrl
//               getclip
//               setclip
//               userSessions
//      acmactivate
//      wakeonlan
//      runcommands
//      toast
//      amtPolicy
//      sysinfo

var img = 'image/jpeg,base64,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';

Object.defineProperty(Array.prototype, 'getParameterEx',
    {
        value: function (name, defaultValue)
        {
            var i, ret;
            for (i = 0; i < this.length; ++i)
            {
                if (this[i].startsWith(name + '='))
                {
                    ret = this[i].substring(name.length + 1);
                    if (ret.startsWith('"')) { ret = ret.substring(1, ret.length - 1); }
                    return (ret);
                }
            }
            return (defaultValue);
        }
    });
Object.defineProperty(Array.prototype, 'getParameter',
    {
        value: function (name, defaultValue)
        {
            return (this.getParameterEx('--' + name, defaultValue));
        }
    });
Object.defineProperty(Array.prototype, 'getParameterIndex',
    {
        value: function (name)
        {
            var i;
            for (i = 0; i < this.length; ++i)
            {
                if (this[i].startsWith('--' + name + '='))
                {
                    return (i);
                }
            }
            return (-1);
        }
    });


var promise = require('promise');
var localmode = true;
var debugmode = false;

function agentConnect(test, ipcPath)
{
    img = '';
    if (global.agentipc_next)
    {
        global.agentipc = global.agentipc_next;
        global.agentipc.count = 0;
        global.agentipc_next = null;
    }
    else
    {
        if (global.agentipc == null)
        {
            global.agentipc = new promise(function (r, j) { this._res = r; this._rej = j; });
            global.agentipc.count = 0;
        }
    }
    global.client = require('net').createConnection({ path: ipcPath });
    global.client.test = test;
    global.client.on('error', function ()
    {
        if (global.agentipc.count++ > 100)
        {
            global.agentipc._rej('      -> Connection Timeout...');
        }
        else
        {
            global._rt = setTimeout(function () { agentConnect(test, ipcPath); }, 100);
        }
    });
    global.client.on('end', function ()
    {
        console.log('      -> Connection error, reconnecting...');
        this.removeAllListeners('data');

        global._timeout = setTimeout(function (a, b) { agentConnect(a, b); }, 100, test, ipcPath);
    });
    global.client.on('data', function (chunk)
    {
        var len;
        if (chunk.length < 4) { this.unshift(chunk); return; }
        if ((len = chunk.readUInt32LE(0)) > chunk.length)
        {
            if (debugmode) { console.log('RECV: ' + chunk.length + ' bytes but expected ' + len + ' bytes'); }
            this.unshift(chunk); return;
        }

        var data = chunk.slice(4, len);
        var payload = null;
        try
        {
            payload = JSON.parse(data.toString());
        }
        catch (e)
        {
            if (debugmode) { console.log('JSON ERROR on emit: ' + data.toString()); }
            return;
        }
        if (debugmode) { console.log('\n' + 'EMIT: ' + data.toString()); }
        if (payload.cmd == 'server')
        {
            this.test.emit('command', payload.value);
        }
        else
        {
            this.test.emit('command', payload);
        }
        if (len < chunk.length)
        {
            if (debugmode) { console.log('UNSHIFT', len, chunk.length); }
            this.unshift(chunk.slice(len));
        }

    });
    global.client.on('connect', function ()
    {
        // Register on the IPC for responses
        try
        {
            var cmd = "_sendConsoleText = sendConsoleText; sendConsoleText = function(msg,id){ for(i in obj.DAIPC._daipc) { obj.DAIPC._daipc[i]._send({cmd: 'console', value: msg});}};";
            cmd += "require('MeshAgent')._SendCommand=require('MeshAgent').SendCommand;require('MeshAgent').SendCommand = function(j){ for(i in obj.DAIPC._daipc) { obj.DAIPC._daipc[i]._send({cmd: 'server', value: j});} };"

            var reg = { cmd: 'console', value: 'eval "' + cmd + '"' };

            if (debugmode)
            {
                console.log(JSON.stringify(reg, null, 1));
            }
            var ocmd = Buffer.from(JSON.stringify(reg));
            var buf = Buffer.alloc(4 + ocmd.length);
            buf.writeUInt32LE(ocmd.length + 4, 0);
            ocmd.copy(buf, 4);
            this.write(buf);

            global._tt = setTimeout(function () { global.agentipc._res(); }, 2000);
        }
        catch (f)
        {
            console.log(f);
        }
    });
}

function start()
{
    var isservice = false;
    var servicename = process.argv.getParameter('serviceName');
    var ipcPath = null;
    var svc = null;
    debugmode = process.argv.getParameter('debugMode', false);

    if (servicename != null)
    {
        try
        {
            var svc = require('service-manager').manager.getService(servicename);
            if (!svc.isRunning())
            {
                console.log('      -> Agent: ' + servicename + ' is not running');
                process._exit();
            }

        }
        catch (e)
        {
            console.log('      -> Agent: ' + servicename + ' not found');
            process._exit();
        }


        if (process.platform == 'win32')
        {
            // Find the NodeID from the registry
            var reg = require('win-registry');
            try
            {
                var val = reg.QueryKey(reg.HKEY.LocalMachine, 'Software\\Open Source\\' + servicename, 'NodeId');
                val = Buffer.from(val.split('@').join('+').split('$').join('/'), 'base64').toString('hex').toUpperCase();
                ipcPath = '\\\\.\\pipe\\' + val + '-DAIPC';
            }
            catch (e)
            {
                console.log('      -> Count not determine NodeID for Agent: ' + servicename);
                process._exit();
            }
        }
        else
        {
            ipcPath = svc.appWorkingDirectory() + 'DAIPC';
        }
    }

    if (debugmode)
    {
        console.log('\n' + 'ipcPath = ' + ipcPath + '\n');
    }

    if (ipcPath != null)
    {
        localmode = false;
        console.log('   -> Connecting to agent...');
        agentConnect(this, ipcPath);

        try
        {
            promise.wait(global.agentipc);
            console.log('      -> Connected........................[OK]');
        }
        catch(e)
        {
            console.log('      -> ERROR........................[FAILED]');
            process._exit();
        }

        this.toAgent = function remote_toAgent(inner)
        {
            inner.sessionid = 'pipe';
            var icmd = "Buffer.from('" + Buffer.from(JSON.stringify(inner)).toString('base64') + "','base64').toString()";
            var ocmd = { cmd: 'console', value: 'eval "require(\'MeshAgent\').emit(\'Command\', JSON.parse(' + icmd + '));"'};
            ocmd = Buffer.from(JSON.stringify(ocmd));

            if (debugmode) { console.log('\n' + 'To AGENT => ' + JSON.stringify(ocmd) + '\n'); }

            var buf = Buffer.alloc(4 + ocmd.length);
            buf.writeUInt32LE(ocmd.length + 4, 0);
            ocmd.copy(buf, 4);
            global.client.write(buf);
        };

        if (debugmode=='2') { console.log('\nDEBUG MODE\n'); return; }
    }

    console.log('Starting Self Test...');

    if (process.argv.getParameter('dumpOnly', false))
    {
        var iterations = process.argv.getParameter('cycleCount', 20);
        console.log('Core Dump Test Mode, ' + iterations + ' cycles');

        DumpOnlyTest(iterations)
            .then(function () { return (completed()); })
            .then(function ()
            {
                console.log('End of Self Test');
                process._exit();
            })
            .catch(function (v)
            {
                console.log(v);
                process._exit();
            });
    }
    else
    {
        coreInfo()
            .then(function () { return (testLMS()); })
            .then(function () { return (testConsoleHelp()); })
            .then(function () { return (testCPUInfo()); })
            .then(function () { return (WebRTC_Test()); })
            .then(function () { return (testTunnel()); })
            .then(function () { return (testTerminal()); })
            .then(function () { return (testKVM()); })
            .then(function () { return (testFileDownload()); })
            .then(function () { return (testCoreDump()); })
            .then(function () { return (testServiceRestart()); })
            .then(function () { return (completed()); })
            .then(function ()
            {
                console.log('End of Self Test');
                process._exit();
            })
            .catch(function (v)
            {
                console.log(v);
                process._exit();
            });
    }
}

function WebRTC_Test()
{
    console.log('   => Testing WebRTC');

    var ret = new promise(function (r, j) { this._res = r; this._rej = j; });
    ret.factory = require('ILibWebRTC').createNewFactory();
    ret.serverConnection = ret.factory.createConnection();
    ret.clientConnection = require('ILibWebRTC').createConnection();
    ret.clientConnection.on('dataChannel', function (rtcchannel) { rtcchannel.write(Buffer.alloc(6665535)); });

    var offer = ret.clientConnection.generateOffer()
    var counter = ret.serverConnection.setOffer(offer);
    ret.clientConnection.setOffer(counter);

    ret.serverConnection.on('connected', function ()
    {
        this.dc = this.createDataChannel('Test Data Channel');
        this.dc.on('data', function (b)
        {
            if (b.length == 6665535)
            {
                console.log('       => WebRTC Data Channel Test........[OK]');
                ret._res();
            }
        });
    });

    return (ret);
}

function DumpOnlyTest_cycle(pid, cyclecount, p, self)
{
    if(cyclecount==0) { p._res(); return; }

    console.log('   => Starting Cycle: ' + cyclecount + ' Current PID = ' + pid);

    var nextp = new promise(function (r, j) { this._res = r; this._rej = j; });
    global.agentipc_next = nextp

    self.consoleCommand("eval require('MeshAgent').restartCore();").catch(function () { });
    try
    {
        promise.wait(nextp);
    }
    catch(e)
    {
        p._rej(e);
        return;
    }

    try
    {
        var newpid = promise.wait(self.agentQueryValue('process.pid'));
        if (newpid == pid)
        {
            console.log('      => Mesh Core successfully restarted without crashing');
            var t = getRandom(0, 20000);
            console.log('      => Waiting ' + t + ' milliseconds before starting next cycle');
            global._t = setTimeout(function (_pid, _cyclecount, _p, _self)
            {
                DumpOnlyTest_cycle(_pid, _cyclecount, _p, _self);
            }, t, pid, cyclecount-1, p, self);
        }
        else
        {
            p._rej('      => Mesh Core restart resulted in crash. PID = ' + newpid);
        }
        return;
    }
    catch(e)
    {
        p._rej(e);
        return;
    }
}

function DumpOnlyTest(cyclecount)
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    if (localmode)
    {
        ret._rej('   => Background Agent connection required...');
        return (ret);
    }

    var p = this.agentQueryValue("process.pid");
    p.self = this;
    p.then(function (pid)
    {
        DumpOnlyTest_cycle(pid, cyclecount, ret, this.self);
    }).catch(function (v)
    {
        ret._rej(v);
    });

    return (ret);
}

function completed()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret._res();

    if (!localmode)
    {
        // We're restarting the core, to undo the changes that were made to the core, to run the self-test.
        this.consoleCommand("eval require('MeshAgent').restartCore();");
    }
    return (ret);
}

function getFDSnapshot()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret.tester = this;
    ret.tester.consoletext = '';
    ret.consoleTest = this.consoleCommand('fdsnapshot');
    ret.consoleTest.parent = ret;
    ret.consoleTest.then(function (J)
    {
        console.log('   => FDSNAPSHOT');
        console.log(this.tester.consoletext);
        this.parent._res();
    }).catch(function (e)
    {
        this.parent._rej('   => FDSNAPSHOT..........................[FAILED]');
    });
    return (ret);
}

function testLMS()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret.tester = this;
    ret._test = function ()
    {
        // AMT is supported, so we need to test to see if LMS is responding
        this.req = require('http').request(
        {
            protocol: 'http:',
            host: '127.0.0.1',
            port: 16992,
            method: 'GET',
            path: '/'
        });
        this.req.on('response', function (imsg)
        {
            if (this.tester.microlms)
            {
                console.log('         -> Testing MicroLMS..............[OK]');
            }
            else
            {
                console.log('         -> Testing External LMS..........[OK]');
            }
            this.p._res();
        })
        this.req.on('error', function (err)
        {
            if (this.tester.microlms)
            {
                this.p._rej('         -> Testing MicroLMS..............[FAILED]');
            }
            else
            {
                this.p._rej('         -> Testing External LMS..........[FAILED]');
            }
        });
        this.req.tester = this.tester;
        this.req.p = this;
        this.req.end();
    };


    if (!this.amtsupport)
    {
        console.log('         -> Testing LMS...................[N/A]');
        ret._res();
    }
    else
    {
        if (this.microlms)
        {
            this.on('command', function _lmsinfoHandler(v)
            {
                if (v.action == 'lmsinfo')
                {
                    if (v.value.ports.includes('16992'))
                    {
                        this.removeListener('command', _lmsinfoHandler);
                        console.log('         -> Micro LMS bound to 16992......[OK]');
                        ret._test();
                    }
                }
            });
        }
        else
        {
            ret._test();
        }
    }
    return (ret);
}

function coreInfo()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    console.log('   => Waiting for Agent Info');

    ret.tester = this;
    ret.handler = function handler(J)
    {
        if (debugmode) { console.log(JSON.stringify(J)); }
        switch(J.action)
        {
            case 'netinfo':
            case 'sessions':
                ret._sessions = true;
                break;
            case 'coreinfo':
                if (!handler.coreinfo)
                {
                    handler.coreinfo = true;
                    console.log('      -> Core Info received..............[OK]');
                    console.log('');
                    console.log('         ' + J.osdesc);
                    console.log('         ' + J.value);
                    console.log('');
                }
                if (J.intelamt && J.intelamt.microlms == 'CONNECTED')
                {
                    if (!handler.tester.microlms)
                    {
                        handler.tester.microlms = true;
                        console.log('         -> Micro LMS.....................[CONNECTED]');

                        this.removeListener('command', handler);
                        handler.promise._res();
                    }
                }
                if (process.argv.includes('--showCoreInfo="1"'))
                {
                    console.log('\n' + JSON.stringify(J) + '\n');
                }

                break;
            case 'smbios':
                if (!handler.smbios)
                {
                    handler.smbios = true;
                    console.log('      -> SMBIOS Info received.............[OK]');
                    var tables = null;
                    try
                    {
                        tables = require('smbios').parse(J.value);
                        handler.tester.amtsupport = tables.amtInfo && tables.amtInfo.AMT;
                        console.log('         -> AMT Support...................[' + ((tables.amtInfo && tables.amtInfo.AMT == true) ? 'YES' : 'NO') + ']');
                    }
                    catch (e)
                    {
                        clearTimeout(handler.timeout);
                        console.log(e);
                        handler.promise._rej('         -> (Parse Error).................[FAILED]');
                        return;
                    }
                    if (!handler.tester.amtsupport)
                    {
                        clearTimeout(handler.timeout);
                        handler.promise._res();
                    }
                }
                if (process.argv.includes('--smbios="1"'))
                {
                    console.log(JSON.stringify(tables));
                }

                break;
        }
    };
    ret.handler.tester = ret.tester;
    ret.handler.promise = ret;
    ret.handler.coreinfo = false;
    ret.handler.smbios = false;
    ret.tester.amtsupport = false;
    ret.tester.microlms = false;
    ret.tester.on('command', ret.handler);

    ret.handler.timeout = setTimeout(function (r)
    {
        if(!r.handler.coreinfo)
        {
            if (r._sessions)
            {
                console.log('      -> Core Info received...............[OK]')
                r._res();
                return;
            }
            // Core Info was never recevied
            r._rej('      -> Core Info received...............[FAILED]')
        }
        else if(r.handler.amt)
        {
            // AMT support, so check Micro LMS
            if(r.handler.microlms)
            {
                r._res();
            }
            else
            {
                // No MicroLMS, so let's check to make sure there is an LMS service running
                console.log('         -> Micro LMS.....................[NO]');
            }
        }
        else
        {
            // No AMT Support
            r._res();
        }
    }, 10000, ret);

    if (localmode)
    {
        require('MeshAgent').emit('Connected', 3);
    }
    else
    {
        ret._info = this.consoleCommand("eval \"require('MeshAgent').emit('Connected', 3);\"");
    }

    return (ret);
}

function testServiceRestart()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });

    if (localmode)
    {
        ret._res();
        return (ret);
    }
    console.log('   => Service Restart Test');
    ret.self = this;
    //ret._part1 = this.consoleCommand("eval \"var _A=setTimeout(function(){sendConsoleText(require('MeshAgent').serviceName);},1000);\"");
    ret._part1 = this.agentQueryValue("require('MeshAgent').serviceName");
    ret._part1.then(function (c)
    {
        console.log('      => Service Name = ' + c);
        ret._servicename = c;

        var nextp = new promise(function (r, j) { this._res = r; this._rej = j; });
        global.agentipc_next = nextp

        console.log('      -> Restarting Service...');
        ret.self.consoleCommand("service restart").catch(function (x)
        {
            //ret._rej('         -> Restarted.....................[FAILED]');
        });

        try
        {
            promise.wait(nextp);
            console.log('         -> Restarted.....................[OK]');
            ret._res();
        }
        catch(f)
        {
            console.log(f);
            ret._rej('         -> Restarted.....................[FAILED]');
        }
    });

    return (ret);
}

function testCoreDump()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });

    if (localmode)
    {
        ret._res();
        return (ret);
    }
    console.log('   => Mesh Core Dump Test');
    ret.self = this;
    ret.consoleTest = this.consoleCommand('eval process.pid');
    ret.consoleTest.ret = ret;
    ret.consoleTest.self = this;
    ret.consoleTest.then(function coreDumpTest_1(c)
    {
        var pid = c;
        console.log('      -> Agent PID = ' + c);

        if (process.platform == 'linux' || process.platform == 'freebsd')
        {
            var p = ret.self.agentQueryValue("require('monitor-info').kvm_x11_support");
            if (promise.wait(p).toString() != 'true')
            {
                // No KVM Support, so just do a plain dump test
                var nextp = new promise(function (r, j) { this._res = r; this._rej = j; });
                global.agentipc_next = nextp
                console.log('      -> Initiating plain dump test');
                ret.self.consoleCommand("eval require('MeshAgent').restartCore();");
                try
                {
                    promise.wait(nextp);
                    ret.self.agentQueryValue('process.pid').then(function (cc)
                    {
                        if (cc == pid)
                        {
                            console.log('      -> Core Restarted without crashing..[OK]');
                            ret._res();
                        }
                        else
                        {
                            ret._rej('      -> Core Restart resulted in crash...[FAILED]');
                        }
                    });
                }
                catch (z)
                {
                    ret._rej('      -> ERROR', z);
                }
                return;
            }
        }

        console.log('      -> Initiating KVM for dump test');
        ret.tunnel = this.self.createTunnel(0x1FF, 0x00);
        ret.tunnel.then(function (c)
        {
            this.connection = c;
            c.ret = this.ret;
            c.jumbosize = 0;
            c.on('data', function (buf)
            {
                if (typeof (buf) == 'string') { return; }
                var type = buf.readUInt16BE(0);
                var sz = buf.readUInt16BE(2);

                if (type == 3 && sz == buf.length)
                {
                    this.removeAllListeners('data');
                    var nextp = new promise(function (r, j) { this._res = r; this._rej = j; });
                    global.agentipc_next = nextp

                    console.log('      -> KVM initiated, dumping core');
                   ret.self.consoleCommand("eval require('MeshAgent').restartCore();");
                   // ret.self.consoleCommand("eval _debugCrash()");

                    try
                    {
                        promise.wait(nextp);
                        ret.self.agentQueryValue('process.pid').then(function (cc)
                        {
                            if(cc==pid)
                            {
                                console.log('      -> Core Restarted without crashing..[OK]');
                                ret._res();
                            }
                            else
                            {
                                ret._rej('      -> Core Restart resulted in crash...[FAILED]');
                            }
                        });
                    }
                    catch(z)
                    {
                        console.log('      -> ERROR', z);
                    }

                }
            });

            c.write('c');
            c.write('2'); // Request KVM
        });

    });

    return (ret);
}
function testFileDownload()
{
    console.log('   => File Transfer Test');
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret.tester = this;
    ret.tunnel = this.createTunnel(0x1FF, 0x00);
    ret.tunnel.ret = ret;
    ret.tunnel.then(function (c)
    {
        this.connection = c;
        c.ret = this.ret;
        c.ret.testbuffer = require('EncryptionStream').GenerateRandom(65535); // Generate 64k Test Buffer
        c.ret.testbufferCRC = crc32c(c.ret.testbuffer);

        c.on('data', function (buf)
        {
            // JSON Control Packet
            var cmd = JSON.parse(buf.toString());
            switch (cmd.action)
            {
                case 'uploadstart':
                    // Start sending the file in 16k blocks
                    this.uploadBuffer = this.ret.testbuffer.slice(0);
                    this.write(this.uploadBuffer.slice(0, 16384));
                    this.uploadBuffer = this.uploadBuffer.slice(16384);
                    break;
                case 'uploadack':
                    this.write(this.uploadBuffer.slice(0, this.uploadBuffer.length > 16384 ? 16384 : this.uploadBuffer.length));
                    this.uploadBuffer = this.uploadBuffer.slice(this.uploadBuffer.length > 16384 ? 16384 : this.uploadBuffer.length);
                    if (this.uploadBuffer.length == 0)
                    {
                        this.write({ action: 'uploaddone' });
                    }
                    break;
                case 'uploaddone':
                    console.log('      -> File Transfer (Upload)...........[OK]');
                    this.uploadsuccess = true;
                    this.end();
                    break;
            }
        });
        c.on('end', function ()
        {
            if (this.uploadsuccess != true)
            {
                this.ret._rej('      -> File Transfer (Upload)...........[FAILED]');
                return;
            }

            // Start download test, so we can verify the data
            this.ret.download = this.ret.tester.createTunnel(0x1FF, 0x00);
            this.ret.download.ret = this.ret;
            this.ret.download.tester = this.ret.tester;

            this.ret.download.then(
                function (dt)
                {
                    dt.ret = this.ret;
                    dt.crc = 0;
                    dt.on('data', function (b)
                    {
                        if(typeof(b)=='string')
                        {
                            var cmd = JSON.parse(b);
                            if (cmd.action != 'download') { return; }
                            switch(cmd.sub)
                            {
                                case 'start':
                                    this.write({ action: 'download', sub: 'startack', id: 0 });
                                    break;
                            }
                        }
                        else
                        {
                            var fin = (b.readInt32BE(0) & 0x01000001) == 0x01000001;
                            this.crc = crc32c(b.slice(4), this.crc);
                            this.write({ action: 'download', sub: 'ack', id: 0 });
                            if(fin)
                            {
                                if(this.crc == this.ret.testbufferCRC)
                                {
                                    // SUCCESS!

                                    console.log('      -> File Transfer (Download).........[OK]');
                                    this.end();
                                    this.ret._res();
                                }
                                else
                                {
                                    this.end();
                                    this.ret._rej('      -> File Transfer (Download).........[CRC FAILED]');
                                }
                            }
                        }
                    });
                    dt.on('end', function ()
                    {

                    });

                    console.log('      -> Tunnel (Download)................[CONNECTED]');
                    dt.write('c');
                    dt.write('5'); // Request Files
                    dt.write(JSON.stringify({ action: 'download', sub: 'start', path: process.cwd() + 'testFile', id: 0 }));
                })
                .catch(function (dte)
                {
                    ret._rej('      -> Tunnel (Download)................[FAILED]');
                });
        });

        console.log('      -> Tunnel (Upload)..................[CONNECTED]');
        c.write('c');
        c.write('5'); // Request Files
        c.write(JSON.stringify({ action: 'upload', name: 'testFile', path: process.cwd(), reqid: '0' }));
    }).catch(function (e)
    {
        this.parent._rej('   => File Transfer Test (Upload) [TUNNEL FAILED] ' + e);
    });

    return (ret);
}

function testCPUInfo()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    if (process.platform == 'freebsd')
    {
        console.log('   => Testing CPU Info....................[N/A]');
        ret._res();
        return (ret);
    }

    ret.consoleTest = this.consoleCommand('cpuinfo');
    ret.consoleTest.parent = ret;
    ret.consoleTest.then(function (J)
    {
        try
        {
            JSON.parse(J.toString());
            console.log('   => Testing CPU Info....................[OK]');
        }
        catch (e)
        {
            ret._rej('   => Testing CPU Info....................[ERROR]');
            return;
        }
        ret._res();
    }).catch(function (e)
    {  
        ret._rej('   => Testing CPU Info....................[FAILED]');
    });
    return (ret);
}

function testKVM()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret.tester = this;

    if (!localmode)
    {
        if(process.platform == 'linux' || process.platform == 'freebsd')
        {
            var p = this.agentQueryValue("require('monitor-info').kvm_x11_support");
            var val = promise.wait(p);
            if (val == false)
            {
                console.log('   => KVM Test............................[X11 NOT DETECTED]');
                ret._res();
                return (ret);
            }
        }
    }

    if (require('MeshAgent').hasKVM != 0)
    {
        if (process.platform == 'linux' || process.platform == 'freebsd')
        {
            if(require('monitor-info').kvm_x11_support == false)
            {
                // KVM Support detected
                console.log('   => KVM Test............................[X11 NOT DETECTED]');
                ret._res();
                return (ret);
            }
        }
    }
    else
    {
        // KVM Support not compiled into agent
        console.log('   => KVM Test............................[NOT SUPPORTED]');
        ret._res();
        return (ret);
    }
    console.log('   => KVM Test');
    ret.tunnel = this.createTunnel(0x1FF, 0xFF);
    ret.tunnel.ret = ret;

    ret.tunnel.then(function (c)
    {
        this.connection = c;
        c.ret = this.ret;
        c.jumbosize = 0;
        c.on('data', function (buf)
        {
            if (typeof (buf) == 'string') { return; }
            var type = buf.readUInt16BE(0);
            var sz = buf.readUInt16BE(2);

            if (type == 27)
            {
                // JUMBO PACKET
                sz = buf.readUInt32BE(4);
                type = buf.readUInt16BE(8);
                console.log('      -> Received JUMBO (' + sz + ' bytes)');              

                if (buf.readUInt16BE(12) != 0)
                {
                    this.ret._rej('      -> JUMBO/RESERVED...................[ERROR]');
                    this.end();
                }
                buf = buf.slice(8);
            }
            
            if(type == 3 && sz == buf.length)
            {
                console.log('      -> Received BITMAP');
                console.log('      -> Result...........................[OK]');
                this.removeAllListeners('data');
                this.end();
                this.ret._res();
            }
        });
        c.on('end', function ()
        {
            this.ret._rej('      -> (Unexpectedly closed)............[FAILED]');
        });

        console.log('      -> Tunnel...........................[CONNECTED]');
        console.log('      -> Triggering User Consent');
        c.write('c');
        c.write('2'); // Request KVM
    }).catch(function (e)
    {
        this.parent._rej('      -> Tunnel...........................[FAILED]');
    });

    return (ret);
}

//
// 1 = root
// 8 = user
// 6 = powershell (root
// 9 = powershell (user)
//
function testTerminal(terminalMode)
{
    console.log('   => Terminal Test');
    if (terminalMode == null) { terminalMode = 1; }
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret.parent = this;
    var consent = 0xFF;

    if (process.platform == 'linux' || process.platform == 'freebsd')
    {
        if (localmode)
        {
            if (!require('monitor-info').kvm_x11_support) { consent = 0x00; }
        }
        else
        {
            var p = this.agentQueryValue("require('monitor-info').kvm_x11_support");
            if (promise.wait(p).toString() != 'true') { consent = 0x00; }
        }
    }

    ret.tunnel = this.createTunnel(0x1FF, consent);
    ret.mode = terminalMode.toString();
    ret.tunnel.parent = ret;
    ret.tunnel.then(function (c)
    {
        this.connection = c;
        c.ret = this.parent;
        c.ret.timeout = setTimeout(function (r)
        {
            r.tunnel.connection.end();
            r._rej('      -> Result...........................[TIMEOUT]');
        }, 7000, c.ret);
        c.tester = this.parent.parent; c.tester.logs = '';
        c.on('data', function _terminalDataHandler(c)
        {
            try
            {
                JSON.parse(c.toString());
            }
            catch(e)
            {
                console.log('      -> Result...........................[OK]');
                this.removeListener('data', _terminalDataHandler);
                if (process.platform == 'win32')
                {
                    this.end('exit\r\n');
                }
                else
                {
                    this.end('exit\n');
                }
                this.ret._res();
                clearTimeout(this.ret.timeout);
            }
        });
        c.on('end', function ()
        {
            this.ret._rej('      -> (Unexpectedly closed)............[FAILED]');
        });

        console.log('      -> Tunnel...........................[CONNECTED]');
        if (consent != 0)
        {
            console.log('      -> Triggering User Consent');
        }
        else
        {
            console.log('      -> Skipping User Consent');
        }
        c.write('c');
        c.write(c.ret.mode);
    }).catch(function (e)
    {
        this.parent._rej('      -> Tunnel...........................[FAILED]');
    });

    return (ret);
}
function testConsoleHelp()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret.consoleTest = this.consoleCommand('help');
    ret.consoleTest.parent = ret;
    ret.consoleTest.then(function (J)
    {
        console.log('   => Testing console command: help.......[OK]');
        this.parent._res();
    }).catch(function (e)
    {
        ret._rej('   => Testing console command: help.......[FAILED]');
    });
    return (ret);
}
function testTunnel()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret.tunneltest = this.createTunnel(0, 0);
    ret.tunneltest.parent = ret;

    ret.tunneltest.then(function (c)
    {
        console.log('   => Tunnel Test.........................[OK]');
        c.end();
        this.parent._res();
    }).catch(function (e)
    {   
        ret._rej('   => Tunnel Test.........................[FAILED] ');
    });

    return (ret);
}

function setup()
{
    this._ObjectID = 'meshore-tester';
    require('events').EventEmitter.call(this, true)
        .createEvent('command')
        .createEvent('tunnel');
    this._tunnelServer = require('http').createServer();
    this._tunnelServer.promises = [];
    this._tunnelServer.listen({ port: 9250 });
    this._tunnelServer.on('upgrade', function (imsg, sck, head)
    {
        var p = this.promises.shift();
        clearTimeout(p.timeout);
        p._res(sck.upgradeWebSocket());
    });
    this.testTunnel = testTunnel;
    this.toServer = function toServer(j)
    {
        //mesh.SendCommand({ action: 'msg', type: 'console', value: text, sessionid: sessionid });
        toServer.self.emit('command', j);
    };
    this.toServer.self = this;
    this.toAgent = function(j)
    {
        if (debugmode) { console.log('toAgent() => ', JSON.stringify(j)); }
        require('MeshAgent').emit('Command', j);
    }
    this.createTunnel = function createTunnel(rights, consent)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.parent = this;
        this._tunnelServer.promises.push(ret);
        ret.timeout = setTimeout(function ()
        {
            ret._rej('timeout');
        }, 2000);
        ret.options = { action: 'msg', type: 'tunnel', rights: rights, consent: consent, username: '(test script)', value: 'ws://127.0.0.1:9250/test' };
        this.toAgent(ret.options);

        return (ret);
    }

    this.agentQueryValue = function agentQueryValue(value)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        //ret._part1 = this.consoleCommand("eval \"var _A=setTimeout(function(){sendConsoleText(require('MeshAgent').serviceName);},1000);\"");

        var cmd = 'eval "var _A=setTimeout(function(){for(i in obj.DAIPC._daipc){ obj.DAIPC._daipc[i]._send({cmd: \'queryResponse\', value: ' + value + '});}},500);"';
        ret.parent = this;
        ret.handler = function handler(j)
        {
            //console.log('handler', JSON.stringify(j));
            if (j.cmd == 'queryResponse')
            {
                clearTimeout(handler.promise.timeout);
                handler.promise.parent.removeListener('command', handler);
                handler.promise._res(j.value);
            }
        };
        ret.handler.promise = ret;
        ret.timeout = setTimeout(function (r)
        {
            r.parent.removeListener('command', r.handler);
            r._rej('QueryTimeout');
        }, 8000, ret);
        this.on('command', ret.handler);
        this.toAgent({ action: 'msg', type: 'console', rights: 0xFFFFFFFF, value: cmd, sessionid: -1 });
        return (ret);
    };

    this.consoleCommand = function consoleCommand(cmd)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.parent = this;
        ret.tester = this;
        ret.handler = function handler(j)
        {
            if((j.action == 'msg' && j.type == 'console') || j.cmd=='console')
            {
                clearTimeout(handler.promise.timeout);
                handler.promise.tester.removeListener('command', handler);
                handler.promise._res(j.value);
            }
        };
        ret.handler.promise = ret;
        ret.timeout = setTimeout(function (r)
        {
            r.tester.removeListener('command', r.handler);
            r._rej('ConsoleCommandTimeout');
        }, 5000, ret);
        this.on('command', ret.handler);
        this.toAgent({ action: 'msg', type: 'console',rights: 0xFFFFFFFF, value: cmd, sessionid: -1 });
        return (ret);
    };

    this.start = start;

    console.log('   -> Setting up Mesh Agent Self Test.....[OK]');
    require('MeshAgent').SendCommand = this.toServer;
    this.consoletext = '';
    this.logs = '';
    this.on('command', function (j)
    {
        switch(j.action)
        {
            case 'msg':
                if (j.type == 'console') { this.consoletext += j.value; }
                break;
            case 'log':
                this.logs += j.msg;
                break;
            case 'getUserImage':
                setImmediate(function (self)
                {
                    j.image = img;
                    self.toAgent(j);
                }, this);
                break;
        }
    });

    this.start();
}

function getRandom(min, max)
{
    var range = max - min;
    var val = Math.random() * range;
    val += min;
    return (Math.floor(val));
}


module.exports = setup;
