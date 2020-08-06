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


var promise = require('promise');

function start()
{
    console.log('\nStarting Self Test...');

    testConsoleHelp()
        .then(function () { return (testAMT()); })
        .then(function () { return (testCPUInfo()); })
        .then(function () { return (testSMBIOS()); })
        .then(function () { return (testTunnel()); })
        .then(function () { return (testTerminal()); })
        .then(function () { return (testKVM()); })
        .then(function () { return (testFileDownload()); })
        .then(function () { console.log('End of Self Test'); })
        .catch(function (v) { console.log(v); });
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
                    this.ret._rej('      -> Tunnel (Download)................[FAILED]');
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

function testSMBIOS()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret.consoleTest = this.consoleCommand('smbios');
    ret.consoleTest.parent = ret;
    ret.consoleTest.then(function (J)
    {
        if (J.length < 30)
        {  
            this.parent._rej('   => Testing SMBIOS......................[EMPTY]');
            return;
        }
        else
        {
            console.log('   => Testing SMBIOS......................[OK]');
        }
        this.parent._res();
    }).catch(function (e)
    {  
        this.parent._rej('   => Testing SMBIOS......................[FAILED]');
    });
    return (ret);
}

function testCPUInfo()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
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
            this.parent._rej('   => Testing CPU Info....................[ERROR]');
            return;
        }
        this.parent._res();
    }).catch(function (e)
    {  
        this.parent._rej('   => Testing CPU Info....................[FAILED]');
    });
    return (ret);
}

function testAMT()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret.consoleTest = this.consoleCommand('amt');
    ret.consoleTest.parent = ret;
    ret.consoleTest.then(function (J)
    {
        if (J.toString().includes('not detected'))
        {
            console.log('   => Testing AMT.........................[NOT DETECTED]');
        }
        else
        {
            try
            {
                JSON.parse(J.toString());
                console.log('   => Testing AMT Detection...............[OK]');
            }
            catch(e)
            {
                this.parent._rej('   => Testing AMT Detection...............[ERROR]');
                return;
            }
        }
        this.parent._res();
    }).catch(function (e)
    {
        this.parent._rej('   => Testing AMT.........................[FAILED]');
    });
    return (ret);
}

function testKVM()
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret.tester = this;

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
    ret.tunnel = this.createTunnel(0x1FF, 0xFF);
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
        c.on('data', function (c)
        {
            try
            {
                JSON.parse(c.toString());
            }
            catch(e)
            {
                console.log('      -> Result...........................[OK]');
                this.end();
                this.ret._res();
                clearTimeout(this.ret.timeout);
            }
        });
        c.on('end', function ()
        {
            this.ret._rej('      -> (Unexpectedly closed)............[FAILED]');
        });
        //          '   => Testing AMT Detection...............[OK]'

        console.log('      -> Tunnel...........................[CONNECTED]');
        console.log('      -> Triggering User Consent');
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
        this.parent._rej('   => Testing console command: help.......[FAILED]');
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
        this.parent._rej('   => Tunnel Test.........................[FAILED] ' + e);
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
        require('MeshAgent').emit('Command', j);
    }
    this.createTunnel = function createTunnel(rights, consent)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.parent = this;
        this._tunnelServer.promises.push(ret);
        ret.timeout = setTimeout(function (r)
        {
            r._tunnelServer.shift();
            r._rej('timeout');
        }, 2000, ret);
        ret.options = { action: 'msg', type: 'tunnel', rights: rights, consent: consent, username: '(test script)', value: 'ws://127.0.0.1:9250/test' };
        this.toAgent(ret.options);

        return (ret);
    }
    this.consoleCommand = function consoleCommand(cmd)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.parent = this;
        ret.tester = this;
        ret.handler = function handler(j)
        {
            if(j.action == 'msg' && j.type == 'console')
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
            r._rej('timeout');
        }, 5000, ret);
        this.on('command', ret.handler);
        this.toAgent({ action: 'msg', type: 'console', value: cmd, sessionid: -1 });
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
        }
    });

    this.start();
}



module.exports = setup;
