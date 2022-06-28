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

try
{
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
}
catch(x)
{ }

var updateSource = [process.execPath];
function getCurrentUpdatePath()
{
    return (updateSource[(1+cycleCount) % updateSource.length]);
}

var Writable = require('stream').Writable;
const MeshCommand_AuthRequest = 1;              // Server web certificate public key sha384 hash + agent or server nonce
const MeshCommand_AuthVerify = 2;               // Agent or server signature
const MeshCommand_AuthInfo = 3;	                // Agent information
const MeshCommand_AuthConfirm = 4;	            // Server confirm to the agent that is it authenticated
const MeshCommand_ServerId = 5;	                // Optional, agent sends the expected serverid to the server. Useful if the server has many server certificates.
const MeshCommand_CoreModule = 10;	            // New core modules to be used instead of the old one, if empty, remove the core module
const MeshCommand_CompressedCoreModule = 20;
const MeshCommand_CoreModuleHash = 11;	        // Request/return the SHA384 hash of the core module
const MeshCommand_AgentCommitDate = 30;	        // Commit Date that the agent was built with
const MeshCommand_AgentHash = 12;	            // Request/return the SHA384 hash of the agent executable
const MeshCommand_AgentUpdate = 13;             // Indicate the start and end of the mesh agent binary transfer
const MeshCommand_AgentUpdateBlock = 14;        // Part of the mesh agent sent from the server to the agent, confirmation/flowcontrol from agent to server
const MeshCommand_AgentTag = 15;	            // Send the mesh agent tag to the server
const MeshCommand_CoreOk = 16;	                // Sent by the server to indicate the meshcore is ok
const MeshCommand_HostInfo = 31;	            // Host OS and CPU Architecture

const PLATFORMS = ['UNKNOWN', 'DESKTOP', 'LAPTOP', 'MOBILE', 'SERVER', 'DISK', 'ROUTER', 'PI', 'VIRTUAL'];
var agentConnectionCount = 0;
var updateState = 0;
var agentBinaryFD = null;
var agentBinary_Size = 0;
var agentBinary_BytesSent = 0;
const recoveryCore = require('fs').readFileSync('recoverycore.js');

var cycleCount = -1;
var targetCount = 1;
var delayMinimum = 0;
var delayMaximum = 100;

process.stdout.write('Generating Certificate...');
var cert = require('tls').generateCertificate('test', { certType: 2, noUsages: 1 });
var server = require('https').createServer({ pfx: cert, passphrase: 'test' });
server.listen({ port: 9250 });

process.stdout.write('\rGenerating Certificate... [DONE]\n');

var loadedCert = require('tls').loadCertificate({ pfx: cert, passphrase: 'test' });
var der = loadedCert.toDER();
global._test = [];

if (process.argv.getParameter('NoInstall') != null)
{
    require('clipboard')(loadedCert.getKeyHash().toString('hex'));
    console.log('Certificate Fingerprint saved to clipboard...');
}

server.on('connection', function (c)
{
    global._test.push(c);
    console.info1('inbound connection received');
});
server.on('request', function (imsg, resp)
{
    if (imsg.method == 'GET' && imsg.url == '/update')
    {
        var accumulator = new Writable(
            {
                write: function write(chunk, flush)
                {
                    this.sent += chunk.length;
                    var pct = Math.floor((this.sent / this.total) * 100);
                    if (pct % 5 == 0)
                    {
                        process.stdout.write('\rPushing Update via HTTPS...[' + pct + '%]');
                    }
                    flush();
                },
                final: function final(flush)
                {
                    process.stdout.write('\n');
                    flush();
                }
            });
        accumulator.sent = 0;

        process.stdout.write('Pushing Update via HTTPS...[0%]');
        var update = require('fs').createReadStream(getCurrentUpdatePath(), { flags: 'rb' });
        accumulator.total = require('fs').statSync(getCurrentUpdatePath()).size;

        update.pipe(resp);
        update.pipe(accumulator);
    }
});
server.on('upgrade', function (msg, sck, head)
{
    console.info1('upgrade requested');
    global._client = sck.upgradeWebSocket();
    global._client.on('data', function (buffer)
    {
        this.processCommand(buffer);
    });
    global._client.on('end', function ()
    {
        if (updateState < 99) { console.log('Agent Disconnected...'); }
    });
    global._client.command = function command(j)
    {
        this.write(JSON.stringify(j));
    }
    global._client.console = function console(str)
    {
        this.command(
            {
                action: 'msg',
                type: 'console',
                value: str,
                sessionid: 'none',
                rights: 4294967295,
                consent: 0
            });
    }
    global._client.processCommand = function processCommand(buffer)
    {
        if (buffer[0] == '{')
        {
            // JSON Command
            this.processJSON(JSON.parse(buffer.toString()));
            return;
        }
        var cmd = buffer.readUInt16BE(0);
        switch(cmd)
        {
            case MeshCommand_AgentCommitDate:    // Agent Commit Date
                console.log("Connected Agent's Commit Date: " + buffer.slice(2).toString());
                break;
            case MeshCommand_HostInfo:
                console.log("Connected Agent Info: " + buffer.slice(2).toString());
                break;
            case MeshCommand_ServerId:
                console.info1("Connected Agent's ServerID: " + buffer.slice(2).toString('hex'));
                break;
            case MeshCommand_AuthRequest:
                //typedef struct MeshCommand_BinaryPacket_AuthRequest
                //{
                //    unsigned short command;
                //    char serverHash[UTIL_SHA384_HASHSIZE];
                //    char serverNonce[UTIL_SHA384_HASHSIZE];
                //}MeshCommand_BinaryPacket_AuthRequest;
                var serverHash = buffer.slice(2, 50).toString('hex');
                this.agentNonce = Buffer.alloc(48);
                buffer.slice(50, 98).copy(this.agentNonce);

                console.info1('Agent Sent Nonce: ' + this.agentNonce.toString('hex'));
                console.info1('Agent Sent ServerID: ' + serverHash);

                this.serverNonce = Buffer.alloc(48);
                this.serverNonce.randomFill();

                var authBuffer = Buffer.alloc(98);
                authBuffer.writeUInt16BE(1);                    // AuthRequest
                loadedCert.getKeyHash().copy(authBuffer, 2);    // ServerHash
                this.serverNonce.copy(authBuffer, 50);          // ServerNonce
                this.write(authBuffer);

                break;
            case MeshCommand_AuthVerify:
                console.info1('AUTH-VERIFY');

                var hash = require('SHA384Stream').create();
                hash.on('hash', function (h)
                {
                    this._hashedValue = Buffer.alloc(h.length);
                    h.copy(this._hashedValue);
                });
                var y = Buffer.from(cert.digest.split(':').join(''), 'hex');
                hash.write(y); // ServerHash
                hash.write(this.agentNonce);
                hash.write(this.serverNonce);
                hash.end();


                console.info1('SERVER/SIGN => ' + y.toString('hex'), y.length);
                console.info1('SERVER/SIGN/AgentNonce => ' + this.agentNonce.toString('hex'), this.agentNonce.length);
                console.info1('SERVER/SIGN/ServerNonce => ' + this.serverNonce.toString('hex'), this.serverNonce.length);
                console.info1('SERVER/SIGN/RESULT => ' + hash._hashedValue.toString('hex'));

                var RSA = require('RSA');
                var signature = RSA.sign(RSA.TYPES.SHA384, loadedCert, hash._hashedValue);
                var verifyBuffer = Buffer.alloc(4 + der.length + signature.length);
                verifyBuffer.writeUInt16BE(2);              // AUTH-VERIFY
                verifyBuffer.writeUInt16BE(der.length, 2);  // CERT-LEN
                der.copy(verifyBuffer, 4);                  // CERT
                signature.copy(verifyBuffer, 4 + der.length);

                this.write(verifyBuffer);
                break;
            case MeshCommand_AuthInfo:
                //typedef struct MeshCommand_BinaryPacket_AuthInfo
                //{
                //    unsigned short command;
                //    unsigned int infoVersion;
                //    unsigned int agentId;
                //    unsigned int agentVersion;
                //    unsigned int platformType;
                //    char MeshID[UTIL_SHA384_HASHSIZE];
                //    unsigned int capabilities;
                //    unsigned short hostnameLen;
                //    char hostname[];
                //}MeshCommand_BinaryPacket_AuthInfo;

                var agentID = buffer.readUInt32BE(6);
                var platformType = buffer.readUInt32BE(14);
                var hostname = buffer.slice(72);

                console.log('AgentID: ' + getSystemName(agentID));
                try
                {
                    console.log('PlaformType: ' + PLATFORMS[platformType]);
                }
                catch(zz)
                {
                }
                console.log('Hostname: ' + hostname);

                // Send AuthConfirm
                var b = Buffer.alloc(4);
                b.writeUInt16BE(MeshCommand_AuthConfirm);
                b.writeUInt16BE(1, 2);
                this.write(b);

                // Ask for Agent Hash
                var b = Buffer.alloc(4);
                b.writeUInt16BE(MeshCommand_AgentHash);
                b.writeUInt16BE(1, 2);
                this.write(b);

                // Ask for Module Hash
                var b = Buffer.alloc(4);
                b.writeUInt16BE(MeshCommand_CoreModuleHash);
                b.writeUInt16BE(1, 2);
                this.write(b);             
                break;
            case MeshCommand_AgentTag:
                console.log('AgentTag: ' + buffer.slice(4));
                break;
            case MeshCommand_AgentHash:
                var hash = buffer.slice(4).toString('hex');
                console.log('AgentHash=' + hash);
                console.log('');
                console.log('==> CycleCount: ' + (++cycleCount) + ' of ' + targetCount);
                console.log('');

                if (cycleCount < targetCount)
                {
                    // Need to do another round of updates
                    updateState = 0;

                    var delay = Math.floor((Math.random() * delayMaximum) + delayMinimum);
                    console.log('==> Performing Update to: (' + getCurrentUpdatePath() + ') ' + '[' + getSHA384FileHash(getCurrentUpdatePath()).toString('hex').substring(0,8) + '] in: ' + delay + 'ms');
                    global._delay = setTimeout(function ()
                    {
                        if (process.argv.getParameter('JS') === '1')
                        {
                            // Recovery Core Update Path
                            switch (updateState)
                            {
                                case 0:
                                    console.log('Pushing Recovery Core');
                                    updateState = 1;
                                    var b = Buffer.alloc(recoveryCore.length + 48 + 4 + 4);
                                    b.writeUInt16BE(MeshCommand_CoreModule);
                                    b.writeUInt16BE(1, 2);
                                    recoveryCore.copy(b, 56);
                                    require('SHA384Stream').create().syncHash(b.slice(52)).copy(b, 4);
                                    this.write(b);
                                    break;
                                case 1:
                                    updateState = 2;
                                    var b = Buffer.alloc(4);
                                    b.writeUInt16BE(MeshCommand_CoreOk);
                                    b.writeUInt16BE(1, 2);
                                    this.write(b);

                                    this.command({ url: 'https://127.0.0.1:9250/update', action: 'agentupdate', hash: getSHA384FileHash(getCurrentUpdatePath()).toString('hex'), sessionid: 'none' });
                                    break;
                                default:
                                    console.log('Agent Update State: ' + updateState);
                                    break;
                            }
                        }
                        else
                        {
                            // Native Update Path
                            switch(updateState)
                            {
                                case 0:
                                    updateState = 1;
                                    agentBinaryFD = require('fs').openSync(getCurrentUpdatePath(), 'rb');
                                    agentBinary_Size = require('fs').statSync(getCurrentUpdatePath()).size;
                                    process.stdout.write('Sending update to Agent (' + getCurrentUpdatePath() + ')... [0%]');

                                    var b = Buffer.alloc(4);
                                    b.writeUInt16BE(MeshCommand_AgentUpdate);
                                    b.writeUInt16BE(1, 2);
                                    this.write(b);

                                    b = Buffer.alloc(16388);
                                    b.writeUInt16BE(MeshCommand_AgentUpdateBlock);
                                    b.writeUInt16BE(1, 2);              
                                    agentBinary_BytesSent = require('fs').readSync(agentBinaryFD, b, 4, 16384, -1);
                                    this.write(b);
                                    break;
                            }
                        }

                    }.bind(this), delay);
                }
                else
                {
                    updateState = 99;
                    console.log('==> End of Test');
                    var params = ['--meshServiceName=TestAgent'];
                    var paramsString = JSON.stringify(params);

                    require('agent-installer').fullUninstall(paramsString);
                    console.setDestination(console.Destinations.STDOUT);
                }

                break;
            case MeshCommand_CoreModuleHash:
                var hash = buffer.slice(4).toString('hex');
                if (updateState < 99) { console.log('CoreModuleHash[' + hash.length + ']=' + hash); }
                if (process.argv.getParameter('NoInstall') == null && updateState<99)
                {
                    console.log('Service PID: ' + getPID());
                }

                if (process.argv.getParameter('JS') === '1')
                {
                    switch (updateState)
                    {
                        case 1:
                            updateState = 2;
                            var b = Buffer.alloc(4);
                            b.writeUInt16BE(MeshCommand_CoreOk);
                            b.writeUInt16BE(1, 2);
                            this.write(b);
                            this.command({ url: 'https://127.0.0.1:9250/update', action: 'agentupdate', hash: getSHA384FileHash(getCurrentUpdatePath()).toString('hex'), sessionid: 'none' });
                            break;
                        case 99:
                            // No-Op because we are done
                            break;
                        default:
                            console.log('Agent Update State: ' + updateState);
                            break;
                    }
                    break;
                }
                break;
            case MeshCommand_AgentUpdateBlock:
                if (agentBinary_BytesSent < agentBinary_Size)
                {
                    var pct = Math.floor((agentBinary_BytesSent / agentBinary_Size) * 100);
                    if (pct % 5 == 0)
                    {
                        process.stdout.write('\rSending update to Agent (' + getCurrentUpdatePath() + ')... [' + pct + '%]');
                    }

                    var b = Buffer.alloc(4100);
                    var r;
                    b.writeUInt16BE(MeshCommand_AgentUpdateBlock);
                    b.writeUInt16BE(1, 2);
                    agentBinary_BytesSent += (r = require('fs').readSync(agentBinaryFD, b, 4, 4096, -1));
                    this.write(b.slice(0,r+4));
                }
                else
                {
                    process.stdout.write('\rSending update to Agent (' + getCurrentUpdatePath() + ')... [100%]\n');
                    var b = Buffer.alloc(52);
                    b.writeUInt16BE(MeshCommand_AgentUpdate);
                    b.writeUInt16BE(1, 2);
                    getSHA384FileHash(getCurrentUpdatePath()).copy(b, 4);
                    this.write(b);
                }
                break;
            default:
                console.log('Command: ' + cmd);
                break;
        }
    };
    global._client.processJSON = function processJSON(j)
    {
        switch(j.action)
        {
            case 'agentupdatedownloaded':
                console.log('Agent reports successfully downloaded update');
                break;
            case 'coreinfo':
                console.log('');
                console.log('Agent is running core: ' + j.value);
                console.log('');
                break;
            case 'msg':
                if (j.type == 'console')
                {
                    console.log('Agent: ' + j.value);
                }
                break;
            case 'sessions':
                break;
            default:
                console.log(JSON.stringify(j, null, 1));
                break;
        }
    }
});
function getSystemName(id)
{
    var ret = 'unknown';
    switch(id)
    {
        default:
            ret = 'ARCHID=' + id;
            break;
        case 1:
            ret = 'Windows Console 32 bit';
            break;
        case 2:
            ret = 'Windows Console 64 bit';
            break;
        case 3:
            ret = 'Windows Service 32 bit';
            break;
        case 4:
            ret = 'Windows Service 64 bit';
            break;
        case 16:
            ret = 'macOS Intel Silicon 64 bit';
            break;
        case 29:
            ret = 'macOS Apple Silicon 64 bit';
            break;
        case 5:
            ret = 'Linux x86 32 bit';
            break;
        case 6:
            ret = 'Linux x86 64 bit';
            break;
        case 7:
            ret = 'Linux MIPSEL';
            break;
        case 9:
            ret = 'Linux ARM 32 bit';
            break;
        case 13:
            ret = 'Linux ARM 32 bit PogoPlug';
            break;
        case 15:
            ret = 'Linux x86 32 bit POKY';
            break;
        case 18:
            ret = 'Linux x86 64 bit POKY';
            break;
        case 19:
            ret = 'Linux x86 32 bit NOKVM';
            break;
        case 20:
            ret = 'Linux x86 64 bit NOKVM';
            break;
        case 24:
            ret = 'Linux ARM/HF 32 bit (Linaro)';
            break;
        case 26:
            ret = 'Linux ARM 64 bit';
            break;
        case 32:
            ret = 'Linux ARM 64 bit (glibc/2.24)';
            break;
        case 27:
            ret = 'Linux ARM/HF 32 bit NOKVM';
            break;
        case 30:
            ret = 'FreeBSD x86 64 bit';
            break;
        case 31:
            ret = 'FreeBSD x86 32 bit';
            break;
        case 37:
            ret = 'OpenBSD x86 64 bit';
            break;
        case 33:
            ret = 'Alpine Linux x86 64 bit (MUSL)';
            break;
        case 25:
            ret = 'Linux ARM/HF 32 bit';
            break;
        case 28:
            ret = 'Linux MIPS24KC/MUSL (OpenWRT)';
            break;
        case 36:
            ret = 'Linux x86/MUSL 64 bit (OpenWRT)';
            break;
        case 40:
            ret = 'Linux MIPSEL24KC/MUSL (OpenWRT)';
            break;
        case 41:
            ret = 'Linux ARMADA/CORTEX-A53/MUSL (OpenWRT)';
            break;
        case 35:
            ret = 'Linux ARMADA370/HF';
            break;
    }
    return (ret);
}

function getPID()
{
    var s = require('service-manager').manager.getService('TestAgent');
    var ret = 0;
    switch(process.platform)
    {
        case 'win32':
            ret = s.status.pid;
            s.close();
            break;
        default:
            ret = 0;
            break;
    }

    return (ret);
}


if (process.argv.getParameter('CycleCount') != null)
{
    try
    {
        targetCount = parseInt(process.argv.getParameter('CycleCount'));
    }
    catch(e)
    {}
}
if (process.argv.getParameter('MinimumDelay') != null)
{
    try
    {
        delayMinimum = parseInt(process.argv.getParameter('MinimumDelay'));
    }
    catch (e)
    { }
}
if (process.argv.getParameter('MaximumDelay') != null)
{
    try
    {
        delayMaximum = parseInt(process.argv.getParameter('MaximumDelay'));
    }
    catch (e)
    { }
}
if (process.argv.getParameter('AltBinary') != null)
{
    var alt = process.argv.getParameter('AltBinary');
    if(require('fs').existsSync(alt))
    {
        updateSource.push(alt);
    }
}

if (process.argv.getParameter('NoInstall') == null)
{
    //
    // Start by installing agent as service
    //
    var params = ['--__skipExit=1', '--logUpdate=1', '--MeshID=0x43FEF862BF941B2BBE5964CC7CA02573BBFB94D5A717C5AA3FC103558347D0BE26840ACBD30FFF981F7F5A2083D0DABC', '--MeshServer=wss://127.0.0.1:9250/agent.ashx', '--meshServiceName=TestAgent', '--ServerID=' + loadedCert.getKeyHash().toString('hex')];
    var paramsString = JSON.stringify(params);

    require('agent-installer').fullInstall(paramsString);
    console.setDestination(console.Destinations.STDOUT);
}
console.log('\nWaiting for Agent Connection...');


