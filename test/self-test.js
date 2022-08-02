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

_MSH = function _MSH() { return ({}); };
var img = 'image/jpeg,base64,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';
process.coreDumpLocation = process.platform == 'win32' ? (process.execPath.replace('.exe', '.dmp')) : (process.execPath + '.dmp');

var updateSource = null;
var promise = require('promise');

if (process.platform == 'win32') { global.kernel32 = require('_GenericMarshal').CreateNativeProxy('kernel32.dll'); global.kernel32.CreateMethod('GetCurrentProcess'); global.kernel32.CreateMethod('GetProcessHandleCount'); }

function getHandleCount()
{
    var ret = 0;
    switch(process.platform)
    {
        case 'win32':
            var h = kernel32.GetCurrentProcess();
            var c = require('_GenericMarshal').CreateVariable(4);
            kernel32.GetProcessHandleCount(h, c);
            ret = c.toBuffer().readUInt32LE();
            break;
        default:
            break;
    }
    return (ret);
}

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
                    else if (this[i] == name)
                    {
                        ret = this[i];
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
catch (x)
{ }

var Writable = require('stream').Writable;
var meshcore = null;
var TunnelPromises = [];

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

const MNG_KVM_PICTURE = 3;
const MNG_KVM_SCREEN = 7;
const MNG_KVM_GET_DISPLAYS = 11;
const MNG_KVM_SET_DISPLAY = 12;
const MNG_KVM_KEYSTATE = 18;
const MNG_JUMBO = 27;
const MNG_KVM_DISPLAY_INFO = 82;
const MNG_KVM_MOUSE_CURSOR = 88;


const PLATFORMS = ['UNKNOWN', 'DESKTOP', 'LAPTOP', 'MOBILE', 'SERVER', 'DISK', 'ROUTER', 'PI', 'VIRTUAL'];
var agentConnectionCount = 0;
var updateState = 0;
const consoleMode = process.argv.getParameter('console') != null;

var digest_realm;
var digest_username;
var digest_password;
var remoteDebug = 0;
var localDebug = 0;
var testTimeout = 10;
var agentmsg = process.argv.getParameter('msg') != null;

if (process.argv.getParameter('Timeout') != null)
{
    try
    {
        testTimeout = parseInt(process.argv.getParameter('Timeout'));
    }
    catch(x)
    {
    }
    if(isNaN(testTimeout))
    {
        console.log('Invalid timeout specified: ' + process.argv.getParameter('Timeout'));
        process.exit();
    }
}

// Check Permissions... Need Root/Elevated Permissions
if (!require('user-sessions').isRoot())
{
    console.log('self-test.js requires elevated permissions to run.');
    process.exit();
}
if (process.argv.getParameter('AltBinary') != null)
{
    var alt = process.argv.getParameter('AltBinary');
    if (require('fs').existsSync(alt))
    {
        updateSource = alt;
    }
}

if (process.argv.getParameter('help') != null)
{
    console.log("\nself-test is a Self-Contained test harnass for testing the MeshAgent and MeshCore functions");
    console.log('\n   Available options:');
    console.log('   --AgentsFolder=         The path to the agents folder of the Server Repository');
    console.log('   --AMT                   If specified, individually runs the AMT tests');
    console.log('   --CLIP                  If specified, individually runs the clipboard test');
    console.log('   --console               If specified, enables console command mode');
    console.log('   --Delay                 If specified, will prompt the user to hit enter before starting unit tests');
    console.log('   --Digest                If specified, individually runs the HTTP Digest tests.');
    console.log('   --FileTransfer          If specified, individually runs the FileTransfer Unit Test');
    console.log('   --KVM                   If specified, individually runs the KVM tests');
    console.log('   --LocalDebug            Specifies a port number for the Local Web Debug Interface');
    console.log('   --PrivacyBar            If specified, causes the agent to spawn a privacy bar');
    console.log("   --RemoteDebug           Specifies a port number for the Agent's Web Debug Interface");
    console.log('   --Terminal              If specified, individually runs the Terminal tests');
    console.log('   --Timeout               Specifies a timeout in seconds for the unit tests. Default is 10 seconds');
    console.log('   --WebRTC                If specified, individually runs the WebRTC Unit Test');
    console.log('   --verbose=              Specifies the verbosity level of the displayed output. Default = 0');
    console.log('');
    process.exit();
}
if (process.argv.getParameter('AgentsFolder') == null)
{
    console.log('\nRequired parameter: AgentsFolder,  was not specified.');
    process.exit();
}
else
{
    if(!require('fs').existsSync(process.argv.getParameter('AgentsFolder')))
    {
        console.log('\nThe specified folder does not exist: ' + process.argv.getParameter('AgentsFolder'));
        process.exit();
    }
}
if (process.argv.getParameter('LocalDebug') != null)
{
    try
    {
        localDebug = parseInt(process.argv.getParameter('LocalDebug'));
    }
    catch(z)
    {
        console.log('Invalid Parameter specified for LocalDebug');
        process.exit();
    }
}
if (process.argv.getParameter('RemoteDebug') != null)
{
    try
    {
        remoteDebug = parseInt(process.argv.getParameter('RemoteDebug'));
    }
    catch (z)
    {
        console.log('Invalid Parameter specified for RemoteDebug');
        process.exit();
    }
}

var promises =
    {
        amt: null,
        conpty: null,
        delay: null,
        coreinfo: null,
        CommitInfo: null,
        AgentInfo: null,
        netinfo: null,
        smbios: null,
        cpuinfo: null,
        ps: null,
        help: null,
        services: null,
        setclip: null,
        getclip: null,
        digest: null,
        digest_auth: null,
        digest_authint: null,
        webrtc_test: null,
        webrtc_offer: null,
        webrtc_hash: null,
        filetransfer: null,
        terminal: null,
        kvm: null,
        smbios_check: null,
        fs_1: null,
        fs_2: null,
        fs_3: null
    };

function generateRandomNumber(lower, upper)
{
    return (Math.floor(Math.random() * (upper - lower)) + lower);
}
function generateRandomLetter()
{
    return (String.fromCharCode(generateRandomNumber(97, 122)));
}
function generateRandomString(len)
{
    var ret = '', i;
    for (i = 0; i < len; ++i)
    {
        ret += generateRandomLetter();
    }
    return (ret);
}
function generateRandomRealm()
{
    realm = generateRandomString(generateRandomNumber(1, 5)) + '.' + generateRandomString(generateRandomNumber(8, 20)) + '.com';
    return (realm);
}
function resetPromises()
{
    var i;
    for(i in promises)
    {
        promises[i] = new promise(promise.defaultInit);
    }
}
function addTimeout(prom)
{
    prom.timeout = setTimeout(function (p) { p.reject('Timeout'); }, testTimeout * 1000, prom);
}

if (localDebug > 0)
{
    process.stdout.write('Local WebDebug Listening on port: ' + localDebug + '\n');
    console.enableWebLog(localDebug);
}
if (remoteDebug > 0)
{
    process.stdout.write('Remote WebDebug will listen on port: ' + remoteDebug + '\n');
}

process.stdout.write('Generating Certificate...');
var cert = require('tls').generateCertificate('test', { certType: 2, noUsages: 1 });
var server = require('https').createServer({ pfx: cert, passphrase: 'test' });
server.listen();

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
server.on('request', function (imsg, rsp)
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

        update.pipe(rsp);
        update.pipe(accumulator);
    }
    if (imsg.method == 'POST')
    {
        var username, qop;
        if (imsg.Digest_IsAuthenticated(digest_realm))
        {
            username = imsg.Digest_GetUsername();
            qop = imsg.Digest_GetQOP();

            imsg.on('end', function ()
            {
                switch (imsg.url)
                {
                    case '/auth':
                        if (qop != 'auth') { promises.digest_auth.reject('Received Incorrect QOP: ' + qop); }
                        break;
                    case '/auth-int':
                        if (qop != 'auth-int') { promises.digest_authint.reject('Received Incorrect QOP: ' + qop); }
                        break;
                }
                if (imsg.Digest_ValidatePassword(digest_password))
                {
                    rsp.statusCode = 200;
                    rsp.setHeader('Content-Type', 'text/html');
                    rsp.end('<html>Success!</html>');
                }
                else
                {
                    rsp.Digest_writeUnauthorized(digest_realm);
                }
            });
        }
        else
        {
            imsg.on('end', function ()
            {
                switch (imsg.url)
                {
                    case '/':
                        rsp.Digest_writeUnauthorized(digest_realm);
                        break;
                    case '/auth':
                        rsp.Digest_writeUnauthorized(digest_realm, { qop: 'auth' });
                        break;
                    case '/auth-int':
                        rsp.Digest_writeUnauthorized(digest_realm, { qop: 'auth-int, auth' });
                        break;
                }
            });
        }
    }
});
server.on('upgrade', function (msg, sck, head)
{
    console.info1('upgrade requested');

    switch(msg.url)
    {
        case '/tunnel':
            var p = TunnelPromises.shift();
            clearTimeout(p.timeout);
            p.resolve(sck.upgradeWebSocket());
            return;
            break;
        case '/agent.ashx': // No-Op, because we'll continue processing after the switch statement
            break;
        default:
            return;         // We will not handle other requests
            break;
    }


    resetPromises();
    global._client = sck.upgradeWebSocket();
    require('events').EventEmitter.call(global._client, true)
        .createEvent('JSONCommand');

    global._client.on('data', function (buffer)
    {
        this.processCommand(buffer);
    });
    global._client.on('end', function ()
    {
        console.log('Agent Disconnected...');
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
        if (buffer[0] == '{' || buffer[0] == 123)
        {
            // JSON Command
            jcmd = JSON.parse(buffer.toString());
            this.emit('JSONCommand', jcmd);
            return;
        }

        var cmd = buffer.readUInt16BE(0);
        switch(cmd)
        {
            case MeshCommand_AgentCommitDate:    // Agent Commit Date
                promises.CommitInfo.resolve(buffer.slice(2).toString());
                console.log("Connected Agent's Commit Date: " + buffer.slice(2).toString());
                break;
            case MeshCommand_HostInfo:
                promises.AgentInfo.resolve(buffer.slice(2).toString());
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

                console.info2('Agent Sent Nonce: ' + this.agentNonce.toString('hex'));
                console.info2('Agent Sent ServerID: ' + serverHash);

                this.serverNonce = Buffer.alloc(48);
                this.serverNonce.randomFill();

                var authBuffer = Buffer.alloc(98);
                authBuffer.writeUInt16BE(1);                    // AuthRequest
                loadedCert.getKeyHash().copy(authBuffer, 2);    // ServerHash
                this.serverNonce.copy(authBuffer, 50);          // ServerNonce
                this.write(authBuffer);

                break;
            case MeshCommand_AuthVerify:
                console.info2('AUTH-VERIFY');

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


                console.info2('SERVER/SIGN => ' + y.toString('hex'), y.length);
                console.info2('SERVER/SIGN/AgentNonce => ' + this.agentNonce.toString('hex'), this.agentNonce.length);
                console.info2('SERVER/SIGN/ServerNonce => ' + this.serverNonce.toString('hex'), this.serverNonce.length);
                console.info2('SERVER/SIGN/RESULT => ' + hash._hashedValue.toString('hex'));

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
                console.info1('AgentHash=' + hash);
                console.info1('');
                break;
            case MeshCommand_CoreModuleHash:
                var hash = buffer.slice(4).toString('hex');
                console.info1('CoreModuleHash[' + hash.length + ']=' + hash);

                if (updateState == 0)
                {
                    updateState = 1;
                    var mc = Buffer.from(meshcore);
                    var targetHash = require('SHA384Stream').create();

                    var b = Buffer.alloc(mc.length + 48 + 4 + 4);
                    b.writeUInt16BE(MeshCommand_CoreModule);
                    b.writeUInt16BE(1, 2);
                    mc.copy(b, 56);
                    targetHash.syncHash(b.slice(52)).copy(b, 4);
                    console.info1('TargetHash[' + b.slice(4, 52).toString('hex') + ']');

                    if (hash == b.slice(4, 52).toString('hex'))
                    {
                        // Mesh Core OK
                        var b = Buffer.alloc(4);
                        b.writeUInt16BE(MeshCommand_CoreOk);
                        b.writeUInt16BE(1, 2);
                        this.write(b);

                        this.runCommands();
                    }
                    else
                    {
                        this.write(b);
                    }
                    break;
                }

                if (process.argv.getParameter('NoInstall') == null)
                {
                    console.log('Service PID: ' + getPID());
                }
                this.runCommands();
                break;
            case MeshCommand_AuthConfirm:
                console.log('Agent Authenticated');
                break;
            default:
                console.log('Command: ' + cmd);
                break;
        }
    };
    global._client.processJSON = function processJSON(j)
    {
        console.info2(JSON.stringify(j, null, 1));

        switch(j.action)
        {
            case 'agentupdatedownloaded':
                console.log('Agent reports successfully downloaded update');
                break;
            case 'coreinfo':
                promises.coreinfo.resolve('Agent is running core: ' + j.value);
                break;
            case 'getUserImage':
                j.image = img;
                global._client.command(j);
                break;
            case 'msg':
                switch(j.type)
                {
                    case 'console':
                        if (j.value != 'Command returned an exception error: TypeError: cyclic input')
                        {
                            if (j.sessionid == null || process.argv.getParameter('verbose') != null || consoleMode || agentmsg)
                            {
                                console.log('Agent: ' + j.value);
                            }
                        }
                        if (j.value == "PrivacyBarClosed") { endTest(); }
                        if (j.value.startsWith('Available commands:')) { promises.help.resolve(j.value); }
                        break;
                    case 'cpuinfo':
                        promises.cpuinfo.resolve(j);
                        break;
                    case 'ps':
                        promises.ps.resolve(j);
                        break;
                    case 'services':
                        promises.services.resolve(j);
                        break;
                    case 'setclip':
                        promises.setclip.resolve(j);
                        break;
                    case 'getclip':
                        promises.getclip.resolve(j);
                        break;
                }
                break;
            case 'sessions':
                break;
            case 'netinfo':
                console.info1(j.action, JSON.stringify(j, null, 1));
                promises.netinfo.resolve(j);
                break;
            case 'smbios':
                console.info1(j.action, JSON.stringify(j, null, 1));
                promises.smbios.resolve(j);
                break;
            case 'result':
                console.info1(JSON.stringify(j, null, 1));

                if (promises[j.id] != null)
                {
                    if (promises[j.id].timeout != null)
                    {
                        clearTimeout(promises[j.id].timeout);
                    }
                    if (j.result===true)
                    {
                        promises[j.id].resolve(j);
                    }
                    else
                    {
                        promises[j.id].reject(j.reason == null ? '' : j.reason);
                    }
                }
                break;
            default:
                console.info1(j.action, JSON.stringify(j, null, 1));
                break;
        }
    }
    global._client.on('JSONCommand', global._client.processJSON);

    global._client.runCommands = function runCommands()
    {
        if (process.argv.getParameter('PrivacyBar') != null)
        {
            this.command({  sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'console', value: 'eval "global._n=require(\'notifybar-desktop\')(\'Self Test Privacy Bar\', require(\'MeshAgent\')._tsid);global._n.on(\'close\', function (){sendConsoleText(\'PrivacyBarClosed\');});"' });
            return;
        }
        if(consoleMode)
        {
            console.log("\nEntering CONSOLE mode. Type 'exit' when done.");
            this.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'console', value: 'help' });
            process.stdin.on('data', function (c)
            {
                if (c == null || c.toString() == null) { return; }
                if (c.toString().toLowerCase().trim() == 'exit')
                {
                    console.log('EXITING console mode');
                    endTest();
                }
                else
                {
                    global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'console', value: c.toString().trim() });
                }
            });
            return;
        }

        if (process.argv.getParameter('Delay') != null)
        {
            process.stdout.write('\nPress any key to start running Mesh Core Unit Tests\n');
            console.canonical = false;  // This takes the console out of canonical mode, which means stdin will process each key press individually, instead of by line.
            process.stdin.once('data', function ()
            {
                console.canonical = true;
                promises.delay.resolve();
            });
        }
        else
        {
            promises.delay.resolve();
        }
    };

    promises.delay.then(function runCommands2()
    {
        console.log('\nRunning Meshcore Tests [Timeout = ' + testTimeout + ' seconds]:');

        if (process.argv.getParameter('WebRTC') != null)
        {
            WebRTC_Test().finally(function () { endTest(); });
            return;
        }
        if (process.argv.getParameter('FileTransfer') != null)
        {
            FileTransfer_Test().finally(function () { endTest(); });
            return;
        }

        if (process.argv.getParameter('Digest') != null)
        {
            Digest_Test().finally(function () { endTest(); });
            return;
        }
        if (process.argv.getParameter('Terminal') != null)
        {
            Terminal_Test().finally(function () { endTest(); });
            return;
        }
        if (process.argv.getParameter('KVM') != null)
        {
            KVM_Test().finally(function () { endTest(); });
            return;
        }
        if (process.argv.getParameter('AMT') != null)
        {
            AMT_Detection().finally(function () { endTest(); });
            return;
        }
        if (process.argv.getParameter('CLIP') != null)
        {
            Clipboard_Test().finally(function () { endTest(); });
            return;
        }
        if (process.argv.getParameter('SMBIOS') != null)
        {
            SMBIOS_Test().finally(function () { endTest(); });
            return;
        }
        if (process.argv.getParameter('MODULES') != null)
        {
            MODULES_Test().finally(function () { endTest(); });
            return;
        }

        //
        // Run thru the main tests, becuase no special options were sent
        //
        if (console.getInfoLevel() == 0) { console.setDestination(console.Destinations.DISABLED); }

        process.stdout.write('   Agent sent version information to server................');

        promises.CommitInfo.then(function ()
        {
            process.stdout.write('[OK]\n');
            process.stdout.write('   Agent sent AgentInfo to server..........................');
            return (promises.AgentInfo);
        }).then(function ()
        {
            process.stdout.write('[OK]\n');
            process.stdout.write('   Agent sent Network Info to server.......................[WAITING]');
            return (promises.netinfo);
        }).then(function ()
        {
            process.stdout.write('\r');
            process.stdout.write('   Agent sent Network Info to server.......................[OK]      \n');
        }).then(function ()
        {
            return(SMBIOS_Test());
        }).then(function ()
        {
            process.stdout.write('   Agent sent CoreInfo to server...........................[WAITING]');
            return (promises.coreinfo);
        }).then(function (v)
        {
            process.stdout.write('\r   Agent sent CoreInfo to server...........................[OK]     \n');
            process.stdout.write('      => ' + v + '\n');
        }).then(function ()
        {
            return (AMT_Detection());
        }).then(function ()
        {
            process.stdout.write('   Tunnel Test.............................................[WAITING]');
            return (createTunnel(0, 0));
        }).then(function (t)
        {
            process.stdout.write('\r   Tunnel Test.............................................[OK]      \n');
            t.end();
        }).then(function ()
        {
            addTimeout(promises.help);
            global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'console', value: 'help' });
            process.stdout.write('   Console Test (Help).....................................[WAITING]');
            return (promises.help);
        }).then(function (v)
        {
            process.stdout.write('\r   Console Test (Help).....................................[OK]      \n');
            if (process.platform == 'freebsd')
            {
                process.stdout.write('   CPUINFO Test............................................[NA]\n');
                return;
            }
            process.stdout.write('   CPUINFO Test............................................[WAITING]');
            addTimeout(promises.cpuinfo);
            global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'cpuinfo' });
            return (promises.cpuinfo);
        }).then(function (v)
        {
            process.stdout.write('\r   CPUINFO Test............................................[OK]      \n');
            process.stdout.write('   PS Test.................................................[WAITING]');
            addTimeout(promises.ps);
            global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'ps' });
            return (promises.ps);
        }).then(function (v)
        {
            var p;
            try
            {
                p = JSON.parse(v.value);
            }
            catch (e)
            {
                process.stdout.write('\r   PS Test.................................................[FAILED]      \n');
                process.stdout.write('   => ' + e + '\n');
                return;
            }
            process.stdout.write('\r   PS Test.................................................[OK]      \n');
            process.stdout.write('      => ' + p.keys().length + ' processes retrieved.\n');

            process.stdout.write('   Service Enumeration Test................................[WAITING]');
            addTimeout(promises.services);
            global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'services' });
            return (promises.services);
        }).then(function (v)
        {
            var services;
            try
            {
                services = JSON.parse(v.value);
            }
            catch (x)
            {
                process.stdout.write('\r   Service Enumeration Test................................[INVALID JSON]\n');
                process.stdout.write('      => ' + x + '\n');
                return;
            }
            process.stdout.write('\r   Service Enumeration Test................................[OK]      \n');
            process.stdout.write('\r      => ' + services.length + ' services retrieved.\n');
        }).then(function ()
        {
            return (Clipboard_Test());
        }).then(function ()
        {
            return (Digest_Test());
        }).then(function ()
        {
            return (WebRTC_Test());
        }).then(function ()
        {
            return (FileTransfer_Test());
        }).then(function ()
        {
            return (Terminal_Test());
        }).then(function ()
        {
            return (KVM_Test());
        }).then(function ()
        {
            process.stdout.write('\nTesting Complete\n\n');
            endTest();
        }).catch(function (e)
        {
            process.stdout.write('\nTesting Failed (' + e + ')\n\n');
            endTest();
        });

    });
});

function MODULES_Test()
{
    var ret;

    ret = fs_test();

    return (ret);
}

function fs_test()
{
    var ret = new promise(promise.defaultInit);

    process.stdout.write('   Module Tests:\n');
    process.stdout.write('      File System Tests\n');
    process.stdout.write('         fs.readFileSync().................................[WAITING]');

    sendEval("global._fsh1=getHandleCount();");
    sendEval("var test1 = require('fs').readFileSync(process.execPath);");
    sendEval("global._fsh2=getHandleCount();");
    sendEval("selfTestResponse('fs_1', true, {pre: global._fsh1, post: global._fsh2});");

    promises.fs_1.then(function (r)
    {
        process.stdout.write('\r         fs.readFileSync().................................[OK]     \n');
        process.stdout.write('            => Handle Counts (Pre/Post): ' + r.reason.pre + '/' + r.reason.post + '\n');
    }).then(function ()
    {
        var tmp = generateRandomString(5);
        process.stdout.write('         fs.writeFileSync()................................[WAITING]');
        sendEval("var testh=getHandleCount();");
        sendEval("var testname='" + tmp + "';");
        sendEval("var testvalue=Buffer.alloc(" + generateRandomNumber(1024, 4096) + ");");
        sendEval("testvalue.randomFill();");
        sendEval("require('fs').writeFileSync(testname, testvalue);");
        sendEval("var testx = require('fs').existsSync(testname);");
        sendEval("var testcount=getHandleCount();");
        sendEval("selfTestResponse('fs_2', testx, {pre: testh, post: testcount});");
    });

    promises.fs_2.then(function (r)
    {
        process.stdout.write('\r         fs.writeFileSync()................................[OK]     \n');
        process.stdout.write('         fs.existsSync()...................................[OK]     \n');
        process.stdout.write('            => Handle Counts (Pre/Post): ' + r.reason.pre + '/' + r.reason.post + '\n');
    }).then(function ()
    {
        process.stdout.write('         fs.renameSync()...................................[WAITING]');
        sendEval("var renamedfile = '" + generateRandomString(5) + "'");
        sendEval("testh=getHandleCount();");
        sendEval("require('fs').renameSync(testname,renamedfile);");
        sendEval("testcount=getHandleCount();");
        sendEval("var testx = !require('fs').existsSync(testname) && require('fs').existsSync(renamedfile);");
        sendEval("selfTestResponse('fs_3', testx, {pre: testh, post: testcount});");
    });

    promises.fs_3.then(function (r)
    {
        process.stdout.write('\r         fs.renameSync()...................................[OK]     \n');
        process.stdout.write('            => Handle Counts (Pre/Post): ' + r.reason.pre + '/' + r.reason.post + '\n');

        ret.resolve();
    }).catch(function ()
    {
        process.stdout.write('\r         fs.renameSync()...................................[FAILED] \n');
        ret.reject('rename failed');
    });

    return (ret);
}

function SMBIOS_Test()
{
    var ret;
    switch(process.platform)
    {
        case 'win32':
            process.stdout.write('   Agent sent SMBIOS info to server........................[WAITING]');
            ret = promises.smbios;
            break;
        case 'linux':
            process.stdout.write('   Agent sent SMBIOS info to server........................[WAITING]');
            ret = (promises.smbios.ret = new promise(promise.defaultInit));
            sendEval("try { global.sm = require('smbios'); } catch (ex) { }");
            sendEval("if(global.sm!=null) { global.sm.get(function (x) { selfTestResponse('smbios_check', true, x!=null); }); }");
            promises.smbios_check.then(function (j)
            {
                if (j.reason === true)
                {
                    promises.smbios.then(function ()
                    {
                        process.stdout.write('\r   Agent sent SMBIOS info to server........................[OK]     \n');
                        promises.smbios.ret.resolve();
                    });
                }
                else
                {
                    process.stdout.write('\r   Agent sent SMBIOS info to server........................[NOT SUPPORTED]\n');
                    promises.smbios.ret.resolve();
                }
            });
            break;
        default:
            process.stdout.write('   Agent sent SMBIOS info to server........................[NA]\n');
            ret = new promise(promise.defaultInit);
            ret.resolve();
            break;
    }
    return (ret);
}
function FileTransfer_Test_Download()
{
    process.stdout.write('      => Initialize Download...............................[WAITING]');

    createTunnel(0x1FF, 0x00).then(function (t)
    {
        process.stdout.write('\r      => Initialize Download...............................[OK]     \n');
        process.stdout.write('      => Downloading File..................................[0 bytes]');

        t.crc = 0;  // Set the CRC to 0, so we can validate the download on the fly
        t.bytes = 0;
        t.on('data', function (b)
        {
            if (typeof (b) == 'string')
            {
                var cmd = JSON.parse(b);
                if (cmd.action != 'download') { return; }
                switch (cmd.sub)
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
                this.bytes += (b.length - 4);
                this.write({ action: 'download', sub: 'ack', id: 0 });
                process.stdout.write('\r      => Downloading File..................................[' + b.length + ' bytes]');

                if (fin)
                {
                    process.stdout.write('\r      => Downloading File..................................[DONE]                    \n');
                    process.stdout.write('         => CRC CHECK......................................[' + (this.crc == global.testbufferCRC ? 'OK' : 'FAILED') + ']\n');
                    this.end();
                }
            }
        });
        t.on('end', function ()
        {
            if(this.crc == global.testbufferCRC)
            {
                global.promises.filetransfer.resolve();
            }
            else
            {
                global.promises.filetransfer.reject('Download FAILED');
            }
        });

        t.write('c');
        t.write('5'); // Request Files
        t.write(JSON.stringify({ action: 'download', sub: 'start', path: process.cwd() + 'testFile', id: 0 }));


        //promises.filetransfer.resolve();
    }).catch(function ()
    {
        process.stdout.write('\r      => Initialize Download...............................[FAILED] \n');
        promises.filetransfer.reject('Failed to create tunnel');
    });
}
function FileTransfer_Test()
{
    process.stdout.write('   File Transfer Test\n');
    process.stdout.write('      => Initialize Upload.................................[WAITING]');

    createTunnel(0x1FF, 0x00).then(function (t)
    {
        t.on('data', function (buffer)
        {
            var jcmd = JSON.parse(buffer.toString());
            switch (jcmd.action)
            {
                case 'uploadstart':
                    // Start sending the file in 16k blocks
                    this.uploadBuffer = global.testbuffer.slice(0);
                    this.write(this.uploadBuffer.slice(0, 16384));
                    this.uploadBuffer = this.uploadBuffer.slice(16384);
                    break;
                case 'uploadack':
                    {
                        var bytesSent = global.testbuffer.length = this.uploadBuffer.length;
                        var pct = bytesSent / global.testbuffer.length;
                        pct = Math.floor(pct * 100);
                        process.stdout.write('\r      => Uploading File....................................[' + pct + '%]   ');

                        this.write(this.uploadBuffer.slice(0, this.uploadBuffer.length > 16384 ? 16384 : this.uploadBuffer.length));
                        this.uploadBuffer = this.uploadBuffer.slice(this.uploadBuffer.length > 16384 ? 16384 : this.uploadBuffer.length);
                        if (this.uploadBuffer.length == 0)
                        {
                            this.write({ action: 'uploaddone' });
                        }
                    }
                    break;
                case 'uploaddone':
                    process.stdout.write('\r      => Uploading File....................................[100%]   \n');
                    this.uploadsuccess = true;
                    this.end();
                    break;
            }
        });
        t.on('end', function ()
        {
            if (!this.uploadsuccess)
            {
                promises.filetransfer.reject('Upload FAILED');
                return;
            }
            FileTransfer_Test_Download();
        });
        process.stdout.write('\r      => Initialize Upload.................................[OK]     \n');

        global.testbuffer = require('EncryptionStream').GenerateRandom(65535); // Generate 64k Test Buffer
        global.testbufferCRC = crc32c(global.testbuffer);

        process.stdout.write('      => Uploading File....................................[0%]');

        t.write('c');
        t.write('5'); // Request Files
        t.write(JSON.stringify({ action: 'upload', name: 'testFile', path: process.cwd(), reqid: '0' }));

        //promises.filetransfer.resolve();
    }).catch(function ()
    {
        process.stdout.write('\r      => Initialize Upload.................................[FAILED] \n');
        promises.filetransfer.reject('Failed to create tunnel');
    });

    return (promises.filetransfer);
}

function Terminal_Test2(mode)
{
    var ret = new promise(promise.defaultInit);
    ret.mode = '';
    switch(mode)
    {
        case 1:
            ret.mode = '      => Initiating ROOT Terminal..........................';
            break;
        case 8:
            ret.mode = '      => Initiating USER Terminal..........................';
            break;
        case 6:
            ret.mode = '      => Initiating PowerShell ROOT Terminal...............';
            break;
        case 9:
            ret.mode = '      => Initiating PowerShell USER Terminal...............';
            break;
        default:
            ret.reject('Unknown Terminal Mode: ' + mode);
            return (ret);
            break;
    }

    process.stdout.write(ret.mode + '[WAITING]');
    var consent = 0xFF;
    if (process.platform == 'linux' || process.platform == 'freebsd')
    {
        if (!require('monitor-info').kvm_x11_support) { consent = 0x00; }
    }

    createTunnel(0x1FF, consent).then(function (t)
    {
        promises.terminal.connection = t;
        t.on('data', function _terminalDataHandler(d)
        {
            try
            {
                JSON.parse(d.toString());
            }
            catch (e)
            {
                process.stdout.write('\r' + ret.mode + '[OK]     \n');
                this.removeListener('data', _terminalDataHandler);
                this.success = true;
                if (process.platform == 'win32')
                {
                    this.write(Buffer.from('exit\r\n'));
                }
                else
                {
                    this.write(Buffer.from('exit\n'));
                }
            }
        });
        t.on('end', function ()
        {
            if (this.success)
            {
                ret.resolve();
            }
            else
            {                                          
                process.stdout.write('\r' + ret.mode + '[FAILED] \n');
                ret.reject('Closed Prematurely');
            }
        });

        //
        // 1 = root
        // 8 = user
        // 6 = powershell (root
        // 9 = powershell (user)
        //
        t.write('c');
        t.write(mode.toString());
    }).catch(function (e) { ret.reject(e); });
    return (ret);
}

function Terminal_Test()
{
    process.stdout.write('   Terminal Test\n');

    var p = Terminal_Test2(1)
                .then(function () { return (Terminal_Test2(8)); });
    if (process.platform == 'win32')
    {
        p = p.then(function ()
        {
            sendEval("selfTestResponse('conpty', true, {support: require('win-virtual-terminal').supported});");
            return (promises.conpty);
        }).then(function (j)
        {
            if (j.reason.support === true)
            {
                return (Terminal_Test2(6).then(function () { return (Terminal_Test2(9)); }));
            }
            else
            {
                process.stdout.write('      => CONPTY NOT Supported on this Platform\n');
                process.stdout.write('         => PowerShell ROOT Terminal.......................[SKIPPING]\n');
                process.stdout.write('         => PowerShell USER Terminal.......................[SKIPPING]\n');
            }
        });

        //p = p.then(function () { return (Terminal_Test2(6)) }).then(function () { return (Terminal_Test2(9)); });
    }

    return (p);
}

function AMT_Detection()
{
    process.stdout.write('   AMT Detection\n');
    var ret = new promise(promise.defaultInit);

    sendEval(" var amtMeiModule=null,amtMei=null; try { amtMeiModule = require('amt-mei'); amtMei = new amtMeiModule(); } catch (ex) { selfTestResponse('amt', false); }")
    sendEval("\
    try\
    {\
        amtMei.getVersion(function (result)\
        {\
            if (result)\
            {\
                var rs = {};\
                for (var version in result.Versions)\
                {\
                    if (result.Versions[version].Description == 'AMT') { rs.version = result.Versions[version].Version; }\
                    if (result.Versions[version].Description == 'Sku') { rs.sku = parseInt(result.Versions[version].Version); }\
                }\
                if (rs.sku & 8) { rs.version = 'Intel AMT v' + rs.version; }\
                else if (rs.sku & 16) { rs.version = 'Intel SM v' + rs.version }\
                else { rs.version = 'Intel ME v' + rs.version;}\
                amtMei.getProvisioningState(function (state) { if (state) { rs.ProvisioningState = state.stateStr; } });\
                amtMei.getProvisioningMode(function (result) { if (result) { rs.ProvisioningMode = result; } });\
                amtMei.getControlMode(function (result) \
                {\
                    if (result) \
                    {\
                        rs.controlmode = result;\
                        if (rs.ProvisioningState == 'PRE') { rs.ProvisioningState = 'pre-provisioning state'; }\
                        else if (rs.ProvisioningState == 'IN') { rs.ProvisioningState = 'in-provisioning state'; }\
                        else if (rs.ProvisioningState == 'POST')\
                        {\
                            if (rs.ProvisioningMode) \
                            {\
                                if (rs.controlmode) \
                                {\
                                    if (rs.ProvisioningMode.modeStr == 'ENTERPRISE') { rs.ProvisioningState= 'activated in ' + ['none', 'Client Control Mode (CCM)', 'Admin Control Mode (ACM)', 'remote assistance mode'][rs.controlmode.controlMode]; } else { rs.ProvisioningState = 'activated in ' + rs.ProvisioningMode.modeStr; }\
                                }\
                                else\
                                {\
                                    rs.ProvisioningState = 'activated in ' + rs.ProvisioningMode.modeStr;\
                                }\
                            }\
                        }\
                        selfTestResponse('amt', true, rs);\
                    }\
                });\
            }\
        });\
    }\
    catch(ex)\
    {\
        selfTestResponse('amt', false);\
    }");
    promises.amt.then(function (j)
    {
        if (j.reason && j.reason.version)
        {
            process.stdout.write('      => Version: ' + j.reason.version + '\n');
            process.stdout.write('      => Provisioning State: ' + j.reason.ProvisioningState + '\n');
            ret.resolve();
        }
        else
        {
            process.stdout.write('      => NOT DETECTED\n');
            ret.resolve();
        }
    }).catch(function ()
    {
        process.stdout.write('      => NOT DETECTED\n');
        ret.resolve();
    });
    return (ret);
}

function KVM_Test()
{
    process.stdout.write('   KVM Test\n');

    if (process.platform == 'linux' || process.platform == 'freebsd')
    {
        if (require('monitor-info').kvm_x11_support == false)
        {
            process.stdout.write('      => Support not detected on this platform\n');
            promises.kvm.resolve();
            return (promises.kvm);
        }
    }

    promises.kvm.DisplayInfo = new promise(promise.defaultInit);
    promises.kvm.ScreenSize = new promise(promise.defaultInit);
    promises.kvm.MouseCursor = new promise(promise.defaultInit);
    promises.kvm.Keyboard = new promise(promise.defaultInit);
    promises.kvm.Selected = new promise(promise.defaultInit);
    promises.kvm.Jumbo = new promise(promise.defaultInit);
    promises.kvm.Picture = new promise(promise.defaultInit);
    promises.kvm.Connected = new promise(promise.defaultInit);
    promises.kvm.Set = new promise(promise.defaultInit);

    process.stdout.write('      => Initiating KVM Tunnel.............................[WAITING]');
    createTunnel(0x1FF, 0xFF).then(function (t)
    {
        promises.kvm.tunnel = t;

        t.on('data', function (buf)
        {
            if (typeof (buf) == 'string') { return; }
            var type = buf.readUInt16BE(0);
            var sz = buf.readUInt16BE(2);

            if (promises.kvm.OK == null)
            {
                process.stdout.write('\r      => Initiating KVM Tunnel.............................[OK]     \n');
                promises.kvm.OK = true;
                promises.kvm.Connected.resolve();
            }

            switch(type)
            {
                case MNG_JUMBO:
                    // JUMBO PACKET
                    sz = buf.readUInt32BE(4);
                    type = buf.readUInt16BE(8);
                    if (buf.readUInt16BE(12) != 0)
                    {
                        promises.kvm.Jumbo.reject('JUMBO ERROR');
                        this.end();
                    }
                    else
                    {
                        promises.kvm.Jumbo.resolve(sz);
                    }
                    buf = buf.slice(8);
                    break;
                case MNG_KVM_PICTURE:
                    promises.kvm.Picture.resolve(sz);
                    break;
                case MNG_KVM_SCREEN:
                    if (sz != 8)
                    {
                        process.stdout.write('         => MNG_KVM_SCREEN (ERROR)\n');
                        promises.kvm.ScreenSize.reject('MNG_KVM_SCREEN ERROR');
                        this.end();
                    }
                    promises.kvm.ScreenSize.resolve(buf.readUInt16BE(3) + ' x ' + buf.readUInt16BE(4));
                    break;
                case MNG_KVM_DISPLAY_INFO:
                    {
                        var entries = (sz - 4) / 10, i, offset;
                        var n = [];

                        for(i=0;i<entries;++i)
                        {
                            offset = (10 * i) + 4;
                            n.push({ ID: buf.readUInt16BE(offset), X: buf.readUInt16BE(offset + 2), Y: buf.readUInt16BE(offset + 4), W: buf.readUInt16BE(offset + 6), H: buf.readUInt16BE(offset + 8) });
                        }
                        promises.kvm.DisplayInfo.resolve(n);
                    }
                    break;
                case MNG_KVM_MOUSE_CURSOR:
                    promises.kvm.MouseCursor.resolve();
                    break;
                case MNG_KVM_KEYSTATE:
                    promises.kvm.Keyboard.resolve();
                    break;
                case MNG_KVM_GET_DISPLAYS:
                    promises.kvm.Selected.resolve();
                    break;
                case MNG_KVM_SET_DISPLAY:
                    promises.kvm.Set.resolve(buf[5]);
                    break;
                default:
                    process.stdout.write('         => Received KVM PACKET TYPE: ' + type + ' (' + sz + ' bytes)\n');
                    break;
            }
        });
        t.on('end', function () { });

        promises.kvm.Connected.then(function ()
        {
            process.stdout.write('         => Display Info Received..........................[WAITING]');
            promises.kvm.DisplayInfo.timeout = setTimeout(function () { promises.kvm.DisplayInfo.resolve([]); }, 3000);
            return (promises.kvm.DisplayInfo);
        }).then(function (v)
        {
            if (v.length == 0)
            {
                process.stdout.write('\r         => Display Info Received..........................[NA]     \n');
            }
            else
            {
                process.stdout.write('\r         => Display Info Received..........................[OK]     \n');
                process.stdout.write('              => Number of Displays: ' + v.length + '\n');
            }
            while (v.length > 0)
            {
                var info = v.pop();
                process.stdout.write('                 ID: ' + info.ID + ' (' + info.W + ' x ' + info.H + ')\n');
            }
        }).then(function ()
        {
            process.stdout.write('         => Display Selection Received.....................[WAITING]');
            return (promises.kvm.Selected);
        }).then(function ()
        {
            process.stdout.write('\r         => Display Selection Received.....................[OK]     \n');
            process.stdout.write('         => Screen Resolution..............................[WAITING]');
            return (promises.kvm.ScreenSize);
        }).then(function (s)
        {
            process.stdout.write('\r         => Screen Resolution..............................[OK]     \n');
            process.stdout.write('         => JUMBO Packet Received..........................[WAITING]');
            return (promises.kvm.Jumbo);
        }).then(function ()
        {
            process.stdout.write('\r         => JUMBO Packet Received..........................[OK]     \n');
            process.stdout.write('         => JPEG Received..................................[WAITING]');
            return (promises.kvm.Picture);
        }).then(function ()
        {
            process.stdout.write('\r         => JPEG Received..................................[OK]     \n');
            promises.kvm.resolve();
        });


        t.write('c');
        t.write('2'); // Request KVM
    });

    return (promises.kvm);
}
function Digest_Test()
{
    digest_realm = generateRandomRealm();
    digest_username = generateRandomString(generateRandomNumber(5, 10));
    digest_password = generateRandomString(generateRandomNumber(8, 20));

    process.stdout.write('   HTTP Digest Test\n');
    process.stdout.write('      => Basic.............................................[WAITING]');

    sendEval("var digest = require('http-digest').create('" + digest_username + "', '" + digest_password + "');");
    sendEval("digest.http = require('http');");
    sendEval("var options = { protocol: 'https:', host: '127.0.0.1', port: " + server.address().port + ", path: '/', method: 'POST', rejectUnauthorized: false };");
    sendEval("var req = digest.request(options);");
    sendEval("req.on('error', function (e) { selfTestResponse('digest', false, JSON.stringify(e)); req = null; });");
    sendEval("req.on('response', function (imsg) { selfTestResponse('digest', true); });");
    sendEval("req.end('TestData');");

    promises.digest.then(function (v)
    {
        process.stdout.write('\r      => Basic.............................................[OK]     \n');
        process.stdout.write('      => QOP = auth........................................[WAITING]');

        digest_realm = generateRandomRealm();
        digest_username = generateRandomString(generateRandomNumber(5, 10));
        digest_password = generateRandomString(generateRandomNumber(8, 20));

        sendEval("digest = require('http-digest').create('" + digest_username + "', '" + digest_password + "');");
        sendEval("digest.http = require('http');");
        sendEval("var options = { protocol: 'https:', host: '127.0.0.1', port: " + server.address().port + ", path: '/auth', method: 'POST', rejectUnauthorized: false };");
        sendEval("var req = digest.request(options);");
        sendEval("req.on('error', function (e) { selfTestResponse('digest_auth', false, JSON.stringify(e)); req = null; });");
        sendEval("req.on('response', function (imsg) { selfTestResponse('digest_auth', true); });");
        sendEval("req.end('TestData');");
    });

    promises.digest_auth.then(function ()
    {
        process.stdout.write('\r      => QOP = auth........................................[OK]     \n');
        process.stdout.write('      => QOP = auth-int....................................[WAITING]');

        digest_realm = generateRandomRealm();
        digest_username = generateRandomString(generateRandomNumber(5, 10));
        digest_password = generateRandomString(generateRandomNumber(8, 20));

        sendEval("digest = require('http-digest').create('" + digest_username + "', '" + digest_password + "');");
        sendEval("digest.http = require('http');");
        sendEval("var options = { protocol: 'https:', host: '127.0.0.1', port: " + server.address().port + ", path: '/auth-int', method: 'POST', rejectUnauthorized: false };");
        sendEval("var req = digest.request(options);");
        sendEval("req.on('error', function (e) { selfTestResponse('digest_authint', false, JSON.stringify(e)); req = null; });");
        sendEval("req.on('response', function (imsg) { selfTestResponse('digest_authint', true); });");
        sendEval("req.end('TestData');");
    });

    return (promises.digest_authint.then(function ()
    {
        process.stdout.write('\r      => QOP = auth-int....................................[OK]     \n');
    }));
}

function WebRTC_Test()
{
    promises.webrtc_test.timeout = setTimeout(function ()
    {
        process.stdout.write('\n *TIMEOUT*\n');
        promises.webrtc_test.resolve();
    }, testTimeout * 1000);
    process.stdout.write('   WebRTC Test\n');
    process.stdout.write('      => Recieved Initial Offer............................[WAITING]');

    sendEval("var clientConnection = require('ILibWebRTC').createConnection();")
    sendEval("var hasher = require('SHA384Stream').create();");
    sendEval("clientConnection.on('dataChannel', function (rtcchannel) { var b = Buffer.alloc(6665535); b.randomFill(); selfTestResponse('webrtc_hash', true, hasher.syncHash(b).toString('hex')); rtcchannel.write(b); });");
    sendEval("var offer = clientConnection.generateOffer(); var ob = Buffer.from(offer); selfTestResponse('webrtc_offer', true, ob.toString('base64'));");
    
    promises.webrtc_test.serverConnection = require('ILibWebRTC').createConnection();
    promises.webrtc_offer.then(function (offer)
    {
        process.stdout.write('\r      => Recieved Initial Offer............................[OK]     \n');
        //process.stdout.write(JSON.stringify(offer, null, 1));
        process.stdout.write('      => Counter-Offer Set.................................[OK]\n');
        process.stdout.write('      => Peer Connection Established.......................[WAITING]');

        var offer = Buffer.from(offer.reason, 'base64').toString();
        var counter = promises.webrtc_test.serverConnection.setOffer(offer);
        var b = Buffer.from(counter).toString('base64');
        sendEval("try{clientConnection.setOffer(Buffer.from('" + b + "', 'base64').toString());} catch(z) { sendConsoleText(JSON.stringify(z)); }");
    });

    promises.webrtc_test.serverConnection.on('connected', function ()
    {
        process.stdout.write('\r      => Peer Connection Established.......................[OK]     \n');
        process.stdout.write('      => Data Channel Creation.............................[WAITING]');
        this.dc = this.createDataChannel('Test Data Channel');
        this.dc.on('data', function (b)
        {
            var h = require('SHA384Stream').create();
            var dataHash = h.syncHash(b).toString('hex');

            promises.webrtc_hash.then(function (j)
            {
                process.stdout.write('\r      => Data Channel Creation.............................[OK]     \n');
                if (j.reason == dataHash)
                {
                    process.stdout.write('      => Data Fragmentation Test...........................[OK]\n');
                    clearTimeout(promises.webrtc_test.timeout);
                    promises.webrtc_test.resolve();
                }
                else
                {
                    clearTimeout(promises.webrtc_test.timeout);
                    promises.webrtc_test.reject('WebRTC Data Channel received corrupt data (' + b.length + ' bytes');
                }
            });
        });

    });

    return (promises.webrtc_test);
}

function Clipboard_Test()
{
    if ((process.platform == 'linux' || process.platform == 'freebsd') && !require('monitor-info').kvm_x11_support)
    {
        // X11 Support Missing, so Clipboard is not supported
        process.stdout.write('   Clipboard Test..........................................[NOT SUPPORTED]\n');
        promises.setclip.resolve();
        return (promises.setclip);
    }

    addTimeout(promises.setclip);
    process.stdout.write('   Clipboard Test..........................................[WAITING]');
    var b = Buffer.alloc(16);
    b.randomFill();
    global._cliptest = b.toString('base64');
    global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'setclip', data: global._cliptest });
    
    var r = promises.setclip.then(function (v)
    {
        console.info1(JSON.stringify(v));
        if (!v.success)
        {
            process.stdout.write('\r   Clipboard Test..........................................[FAILED TO SET]\n');
            return;
        }
        addTimeout(promises.getclip);
        global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'getclip' });
        return (promises.getclip);
    }).then(function (v)
    {
        if (v.data == global._cliptest)
        {
            process.stdout.write('\r   Clipboard Test..........................................[OK]      \n');
        }
        else
        {
            process.stdout.write('\r   Clipboard Test..........................................[FAILED]  \n');
            process.stdout.write('      => Expected: ' + global._cliptest + '\n');
            process.stdout.write('      => Received: ' + v.data + '\n');
        }
    });
    return (r);
}

function createTunnel(rights, consent)
{
    var ret = new promise(promise.defaultInit);
    TunnelPromises.push(ret);

    ret.parent = global._client;
    ret.timeout = setTimeout(function ()
    {
        ret.reject('timeout');
    }, testTimeout*1000);
    ret.options =
        {
            action: 'msg',
            type: 'tunnel',
            rights: rights,
            consent: consent,
            userid: 'testid',
            username: '(test script)',
            value: 'wss://127.0.0.1:' + server.address().port + '/tunnel'
        };
    global._client.command(ret.options);
    return (ret);
}
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
            if (s.pid != null)
            {
                try
                {
                    ret = s.pid();
                }
                catch (x)
                {
                }
            }
            break;
    }

    return (ret);
}
function endTest()
{
    global._client.removeAllListeners('end');

    console.log('==> End of Test');
    var params = ['--meshServiceName=TestAgent'];
    var paramsString = JSON.stringify(params);

    require('agent-installer').fullUninstall(paramsString);
    console.setDestination(console.Destinations.STDOUT);
}
function sendEval(cmd)
{
    global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'console', value: 'eval "' + cmd + '"' });
}

if (process.argv.getParameter('AgentsFolder') != null)
{
    var helper = "function getHandleCount()\
    {\
        var ret = 0;\
        switch (process.platform)\
        {\
            case 'win32':\
                var h = kernel32.GetCurrentProcess();\
                var c = require('_GenericMarshal').CreateVariable(4);\
                kernel32.GetProcessHandleCount(h, c);\
                ret = c.toBuffer().readUInt32LE();\
                break;\
            default:\
                break;\
        }\
        return (ret);\
    }";

    var folder = process.argv.getParameter('AgentsFolder');
    if (folder.endsWith('/')) { folder = folder.split('/'); folder.pop(); folder = folder.join('/'); }
    if (folder.endsWith('\\')) { folder = folder.split('\\'); folder.pop(); folder = folder.join('\\'); }

    meshcore = require('fs').readFileSync(folder + (process.platform == 'win32' ? '\\' : '/') + 'meshcore.js').toString();
    var modules = folder + (process.platform == 'win32' ? '\\' : '/') + 'modules_meshcore';
    var modules_folder = require('fs').readdirSync(modules);
    var i, tmp, m;

    var lines = ['var addedModules = [];'];
    if (remoteDebug != 0)
    {
        lines.push("console.enableWebLog(" + remoteDebug + ");");
    }
    lines.push("if (process.platform == 'win32') { global.kernel32 = require('_GenericMarshal').CreateNativeProxy('kernel32.dll'); global.kernel32.CreateMethod('GetCurrentProcess'); global.kernel32.CreateMethod('GetProcessHandleCount'); }");
    lines.push(helper);
    lines.push("process.coreDumpLocation = process.platform == 'win32' ? (process.execPath.replace('.exe', '.dmp')) : (process.execPath + '.dmp');");
    lines.push("function selfTestResponse(id, result, reason) { require('MeshAgent').SendCommand({ action: 'result', id: id, result: result, reason: reason }); }");
    for (i = 0; i < modules_folder.length; ++i)
    {
        tmp = require('fs').readFileSync(modules + (process.platform == 'win32' ? '\\' : '/') + modules_folder[i]);
        lines.push('try { addModule("' + (m = modules_folder[i].split('.').shift()) + '", Buffer.from("' + tmp.toString('base64') + '", "base64").toString()); addedModules.push("' + m + '");} catch (x) { }');
    }

    meshcore = lines.join('\n') + meshcore;
}

if (process.argv.getParameter('verbose') != null)
{
    console.setInfoLevel(parseInt(process.argv.getParameter('verbose')));
}

if (process.argv.getParameter('NoInstall') == null)
{
    //
    // Start by installing agent as service
    //
    var params = ['--__skipExit=1', '--logUpdate=1', '--meshServiceName=TestAgent'];
    var options =
        {
            files:
                [
                    {
                        newName: (process.platform == 'win32' ? 'MeshAgent.msh' : 'meshagent.msh'),
                        _buffer: 'enableILibRemoteLogging=5556\nlogUpdate=1\nMeshID=0x43FEF862BF941B2BBE5964CC7CA02573BBFB94D5A717C5AA3FC103558347D0BE26840ACBD30FFF981F7F5A2083D0DABC\nMeshServer=wss://127.0.0.1:' + server.address().port + '/agent.ashx\nmeshServiceName=TestAgent\nServerID=' + loadedCert.getKeyHash().toString('hex')
                    }
                ],
            binary: updateSource,
            noParams: true
        };
    require('agent-installer').fullInstallEx(params, options);
    console.setDestination(console.Destinations.STDOUT);
}
console.log('\nWaiting for Agent Connection...');
