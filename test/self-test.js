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
process.coreDumpLocation = process.platform == 'win32' ? (process.execPath.replace('.exe', '.dmp')) : (process.execPath + '.dmp');

var updateSource = null;
var promise = require('promise');

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

const PLATFORMS = ['UNKNOWN', 'DESKTOP', 'LAPTOP', 'MOBILE', 'SERVER', 'DISK', 'ROUTER', 'PI', 'VIRTUAL'];
var agentConnectionCount = 0;
var updateState = 0;
const consoleMode = process.argv.getParameter('console') != null;

var digest_realm;
var digest_username;
var digest_password;


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
    console.log('   --console               If specified, enables console command mode');
    console.log('   --PrivacyBar            If specified, causes the agent to spawn a privacy bar');
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

var promises =
    {
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
            this.processJSON(JSON.parse(buffer.toString()));
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
                console.log('');
                console.log('Agent is running core: ' + j.value);
                console.log('');
                break;
            case 'msg':
                switch(j.type)
                {
                    case 'console':
                        if (j.value != 'Command returned an exception error: TypeError: cyclic input') { console.log('Agent: ' + j.value); }
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

        //
        // Run thru the main tests, becuase no special options were sent
        //
        console.log('\nRunning Meshcore Tests:');
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
            process.stdout.write('   Agent sent SMBIOS info to server........................[WAITING]');
            switch(process.platform)
            {
                case 'linux':
                case 'win32':
                    return (promises.smbios);
                    break;
                default:
                    break;
            }
        }).then(function ()
        {
            process.stdout.write('\r');
            switch (process.platform)
            {
                case 'linux':
                case 'win32':
                    process.stdout.write('   Agent sent SMBIOS info to server........................[OK]      \n');
                    break;
                default:
                    process.stdout.write('   Agent sent SMBIOS info to server........................[NA]      \n');
                    break;
            }
            process.stdout.write('   Tunnel Test.............................................[WAITING]');
            return (createTunnel(0, 0));
        }).then(function (t)
        {
            process.stdout.write('\r   Tunnel Test.............................................[OK]      \n');
            t.end();
        }).then(function ()
        {
            global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'console', value: 'help' });
            process.stdout.write('   Console Test (Help).....................................[WAITING]');
            return (promises.help);
        }).then(function (v)
        {
            //var vals = v.substring(19).split('\n').join('').split('\r').join('').split('.').join('').split(' ').join('');
            process.stdout.write('\r   Console Test (Help).....................................[OK]      \n');
            process.stdout.write('   CPUINFO Test............................................[WAITING]');
            global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'cpuinfo' });
            return (promises.cpuinfo);
        }).then(function (v)
        {
            process.stdout.write('\r   CPUINFO Test............................................[OK]      \n');
            process.stdout.write('   PS Test.................................................[WAITING]');
            global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'ps' });
            return (promises.ps);
        }).then(function (v)
        {
            var p;
            try
            {
                p = JSON.parse(v.value);
            }
            catch(e)
            {
                process.stdout.write('\r   PS Test.................................................[FAILED]      \n');
                process.stdout.write('   => ' + e + '\n');
                return;
            }
            process.stdout.write('\r   PS Test.................................................[OK]      \n');
            process.stdout.write('      => ' + p.keys().length + ' processes retrieved.\n');

            process.stdout.write('   Service Enumeration Test................................[WAITING]');
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
            process.stdout.write('   Clipboard Test..........................................[WAITING]');
            var b = Buffer.alloc(16);
            b.randomFill();
            global._cliptest = b.toString('base64');
            global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'setclip', data: global._cliptest });
            return (promises.setclip);
        }).then(function (v)
        {
            console.info1(JSON.stringify(v));
            if (!v.success)
            {
                process.stdout.write('\r   Clipboard Test..........................................[FAILED TO SET]\n');
                return;
            }
            global._client.command({ sessionid: 'user//foo//bar', rights: 4294967295, consent: 64, action: 'msg', type: 'getclip' });
            return (promises.getclip);
        }).then(function (v)
        {
            if(v.data == global._cliptest)
            {
                process.stdout.write('\r   Clipboard Test..........................................[OK]      \n');
            }
            else
            {
                process.stdout.write('\r   Clipboard Test..........................................[FAILED]  \n');
                process.stdout.write('      => Expected: ' + global._cliptest + '\n');
                process.stdout.write('      => Received: ' + v.data + '\n');
            }
        }).then(function ()
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

            return (promises.digest);
        }).then(function (v)
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

            return (promises.digest_auth);
        }).then(function ()
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

            return (promises.digest_authint);
        }).then(function ()
        {
            process.stdout.write('\r      => QOP = auth-int....................................[OK]     \n');
        }).then(function ()
        {
            process.stdout.write('\nTesting Complete\n\n');
            endTest();
        }).catch(function (e)
        {
            process.stdout.write('\nTesting Failed (' + e + ')\n\n');
            endTest();
        });

    };
});

function createTunnel(rights, consent)
{
    var ret = new promise(promise.defaultInit);
    TunnelPromises.push(ret);

    ret.parent = global._client;
    ret.timeout = setTimeout(function ()
    {
        ret.reject('timeout');
    }, 2000);
    ret.options = { action: 'msg', type: 'tunnel', rights: rights, consent: consent, username: '(test script)', value: 'wss://127.0.0.1:' + server.address().port + '/tunnel' };
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
    var folder = process.argv.getParameter('AgentsFolder');
    
    if (folder.endsWith('/')) { folder = folder.split('/'); folder.pop(); folder = folder.join('/'); }
    if (folder.endsWith('\\')) { folder = folder.split('\\'); folder.pop(); folder = folder.join('\\'); }

    meshcore = require('fs').readFileSync(folder + (process.platform == 'win32' ? '\\' : '/') + 'meshcore.js').toString();
    var modules = folder + (process.platform == 'win32' ? '\\' : '/') + 'modules_meshcore';
    var modules_folder = require('fs').readdirSync(modules);
    var i, tmp, m;

    var lines = ['var addedModules = [];'];
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
                        _buffer: 'logUpdate=1\nMeshID=0x43FEF862BF941B2BBE5964CC7CA02573BBFB94D5A717C5AA3FC103558347D0BE26840ACBD30FFF981F7F5A2083D0DABC\nMeshServer=wss://127.0.0.1:' + server.address().port + '/agent.ashx\nmeshServiceName=TestAgent\nServerID=' + loadedCert.getKeyHash().toString('hex')
                    }
                ],
            binary: updateSource,
            noParams: true
        };
    require('agent-installer').fullInstallEx(params, options);
    console.setDestination(console.Destinations.STDOUT);
}
console.log('\nWaiting for Agent Connection...');


