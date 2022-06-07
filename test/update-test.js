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

process.stdout.write('Generating Certificate...');
var cert = require('tls').generateCertificate('test', { certType: 2, noUsages: 1 });
var server = require('https').createServer({ pfx: cert, passphrase: 'test' });
server.listen({ port: 9250 });

process.stdout.write('\rGenerating Certificate... [DONE]\n');

var loadedCert = require('tls').loadCertificate({ pfx: cert, passphrase: 'test' });
var der = loadedCert.toDER();

var tmp = require('tls').loadCertificate({ der: der });
console.log('DER: ' + tmp.getKeyHash().toString('hex'));

console.log('DER/LEN: ' + der.length);
console.log('Certificate Digest = ' + cert.digest.split(':').join(''));
console.log('Certificate Fingerprint = ' + loadedCert.getKeyHash().toString('hex'));
global._test = [];

server.on('connection', function (c)
{
    global._test.push(c);
    console.log('inbound connection');
});
server.on('request', function (imsg, response)
{
    console.log(imsg);
});

server.on('upgrade', function (msg, sck, head)
{
    console.log('upgrade');
    global._client = sck.upgradeWebSocket();
    global._client.on('data', function (buffer)
    {
        this.processCommand(buffer);
    });
    global._client.processCommand = function processCommand(buffer)
    {
        var cmd = buffer.readUInt16BE(0);
        switch(cmd)
        {
            case 30:    // Agent Commit Date
                console.log("Connected Agent's Commit Date: " + buffer.slice(2).toString());
                break;
            case 31:
                console.log("Connected Agent Info: " + buffer.slice(2).toString());
                break;
            case 5:
                console.log("Connected Agent's ServerID: " + buffer.slice(2).toString('hex'));
                break;
            case 1:
                //typedef struct MeshCommand_BinaryPacket_AuthRequest
                //{
                //    unsigned short command;
                //    char serverHash[UTIL_SHA384_HASHSIZE];
                //    char serverNonce[UTIL_SHA384_HASHSIZE];
                //}MeshCommand_BinaryPacket_AuthRequest;
                var serverHash = buffer.slice(2, 50).toString('hex');
                this.agentNonce = Buffer.alloc(48);
                buffer.slice(50, 98).copy(this.agentNonce);

                console.log('Agent Sent Nonce: ' + this.agentNonce);
                console.log('Agent Sent ServerID: ' + serverHash);

                this.serverNonce = Buffer.alloc(48);
                this.serverNonce.randomFill();

                var authBuffer = Buffer.alloc(98);
                authBuffer.writeUInt16BE(1);                    // AuthRequest
                loadedCert.getKeyHash().copy(authBuffer, 2);    // ServerHash
                this.serverNonce.copy(authBuffer, 50);          // ServerNonce
                this.write(authBuffer);

                break;
            case 2:
                console.log('AUTH-VERIFY');

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


                console.log('SERVER/SIGN => ' + y.toString('hex'), y.length);
                console.log('SERVER/SIGN/AgentNonce => ' + this.agentNonce.toString('hex'), this.agentNonce.length);
                console.log('SERVER/SIGN/ServerNonce => ' + this.serverNonce.toString('hex'), this.serverNonce.length);
                console.log('SERVER/SIGN/RESULT => ' + hash._hashedValue.toString('hex'));

                var RSA = require('RSA');
                var signature = RSA.sign(RSA.TYPES.SHA384, loadedCert, hash._hashedValue);
                var verifyBuffer = Buffer.alloc(4 + der.length + signature.length);
                verifyBuffer.writeUInt16BE(2);              // AUTH-VERIFY
                verifyBuffer.writeUInt16BE(der.length, 2);  // CERT-LEN
                der.copy(verifyBuffer, 4);                  // CERT
                signature.copy(verifyBuffer, 4 + der.length);

                var v = RSA.verify(RSA.TYPES.SHA384, loadedCert, hash._hashedValue, signature);
                console.log('VERIFIED: ' + v);


                var zmp = require('tls').loadCertificate({ der: verifyBuffer.slice(4, verifyBuffer.readUInt16BE(2) + 4) });
                console.log('SENDING: ' + verifyBuffer.slice(4, verifyBuffer.readUInt16BE(2) + 4).toString('hex'));

                this.write(verifyBuffer);
                break;
            default:
                console.log('Command: ' + cmd);
                break;
        }
    };
});










