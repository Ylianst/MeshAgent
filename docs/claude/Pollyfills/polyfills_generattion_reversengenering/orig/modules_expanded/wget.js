// Module: wget
// Timestamp: 2025-08-19T13:12:47.000-06:00
// Original compressed size: 1700 bytes
// Decompressed size: 4627 bytes
// Compression ratio: 63.3%

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


//
// This module provides wget functionality on platforms that lack wget
//

var promise = require('promise');
var http = require('http');
var writable = require('stream').Writable;


//
// Returns a promise, that connects to a remoteUri, saving the target to localFilePath, using the specified options
//
function wget(remoteUri, localFilePath, wgetoptions)
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    var agentConnected = false;
    require('events').EventEmitter.call(ret, true)
        .createEvent('bytes')
        .createEvent('abort')
        .addMethod('abort', function () { this._request.abort(); });

    try
    {
        agentConnected = require('MeshAgent').isControlChannelConnected;
    }
    catch (e)
    {
    }

    // We only need to check proxy settings if the agent is not connected, because when the agent
    // connects, it automatically configures the proxy for JavaScript.
    if (!agentConnected)
    {
        if (process.platform == 'win32')
        {
            var reg = require('win-registry');
            if (reg.QueryKey(reg.HKEY.CurrentUser, 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 'ProxyEnable') == 1)
            {
                var proxyUri = reg.QueryKey(reg.HKEY.CurrentUser, 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 'ProxyServer');
                var options = require('http').parseUri('http://' + proxyUri);

                console.log('proxy => ' + proxyUri);
                require('global-tunnel').initialize(options);
            }
        }
    }

    var reqOptions = require('http').parseUri(remoteUri);
    if (wgetoptions)
    {
        // Enumerate the specified options, and save them as http options
        for (var inputOption in wgetoptions)
        {
            reqOptions[inputOption] = wgetoptions[inputOption];
        }
    }
    ret._totalBytes = 0;
    ret._request = http.get(reqOptions);
    ret._localFilePath = localFilePath;
    ret._request.promise = ret;
    ret._request.on('error', function (e) { this.promise._rej(e); });
    ret._request.on('abort', function () { this.promise.emit('abort'); });
    ret._request.on('response', function (imsg)
    {
        if(imsg.statusCode != 200)
        {
            this.promise._rej('Server responsed with Status Code: ' + imsg.statusCode);
        }
        else
        {
            //
            // The http response was successful, so lets setup the destination stream, and hash stream
            //
            try
            {
                this._file = require('fs').createWriteStream(this.promise._localFilePath, { flags: 'wb' });
                this._sha = require('SHA384Stream').create();
                this._sha.promise = this.promise;
            }
            catch(e)
            {
                this.promise._rej(e);
                return;
            }
            this._sha.on('hash', function (h) { this.promise._res(h.toString('hex')); }); // Resolve the promise with the hash of the received data
            this._accumulator = new writable(
                {
                    write: function(chunk, callback)
                    {
                        this.promise._totalBytes += chunk.length;
                        this.promise.emit('bytes', this.promise._totalBytes); // Emit the running total of bytes received as 'bytes'
                        return (true);
                    },
                    final: function(callback)
                    {
                        callback();
                    }
                });
            this._accumulator.promise = this.promise;
            imsg.pipe(this._file);          // Write the received data to the file stream
            imsg.pipe(this._accumulator);   // Accumulate the number of bytes received to emit 'byte'
            imsg.pipe(this._sha);           // Hash the received data using SHA384
        }
    });
    ret.progress = function () { return (this._totalBytes); };
    return (ret);
}

module.exports = wget;


