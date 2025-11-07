// Module: mac-powerutil
// Timestamp: 2025-08-19T13:12:47.000-06:00
// Original compressed size: 763 bytes
// Decompressed size: 2769 bytes
// Compression ratio: 72.4%

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

function powerutil()
{
    this._ObjectID = 'mac-powerutil';

    this.sleep = function sleep()
    {
        var child;
        switch (process.platform)
        {
            case 'darwin':
                child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write('osascript -e \'tell application "System Events" to sleep\'\nexit\n');
                child.waitExit();
                break;
            default:
                throw ('sleep() not implemented on this platform');
                break;
        }
    }
    this.restart = function restart()
    {
        var child;
        switch(process.platform)
        {
            case 'darwin':
                child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write('shutdown -r now\n');
                child.waitExit();
                break;
            default:
                throw ('restart() not implemented on this platform');
                break;
        }
    }
    this.shutdown = function shutdown()
    {
        var child;
        switch (process.platform)
        {
            case 'darwin':
                child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write('shutdown -h now\n');
                child.waitExit();
                break;
            default:
                throw ('shutdown() not implemented on this platform');
                break;
        }
    }
}

module.exports = new powerutil();