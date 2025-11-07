// Module: AgentHashTool
// Timestamp: 2025-08-19T13:12:47.000-06:00
// Original compressed size: 1259 bytes
// Decompressed size: 3760 bytes
// Compression ratio: 66.5%

/*
Copyright 2018 Intel Corporation

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

const exeMeshPolicyGuid = 'B996015880544A19B7F7E9BE44914C19';

// options <object>
//  sourcePath: <string> Executable Path
//  targetStream: <stream.writeable> Hashing Stream
//  platform: <string> Optional. Same value as process.platform ('win32' | 'linux' | 'darwin')

function hashFile(options)
{
    if(!options.sourcePath || !options.targetStream) {throw('Please specify sourcePath and targetStream');}

    var fs = require('fs');

    if(!options.platform)
    {
        // Determine Platform type
        // Try to determine what the platform is
        try
        {
            options.peinfo = require('PE_Parser')(options.sourcePath);
            options.platform = 'win32';
        }
        catch (e) {
            options.platform = 'other';
        }
    }
   
    options.state = {endIndex:0, checkSumIndex:0, tableIndex:0, stats:fs.statSync(options.sourcePath)};

    if(options.platform == 'win32')
    {
        if(options.peinfo.CertificateTableAddress!=0) {options.state.endIndex = options.peinfo.CertificateTableAddress;}
        options.state.tableIndex = options.peinfo.CertificateTableSizePos - 4;
        options.state.checkSumIndex = options.peinfo.CheckSumPos;
    }

    if (options.state.endIndex == 0)
    {
        // We just need to check for Embedded MSH file
        var fd = fs.openSync(options.sourcePath, 'rb');
        var guid = Buffer.alloc(16);
        var bytesRead;

        bytesRead = fs.readSync(fd, guid, 0, guid.length, options.state.stats.size - 16);
        if(guid.toString('hex') == exeMeshPolicyGuid)
        {
            bytesRead = fs.readSync(fd, guid, 0, 4, options.state.stats.size - 20);
            options.state.endIndex = options.state.stats.size - 20 - guid.readUInt32LE(0);
        }
        else
        {
            options.state.endIndex = options.state.stats.size;
        }
        fs.closeSync(fd);
    }

    if (options.state.checkSumIndex != 0)
    {
        options.state.source = fs.createReadStream(options.sourcePath, { flags: 'rb', start: 0, end: options.state.checkSumIndex-1 });
        options.state.source.on('end', function ()
        {
            options.targetStream.write(Buffer.alloc(4));
            var source = fs.createReadStream(options.sourcePath, { flags: 'rb', start: options.state.checkSumIndex + 4, end: options.state.tableIndex-1 });
            source.on('end', function ()
            {
                options.targetStream.write(Buffer.alloc(8));
                var source = fs.createReadStream(options.sourcePath, { flags: 'rb', start: options.state.tableIndex + 8, end: options.state.endIndex-1 });
                options.state.source = source;
                options.state.source.pipe(options.targetStream);

            });
            options.state.source = source;
            options.state.source.pipe(options.targetStream, { end: false });
        });
        options.state.source.pipe(options.targetStream, { end: false });
    }
    else
    {
        options.state.source = fs.createReadStream(options.sourcePath, { flags: 'rb', start: 0, end: options.state.endIndex-1 });
        options.state.source.pipe(options.state.targetStream);
    }
}

module.exports = hashFile;


