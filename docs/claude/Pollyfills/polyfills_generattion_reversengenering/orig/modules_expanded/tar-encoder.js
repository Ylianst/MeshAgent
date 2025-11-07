// Module: tar-encoder
// Timestamp: 2025-08-19T13:12:47.000-06:00
// Original compressed size: 2413 bytes
// Decompressed size: 8590 bytes
// Compression ratio: 71.9%

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

var readable = require('stream').Readable;


function loadUstarHeader(path, offset)
{
    var fd = require('fs').openSync(path, 'rb');
    var buffer = Buffer.alloc(512);
    var result = require('fs').readSync(fd, buffer, 0, 512, offset);
    require('fs').closeSync(fd);

    var v = 0;
    for (var i = 0; i < 512; ++i)
    {
        if (i >= 148 && i < 155)
        {
            v += 32;
        }
        else
        {
            v += buffer[i];
        }
    }

    if (parseInt(buffer.slice(148, 148 + 8).toString(), 8) != (new Uint32Array([v]))[0])
    {
        return (null);
    }
    else
    {
        return (buffer);
    }
}

function generateUstarHeader(path, basePath, uidtable, gidtable)
{
    var ret = Buffer.alloc(512);
    var stats = require('fs').statSync(path);
    var name = process.platform == 'win32' ? path.split('\\').join('/') : path;
    if (basePath) { name = name.substring(basePath.endsWith('/') ? basePath.length : (basePath.length + 1)); }

    if (stats.isFile())
    {
        Buffer.from(stats.size.toString(8), 'binary').copy(ret, 124, 0, 12);
        Object.defineProperty(ret, 'isFile', { value: true });
    }
    else
    {
        Buffer.from('0').copy(ret, 124, 0, 12);
        Object.defineProperty(ret, 'isFile', { value: false });
        name += '/';
    }

    Buffer.from(name, 'binary').copy(ret, 0, 0, 100);
    ret[156] = stats.isFile() ? 48 : 53;
    Buffer.from((Date.parse(stats.mtime) / 1000).toString(8), 'binary').copy(ret, 136, 0, 12);
    Buffer.from('USTAR', 'binary').copy(ret, 257, 0, 5);

    if (process.platform == 'win32')
    {
        // Windows Platforms, set UID/GID to 0
        Buffer.from('0', 'binary').copy(ret, 108, 0, 8); // uid
        Buffer.from('0', 'binary').copy(ret, 116, 0, 8); // gid

        // Windows Platforms, set uname/gname to root/root
        Buffer.from('root', 'binary').copy(ret, 265, 0, 32);
        Buffer.from('root', 'binary').copy(ret, 297, 0, 32);

        // Windows Platforms, set mode to (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
        var m = require('fs').CHMOD_MODES;
        Buffer.from((m.S_IRUSR | m.S_IWUSR | m.S_IRGRP | m.S_IWGRP | m.S_IROTH | m.S_IWOTH).toString(8), 'binary').copy(ret, 100, 0, 8);
    }
    else
    {
        // POSIX platforms, set the UID/GID
        Buffer.from(stats.uid.toString(8), 'binary').copy(ret, 108, 0, 8); // uid
        Buffer.from(stats.gid.toString(8), 'binary').copy(ret, 116, 0, 8); // gid

        if (!uidtable[stats.uid]) { uidtable[stats.uid] = require('user-sessions').getUsername(stats.uid); }
        if (!gidtable[stats.gid]) { gidtable[stats.gid] = require('user-sessions').getGroupname(stats.gid); }

        Buffer.from(uidtable[stats.uid], 'binary').copy(ret, 265, 0, 32);
        Buffer.from(gidtable[stats.gid], 'binary').copy(ret, 297, 0, 32);

        // Set Mode
        Buffer.from(stats.mode.toString(8), 'binary').copy(ret, 100, 0, 8);
    }


    var checksum = 0;
    for (var i = 0; i < 8; ++i)
    {
        ret[148 + i] = 32; // Blank out the checksum, so we can calculate the checksum, then write it back
    }
    for (var i = 0; i < 512; ++i)
    {
        checksum += ret[i];
    }
    Buffer.from(checksum.toString(8), 'binary').copy(ret, 148, 0, 8); // Write the checksum
    return (ret);
}

function encodeFiles(files, basePath)
{
    var ret = new readable(
        {
            read: function read()
            {
                var bytesRead;
                var ok = true;
                if(this._fd == null)
                {
                    if (this.files.length > 0)
                    {
                        var name = this.files.shift();
                        var header = generateUstarHeader(name, this._basePath, this._uidTable, this._gidTable);
                        if (header.isFile) { this._fd = require('fs').openSync(name, 'rb'); }
                        ok = this.push(header);
                    }
                    else
                    {
                        this.pause();
                        this.push(null);
                        return;
                    }
                }
                while(this._fd != null && ok)
                {
                    bytesRead = require('fs').readSync(this._fd, this._buffer, 0, 512);
                    this._buffer.fill(0, bytesRead, 512);
                    if (bytesRead < 512)
                    {
                        require('fs').closeSync(this._fd);
                        this._fd = null;
                    }
                    ok = this.push(this._buffer);
                }
            }
        });
    ret.files = files;
    ret._basePath = basePath;
    ret._fd = null;
    ret._buffer = Buffer.alloc(512);
    ret._uidTable = {};
    ret._gidTable = {};
    return (ret);
}

function expandFolderPaths(folderPath, recurse, arr)
{
    var files = require('fs').readdirSync(folderPath);
    for(var f in files)
    {
        if(require('fs').statSync(folderPath + '/' + files[f]).isDirectory())
        {
            if (recurse)
            {
                arr.push(folderPath + '/' + files[f]);
                expandFolderPaths(folderPath + '/' + files[f], recurse, arr);
            }
        }
        else
        {
            arr.push(folderPath + '/' + files[f]);
        }
    }
}

function encodeFolder(folderPath, recurse)
{
    var files = [];
    expandFolderPaths(folderPath, recurse, files);
    return (encodeFiles(files, folderPath));
}

function showHeader(path, offset)
{
    do
    {
        var b = loadUstarHeader(path, offset);
        if (b == null) { break; }
        if (offset != null && isNaN(offset)) { process.exit();}
        console.log('-----------------------------');
        console.log('THIS Offset: ' + (offset == null ? 0 : offset));
        var mtime = parseInt(b.slice(136, 136 + 12).toString(), 8) * 1000;
        console.log('name: ' + b.slice(0, 100).toString());
        console.log('size: ' + parseInt(b.slice(124, 124 + 12).toString(), 8));
        console.log('mtime: ' + (new Date(mtime)).toString());
        console.log('type: ' + String.fromCharCode(b[156]));
        console.log('linkname: ' + b.slice(157, 257).toString());
        console.log('magic: ' + b.slice(257, 257 + 6).toString());
        console.log('version: ' + b.slice(263, 265).toString('hex'));
        console.log('uname: ' + b.slice(265, 265 + 32).toString());
        console.log('uid: ' + parseInt(b.slice(108, 108 + 8).toString(), 8));
        console.log('gname: ' + b.slice(297, 297 + 32).toString());
        console.log('gid: ' + parseInt(b.slice(116, 116 + 8).toString(), 8));
        console.log('prefix: ' + b.slice(345, 345 + 155).toString());
        console.log('mode: ' + b.slice(100, 100 + 8).toString());
        console.log('checksum: ' + parseInt(b.slice(148, 148 + 8).toString(), 8).toString());

        // Calculate Checksum
        for (var i = 0; i < 8; ++i)
        {
            b[148 + i] = 32;
        }

        var v = 0;
        for (var i = 0; i < 512; ++i)
        {
            v += b[i];
        }

        v = (new Uint32Array([v]))[0]
        console.log('Computed Checksum: ' + v.toString());
        console.log('');
        if (String.fromCharCode(b[156]) == '5')
        {
            if(offset == null)
            {
                offset = 512;
            }
            else
            {
                offset += 512;
            }
        }
        else
        {
            var filesize = parseInt(b.slice(124, 124 + 12).toString(), 8);
            var recordskip = Math.floor(filesize / 512);
            if (filesize % 512 != 0) { ++recordskip; }
            if (offset == null)
            {
                offset = recordskip * 512;
            }
            else
            {
                offset += (recordskip * 512);
            }
            offset += 512;
        }
    } while (offset != null);
}

module.exports = { encodeFolder: encodeFolder, encodeFiles: encodeFiles, showHeader: showHeader };
