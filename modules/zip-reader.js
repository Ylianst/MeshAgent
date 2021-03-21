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
var EOCDR = 101010256;
var CDR = 33639248;
var LFR = 67324752;

var promise = require('promise');
var duplex = require('stream').Duplex;

function checkFolderPath(dest)
{
    if (process.platform == 'win32')
    {
        dest = dest.split('/').join('\\');
    }
    else
    {
        dest = dest.split('\\').join('/');
    }
    var tokens = dest.split(process.platform == 'win32' ? '\\' : '/');
    
    var base = tokens.shift();
    while(tokens.length > 1)
    {
        base += ((process.platform == 'win32' ? '\\' : '/') + tokens.shift());
        if(!require('fs').existsSync(base))
        {
            require('fs').mkdirSync(base);
        }
    }
}
function extractNext(p)
{
    if (p._stream) { p._stream.unpipe(); }
    if (p.pending.length == 0)
    {
        p.source.close();
        p.source = null;
        p._output = null;
        p._stream = null;
        p._res();
        return;
    }
    var next = p.pending.pop();
    var dest = p.baseFolder + (process.platform == 'win32' ? '\\' : '/') + next;
    if (process.platform == 'win32')
    {
        dest = dest.split('/').join('\\');
    }
    else
    {
        dest = dest.split('\\').join('/');
    }
    console.info1('Extracting: ' + dest);
    try
    {
        checkFolderPath(dest);
    }
    catch(e)
    {
        p.source.close();
        p._rej(e);
        return;
    }

    var wp = WeakReference(p);
    p = null;

    wp.object._stream = wp.object.source.getStream(next);
    wp.object._output = require('fs').createWriteStream(dest, { flags: 'wb' });
    require('events').setFinalizerMetadata.call(wp.object._output, next);
    wp.object._output.name = next;
    wp.object._output.promise = wp;
    wp.object._output.once('close', function ()
    {
        if (this.promise.object._stream.crc != this.promise.object.source.crc(this.name))
        {
            this.promise.object._rej('CRC Check failed');
            return;
        }
        extractNext(this.promise.object);
    });
    wp.object._stream.pipe(wp.object._output);
}

function zippedObject(table)
{
    this._ObjectID = 'zip-reader.zippedObject';
    this._table = table;
    for (var jx in table)
    {
        this._FD = table[jx].fd;
        break;
    }
    Object.defineProperty(this, 'files', {
        get: function ()
        {
            var ret = [];
            var i;
            for(i in this._table)
            {
                ret.push(this._table[i].name);
            }
            return (ret);
        }
    });
    this.crc = function crc(name)
    {
        return (this._table[name].crc);
    };
    this.getStream = function getStream(name)
    {
        var info = this._table[name];
        if (!info) { throw ('not found'); }

        var ret;

        if (info.compression == 0)
        {
            console.info1('No Compression!');
            ret = new duplex(
            {
                write: function (chunk, flush)
                {
                    console.info1('Pass/Thru: ' + chunk.length + ' bytes');
                    this.crc = crc32(chunk, this.crc);
                    if(this._pushOK)
                    {
                        this._pushOK = this.push(chunk);
                        if (this._pushOK)
                        {
                            flush();
                            this._flush = null;
                        }
                        else
                        {
                            this._flush = flush;
                        }
                    }
                    else
                    {
                        this._pendingData.push(chunk);
                        this._flush = flush;
                    }
                },
                final: function (flush)
                {
                    if (this._pushOK)
                    {
                        this.push(null);
                        flush();
                    }
                    else
                    {
                        this._ended = true;
                    }
                },
                read: function (size)
                {
                    this._pushOK = true;
                    while (this._pendingData.length > 0 && (this._pushOK = this.push(this._pendingData.shift())));
                    if (this._pushOK)
                    {
                        if(this._flush)
                        {
                            this._flush(); 
                            this._flush = null;
                        }
                        else
                        {
                            this.emit('drain');
                        }
                    }
                    
                }
            });
            ret.bufferMode = 1;
            ret._pendingData = [];
            ret._pushOK = false;
            ret._ended = false;
            ret._flush = null;
            ret.crc = 0;
            ret.pause();
        }
        else
        {
            ret = require('compressed-stream').createDecompressor({ WBITS: -15 });
        }
        ret._info = info;
        ret._readSink = function _readSink(err, bytesRead, buffer)
        {
            console.info2('read ' + bytesRead + ' bytes [ERR: ' + err + ']', _readSink.self._bytesLeft);
            _readSink.self._bytesLeft -= bytesRead;
            _readSink.self.write(buffer.slice(0, bytesRead), function ()
            {
                // Done Writing, so read the next block
                if(this._bytesLeft == 0)
                {
                    console.info1('DONE Reading This record');
                    // No More Data
                    this.end();
                }
                else
                {
                    // More Data To Read
                    console.info2('Requesting More Data: ' + this._bytesLeft, this._ObjectID);
                    require('fs').read(this._info.fd, { buffer: this._buffer, length: this._bytesLeft > 4096 ? 4096 : this._bytesLeft },
                        this._readSink);
                }
            });
        };
        ret._readSink.self = ret;
        ret._localHeaderSink = function _localHeaderSink(err, bytesRead, buffer)
        {
            console.info1(buffer.readUInt32LE(0) == LFR);
            console.info1('General Purpose Flag: ' + buffer.readUInt16LE(6));
            console.info1('Compression Method: ' + buffer.readUInt16LE(8));
            console.info1('FileName Length: ' + buffer.readUInt16LE(26));
            console.info1('Extra Length: ' + buffer.readUInt16LE(28));
            _localHeaderSink.self._info.uncompressedCRC = buffer.readUInt32LE(14);

            console.info1('Requesting to read: ' + (_localHeaderSink.self._bytesLeft > 4096 ? 4096 : _localHeaderSink.self._bytesLeft) + ' bytes');

            require('fs').read(_localHeaderSink.self._info.fd,
                {
                    buffer: _localHeaderSink.self._buffer,
                    length: _localHeaderSink.self._bytesLeft > 4096 ? 4096 : _localHeaderSink.self._bytesLeft,
                    position: _localHeaderSink.self._info.offset + 30 + buffer.readUInt16LE(26) + buffer.readUInt16LE(28)
                }, _localHeaderSink.self._readSink);
        };
        ret._localHeaderSink.self = ret;
        ret.once('drain', function ()
        {
            this._bytesLeft = this._info.compressedSize;
            this._buffer = Buffer.alloc(4096);
            console.info1('Local Header @ ' + this._info.offset);
            console.info1(' -> Compressed Size = ' + this._bytesLeft);
            require('fs').read(this._info.fd, { buffer: Buffer.alloc(30), position: this._info.offset }, this._localHeaderSink);
        });
        return (ret);
    };
    this.extractAll = function extractAll(destFolder)
    {
        if (process.platform == 'win32')
        {
            if (!destFolder.includes(':\\')) { destFolder = process.cwd() + destFolder; }
        }
        else
        {
            if (!destFolder.startsWith('/')) { destFolder = process.cwd() + destFolder; }
        }

        var i;
        var ret = WeakReference(new promise(promise.defaultInit));
        ret.object._res = ret.object.resolve;
        ret.object._rej = ret.object.reject;

        ret.object.descriptorMetadata = 'extractAll.promise';
        if (destFolder.endsWith(process.platform == 'win32' ? '\\' : '/')) { destFolder = destFolder.substring(0, destFolder.length - 1); }
        ret.object.source = this;
        ret.object.baseFolder = destFolder;
        ret.object.pending = [];
        for (i in this.files)
        {
            ret.object.pending.push(this.files[i]);
        }

        extractNext(ret.object);
        return (ret.object);
    };
    this._extractAllStreams2 = function _extractAllStreams2(prom)
    {
        if (prom.files.length == 0)
        {
            // finished
            prom._res(prom.results);
            this.close();
            return;
        }
        prom.results.push({ name: prom.files.pop() });
        prom.results.peek().stream = this.getStream(prom.results.peek().name);
        prom.results.peek().stream.ret = prom;
        prom.results.peek().stream.on('data', function (c)
        {
            console.info2('DATA: ' + c.length);
            if (this._buf == null)
            {
                this._buf = Buffer.concat([c]);
            }
            else
            {
                this._buf = Buffer.concat([this._buf, c]);
            }
        });
        prom.results.peek().stream.on('end', function ()
        {
            console.info2('End of current stream');
            this.ret.results.peek().buffer = this._buf;
            this.ret.z._extractAllStreams2(this.ret);
        });
    };
    this.extractAllStreams = function extractAllStreams()
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.files = this.files;
        ret.results = [];
        ret.z = this;
        this._extractAllStreams2(ret);
        return (ret);
    };
    this._readLocalHeaderSink = function _readLocalHeaderSink(err, bytesRead, buffer)
    {
        var info = _readLocalHeaderSink.info;

        console.info1('Local File Record -> ');
        var filenameLength = buffer.readUInt32LE(26);
        console.info1('   General Purpose Flag: ' + buffer.readUInt16LE(6));
        console.info1('   CRC-32 of uncompressed data: ' + buffer.readUInt32LE(14));
        console.info1('   Compression Method: ' + buffer.readUInt16LE(8));
        console.info1('   Compressed Size: ' + buffer.readUInt32LE(18));
        console.info1('   Uncompressed Size: ' + buffer.readUInt32LE(22));
        console.info1('   Last Modification Time: ' + buffer.readUInt16LE(10));
        console.info1('   Last Modification Date: ' + buffer.readUInt16LE(12));
        console.info1('   Extra Field Length: ' + buffer.readUInt16LE(28));
        require('fs').read(info.fd, { buffer: Buffer.alloc(filenameLength) }, function (e, b, f)
        {
            console.info1('   File Name: ' + f.toString());
            require('fs').read(info.fd, { buffer: Buffer.alloc(10) }, function (e2, b2, f2)
            {
                console.info1('   Compressed Data Sample: ' + f2.toString('hex'));
            });
        });
    };
    this._readLocalHeaderSink.self = this;
    this.readLocalHeader = function readLocalHeader(name)
    {
        var info = this._table[name];
        this._readLocalHeaderSink.info = info;
        require('fs').read(info.fd, { buffer: Buffer.alloc(30), position: info.offset }, this._readLocalHeaderSink);
    };

    this.close = function close()
    {
        if (this._FD != null)
        {
            require('fs').closeSync(this._FD);
            this._FD = null;
            this._table = null;
        }
    }
    require('events').EventEmitter.call(this);
    this.on('~', function () { this.close(); });
}

function read(path)
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    if (typeof (path) == 'string')
    {
        if (!require('fs').existsSync(path))
        {
            ret._rej('File not found');
            return (ret);
        }

        ret._len = require('fs').statSync(path).size;
        ret._fd = require('fs').openSync(path, require('fs').constants.O_RDONLY);
    }
    else
    {
        ret._len = path.length;
        ret._fd = { _ObjectID: 'fs.bufferDescriptor', buffer: path, position: 0 };
    }
    ret._cdr = function _cdr(err, bytesRead, buffer)
    {
        var table = {};
        while (buffer.length > 0)
        {
            if (buffer.readUInt32LE() != CDR) { _cdr.self._rej('Parse Error'); return; }
            var nameLength = buffer.readUInt16LE(28);
            var efLength = buffer.readUInt16LE(30);
            var comLength = buffer.readUInt16LE(32);
            var name = buffer.slice(46, 46 + nameLength).toString();

            console.info1('Central Directory Record:');
            console.info1('   Version: ' + buffer.readUInt16LE(4));
            console.info1('   Minimum: ' + buffer.readUInt16LE(6));
            console.info1('   Name: ' + name);
            console.info1('   CRC-32 of Uncompressed data: ' + buffer.readUInt32LE(16));
            console.info1('   Uncompressed Size: ' + buffer.readUInt32LE(24));
            console.info1('   Compressed Size: ' + buffer.readUInt32LE(20));
            console.info1('   File Last Modification Time: ' + buffer.readUInt16LE(12));
            console.info1('   File Last Modification Date: ' + buffer.readUInt16LE(14));
            console.info1('   Internal Attributes: ' + buffer.readUInt16LE(36));
            console.info1('   External Attributes: ' + buffer.readUInt32LE(38));
            console.info1('   Local Header at: ' + buffer.readUInt32LE(42));
            
            if (buffer.readUInt32LE(16) != 0)
            {
                table[name] =
                    {
                        name: name,
                        compressedSize: buffer.readUInt32LE(20),
                        uncompressedSize: buffer.readUInt32LE(24),
                        offset: buffer.readUInt32LE(42),
                        fd: _cdr.self._fd,
                        compression: buffer.readUInt16LE(10),
                        crc: buffer.readUInt32LE(16)
                    };
            }
            buffer = buffer.slice(46 + nameLength + efLength + comLength);
        }

        _cdr.self._res(new zippedObject(table));
    };
    ret._eocdr = function _eocdr(err, bytesRead, buffer)
    {
        var record;
        var i;

        for (i = 20; i < buffer.length; ++i)
        {
            if ((record = buffer.slice(buffer.length - i)).readUInt32LE() == EOCDR)
            {
                console.info1('Found Start of ECD Record ' + i + ' bytes from end of file');
                console.info1('-------------------------');
                console.info1('  Disk #: ' + record.readUInt16LE(4));
                console.info1('  Number of Central Directory Records on this disc: ' + record.readUInt16LE(8));
                console.info1('  Total number of Central Directory Records: ' + record.readUInt16LE(10));
                console.info1('  Size of Central Directory: ' + record.readUInt32LE(12) + ' bytes');
                console.info1('  Central Directory Records should be at offset: ' + record.readUInt32LE(16));

                require('fs').read(_eocdr.self._fd, { buffer: Buffer.alloc(record.readUInt32LE(12)), position: record.readUInt32LE(16) }, _eocdr.self._cdr);
                break;
            }
        }

    };
    ret._cdr.self = ret;
    ret._eocdr.self = ret;
    require('fs').read(ret._fd, { buffer: Buffer.alloc(100), position: ret._len - 100 }, ret._eocdr);
    return(ret);
}

function isZip(path)
{
    if (require('fs').statSync(path).size < 30) { return (false); }
    var fd = require('fs').openSync(path, 'rb');
    var jsFile = Buffer.alloc(4);
    var bytesRead = require('fs').readSync(fd, jsFile, { position: 0 });
    require('fs').closeSync(fd);

    if (bytesRead == 4 && jsFile[0] == 0x50 && jsFile[1] == 0x4B && jsFile[2] == 0x03 && jsFile[3] == 0x04)
    {
        return (true);
    }
    return (false);
}

module.exports = { read: read, isZip: isZip };