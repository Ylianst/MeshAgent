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
    if (process.platform == 'win32') { dest = dest.split('/').join('\\'); }
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
    if (p.pending.length == 0) { p._res(); return; }
    var next = p.pending.pop();
    var dest = p.baseFolder + (process.platform == 'win32' ? '\\' : '/') + next;
    if (process.platform == 'win32') { dest = dest.split('/').join('\\'); }
    console.info1('Extracting: ' + dest);
    try
    {
        checkFolderPath(dest);
    }
    catch(e)
    {
        p._rej(e);
        return;
    }

    p._stream = p.source.getStream(next);
    p._output = require('fs').createWriteStream(dest, { flags: 'wb' });
    p._output.name = next;
    p._output.promise = p;
    p._output.on('close', function ()
    {
        if (this.promise._stream.crc != this.promise.source.crc(this.name))
        {
            this.promise._rej('CRC Check failed');
            return;
        }
        extractNext(this.promise);
    });
    p._stream.pipe(p._output);
}

function zippedObject(table)
{
    this._ObjectID = 'zip-reader.zippedObject';
    this._table = table;
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
            ret = require('compressed-stream').createDecompressor(1);
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
            require('fs').read(this._info.fd, { buffer: Buffer.alloc(30), position: this._info.offset }, this._localHeaderSink);
        });
        return (ret);
    };
    this.extractAll = function extractAll(destFolder)
    {
        var i;
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        if (destFolder.endsWith(process.platform == 'win32' ? '\\' : '/')) { destFolder = destFolder.substring(0, destFolder.length - 1); }
        ret.source = this;
        ret.baseFolder = destFolder;
        ret.pending = [];
        for (i in this.files)
        {
            ret.pending.push(this.files[i]);
        }

        extractNext(ret);
        return (ret);
    }
}

function read(path)
{
    var ret = new promise(function(res,rej){this._res = res; this._rej = rej;});
    if (!require('fs').existsSync(path))
    {
        ret._rej('File not found');
        return (ret);
    }
    ret._len = require('fs').statSync(path).size;
    ret._fd = require('fs').openSync(path, require('fs').constants.O_RDONLY);
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

            table[name] = { name: name, compressedSize: buffer.readUInt32LE(20), offset: buffer.readUInt32LE(42), fd: _cdr.self._fd, compression: buffer.readUInt16LE(10), crc: buffer.readUInt32LE(16) };
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

module.exports = { read: read };