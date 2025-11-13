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
var DDR = 134695760;

var duplex = require('stream').Duplex;

function convertToMSDOSTime(datetimestring)
{
    // '2020-06-17T20:58:29Z';

    var datepart = datetimestring.split('T')[0].split('-');
    dt = (parseInt(datepart[0]) - 1980) << 9;
    dt |= (parseInt(datepart[1]) << 5);
    dt |= (parseInt(datepart[2]));

    var timepart = datetimestring.split('T')[1].split(':');
    var tmp = (parseInt(timepart[0]) << 11);
    tmp |= (parseInt(timepart[1]) << 5);
    tmp |= (parseInt(timepart[2].split('Z')[0]) / 2);

    return ({ date: dt, time: tmp });
}

function getBaseFolder(val)
{
    var test = []
    var D = process.platform == 'win32' ? '\\' : '/';
    var base = '';
    var tmp;
    var i;
    var ok;

    for (i = 0; i < val.length; ++i)
    {
        if (process.platform == 'win32')
        {
            test.push(val[i].split('/').join('\\').split(D));
        }
        else
        {
            test.push(val[i].split(D));
        }
    }

    if (val.length == 1)
    {
        if (test[0].length == 1) { return (''); }
        test[0].pop();
        return (test.join(D) + D);
    }

    while (true)
    {
        ok = true;
        for (i = 0; i < val.length; ++i)
        {
            if (i == 0)
            {
                tmp = test[i].shift();
            }
            else
            {
                if (tmp != test[i].shift())
                {
                    ok = false;
                    break;
                }
            }
        }
        if (ok)
        {
            base += (base == '' ? tmp : (D + tmp));
        }
        else
        {
            break;
        }
    }

    return (base == '' ? '' : (base + D));
}

function finished(options)
{
    console.info1('Writing Central Directory Records...');
    var pos;
    var CD;
    var namelen;

    this._pendingCDR = [];
    this._CDRSize = 0;

    // Write the Central Directory Headers
    for(pos in options._localFileTable)
    {
        namelen = options._localFileTable[pos].readUInt32LE(26);
        CD = Buffer.alloc(46 + namelen);
        this._CDRSize += (46 + namelen);

        options._localFileTable[pos].copy(CD, 46, 30, 30 + namelen);
        options._localFileTable[pos].copy(CD, 16, 14, 14 + 12);
        options._localFileTable[pos].copy(CD, 12, 10, 14);

        CD.writeUInt32LE(CDR, 0);               // Signature
        CD.writeUInt16LE(20, 4);                // Version
        CD.writeUInt16LE(20, 6);                // Minimum
        CD.writeUInt16LE(0x08 | 2048, 8);       // General Purpose Bit Flag
        CD.writeUInt16LE(8, 10);                // Compression Method

        CD.writeUInt16LE(namelen, 28);          // File Name Length

        CD.writeUInt16LE(1, 36);                // Internal Attributes
        CD.writeUInt32LE(32, 38);               // External Attributes

        CD.writeUInt32LE(parseInt(pos), 42);    // Relative Offset

        console.info1('   Record:');
        console.info1('      FileName: ' + CD.slice(46).toString());
        console.info1('      Compressed Size: ' + CD.readUInt32LE(20));
        console.info1('      Uncompressed Size: ' + CD.readUInt32LE(24));
        console.info1('      Last Modified Time: ' + CD.readUInt16LE(12));
        console.info1('      Last Modified Date: ' + CD.readUInt16LE(14));
        console.info1('      Local Record Offset: ' + CD.readUInt32LE(42));

        this._pendingCDR.unshift(CD);
    }
    this._NumberOfCDR = this._pendingCDR.length;
    this._CDRPosition = this._currentPosition;
    
    this.write(this._pendingCDR.pop(), this._writeCDR);
}

function next(options)
{
    if (!options) { options = this.options; }

    // this = zip-stream
    while (options.files.length > 0 && !require('fs').existsSync(options.files.peek())) { options.files.pop(); }
    if (options.files.length == 0) { finished.call(this, options); return; }
    var fstat = require('fs').statSync(options.files.peek());

    this._currentFile = options.files.peek();
    this._currentFD = require('fs').openSync(this._currentFile, require('fs').constants.O_RDONLY);
    this._currentName = this._currentFile.substring(options._baseFolder.length);
    this._currentFileLength = fstat.size;
    this._currentFileReadBytes = 0;
    this._currentCRC = 0;
    this._compressedBytes = 0;
    this._timestamp = convertToMSDOSTime(fstat.mtime);
    if (!this._ubuffer) { this._ubuffer = Buffer.alloc(4096); }
    var nameBuffer = Buffer.from(this._currentName);
    this._header = Buffer.alloc(30 + nameBuffer.length);

    this._header.writeUInt32LE(LFR, 0);                             // Signature
    this._header.writeUInt16LE(0x08 | 2048, 6);                     // General Purpose Bit Flag
    this._header.writeUInt16LE(8, 8);                               // Compression Method

    this._header.writeUInt16LE(this._timestamp.time, 10);           // File Last Modification Time
    this._header.writeUInt16LE(this._timestamp.date, 12);           // File Last Modification Date

    this._header.writeUInt32LE(this._currentFileLength, 22);        // Uncompressed size
    this._header.writeUInt16LE(nameBuffer.length, 26);              // File name length
    nameBuffer.copy(this._header, 30);                              // File name
    options._localFileTable[this._currentPosition] = this._header;

    this.write(this._header);
    this._compressor = require('compressed-stream').createCompressor({ WBITS: -15 });
    this._compressor.compressedBytes = this._currentPosition;
    this._compressor.parent = this;
    this._compressor.pipe(this, { end: false });
    require('fs').read(this._currentFD, { buffer: this._ubuffer }, this._uncompressedReadSink);
}

function checkFiles(files)
{
    var checked = [];
    var tmp;
    var s, j;

    for(var i in files)
    {
        s = require('fs').statSync(files[i]);
        if(s.isFile())
        {
            checked.push(files[i]);
        }
        else if (s.isDirectory())
        {
            tmp = require('fs').readdirSync(files[i]);
            for (j in tmp)
            {
                tmp[j] = files[i] + (process.platform == 'win32' ? '\\' : '/') + tmp[j];
            }
            tmp = checkFiles(tmp);
            for(j in tmp)
            {
                checked.push(tmp[j]);
            }
        }
    }
    return (checked);
}

function write(options)
{
    if (!options.files || options.files.length == 0) { throw ('No file specified'); }

    // Check if any folders were specified
    options.files = checkFiles(options.files);

    var ret = new duplex(
        {
            write: function (chunk, flush)
            {
                this._currentPosition += chunk.length;
                if (this._pushOK)
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
            read(size)
            {
                this._pushOK = true;
                while (this._pendingData.length > 0 && (this._pushOK = this.push(this._pendingData.shift())));
                if (this._pushOK)
                {
                    if (this._flush)
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
    require('events').EventEmitter.call(ret, true)
        .createEvent('progress')
        .createEvent('cancel')
        .addMethod('cancel', function(callback)
        {
            this._cancel = true;
            if(callback!=null) { this.once('cancel', callback); }
        });
    ret._currentPosition = 0;
    ret._ObjectID = 'zip-writer.duplexStream';
    ret.bufferMode = 1;
    ret.options = options;
    ret._pendingData = [];
    ret._pushOK = false;
    ret._ended = false;
    ret._flush = null;
    ret.pause();

    options._localFileTable = {};
    options._baseFolder = (options.basePath == null ? getBaseFolder(options.files) : options.basePath);
    if (options._baseFolder != '')
    {
        if (!options._baseFolder.endsWith(process.platform == 'win32' ? '\\' : '/')) { options._baseFolder += (process.platform == 'win32' ? '\\' : '/'); }
    }
    ret._uncompressedReadSink = function _uncompressedReadSink(err, bytesRead, buffer)
    {
        var self = _uncompressedReadSink.self;
        if(self._cancel)
        {
            self._compressor.end();
            self._compressor.unpipe();
            try
            {
                require('fs').closeSync(self._currentFD);
            }
            catch(e)
            {}

            self.options.files.length = 0;
            self.emit('cancel');
            self.end();
            return;
        }
        if(bytesRead == 0)
        {
            // DONE
            self._compressor.end();
            self._compressor.unpipe();

            self._header.writeUInt32LE(self._currentCRC, 14);                             // Uncompressed CRC
            self._header.writeUInt32LE(self._currentPosition - self._compressor.compressedBytes, 18); // Compresed Size
            self._header.writeUInt32LE(self._currentFileLength, 22);                      // Uncompressed Size
            require('fs').closeSync(self._currentFD);
            self.options.files.pop();
            self.write(self._header.slice(14, 26), next);
            return;
        }

        self._currentFileReadBytes += bytesRead;
        var ratio = self._currentFileReadBytes / self._currentFileLength;
        ratio = Math.floor(ratio * 100);
        self.emit('progress', self._currentFile, ratio);

        buffer = buffer.slice(0, bytesRead);
        self._currentCRC = crc32(buffer, self._currentCRC); // Update CRC
        self._compressor.write(buffer, function ()
        {
            require('fs').read(self._currentFD, { buffer: self._ubuffer }, self._uncompressedReadSink);
        });
    };
    ret._uncompressedReadSink.self = ret;

    ret._writeCDR = function _writeCDR(err, bytesRead, buffer)
    {
        if(this._pendingCDR.length>0)
        {
            this.write(this._pendingCDR.pop(), this._writeCDR);
            return;
        }
        else
        {
            console.info1('Write End of Central Directory');
            var ecdr = Buffer.alloc(22);
            ecdr.writeUInt32LE(EOCDR, 0);               // Signature
            ecdr.writeUInt16LE(this._NumberOfCDR, 8);   // Number of CD Records on this disk
            ecdr.writeUInt16LE(this._NumberOfCDR, 10);  // Total number of CD Records
            ecdr.writeUInt32LE(this._CDRSize, 12);      // Size of CD Records in bytes
            ecdr.writeUInt32LE(this._CDRPosition, 16);  // Offset start of CDR
            this.write(ecdr, function ()
            {
                this.end();
            });
        }
    };

    next.call(ret, options);
    return (ret);
}


module.exports = { write: write };
