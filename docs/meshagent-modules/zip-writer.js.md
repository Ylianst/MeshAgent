# zip-writer.js

Cross-platform ZIP archive creation module providing streaming compression of files and directories into standard ZIP format. Supports recursive directory traversal, deflate compression, progress tracking, and cancellation with full ZIP specification compliance including CRC32 validation and Central Directory generation.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support with backslash path handling
- Linux - Full support with forward slash path handling
- macOS (darwin) - Full support with forward slash path handling
- FreeBSD - Full support with forward slash path handling

## Functionality

### Purpose

The zip-writer module creates ZIP archives from files and directories with:

- **Streaming Output** - Memory-efficient duplex stream for ZIP data
- **Compression** - Deflate compression (ZIP method 8)
- **Directory Support** - Recursive directory traversal
- **Progress Tracking** - Per-file progress events
- **Cancellation** - Abort ZIP creation in progress
- **CRC32 Validation** - Automatic checksum calculation
- **Platform Paths** - Automatic path normalization for ZIP entries
- **Base Path Handling** - Common base path detection and removal

This module is used for:
- Creating update packages
- Module distribution
- Backup archives
- Data transfer packaging

### ZIP Creation Flow

When `write(options)` is called:

1. **Validation Phase (line 223):**
   - Ensures files array is provided and non-empty

2. **File Discovery Phase (lines 191-219):**
   - Recursively scans directories
   - Filters for existing files only
   - Builds complete file list

3. **Base Path Detection (lines 300-305):**
   - Calculates common base path across all files
   - Removes base path from ZIP entry names

4. **Compression Phase (lines 150-189):**
   - For each file sequentially:
     - Creates Local File Header
     - Compresses file data via deflate stream
     - Calculates CRC32 checksum
     - Emits progress events
     - Updates header with final sizes/CRC

5. **Finalization Phase (lines 100-148):**
   - Writes Central Directory Records
   - Writes End of Central Directory Record
   - Ends stream

### Key Functions

#### write(options) - Lines 221-379

**Purpose:** Creates a duplex stream that generates a ZIP archive from files.

**Parameters:**
- `options` (object):
  - `files` (array, required) - Array of file/directory paths to include
  - `basePath` (string, optional) - Base path to remove from ZIP entry names

**Process:**

**1. File Collection (lines 223-226):**
```javascript
if (!options.files || options.files.length == 0) {
    throw ('No file specified');
}
options.files = checkFiles(options.files);
```

Validates input and expands directories to file lists.

**2. Stream Creation (lines 228-289):**
```javascript
var ret = new duplex({
    write: function (chunk, flush) {
        this._currentPosition += chunk.length;
        if (this._pushOK) {
            this._pushOK = this.push(chunk);
            if (this._pushOK) {
                flush();
            } else {
                this._flush = flush;
            }
        } else {
            this._pendingData.push(chunk);
            this._flush = flush;
        }
    },
    read(size) {
        this._pushOK = true;
        while (this._pendingData.length > 0 && (this._pushOK = this.push(this._pendingData.shift())));
        if (this._pushOK && this._flush) {
            this._flush();
            this._flush = null;
        }
    }
});
```

Creates duplex stream with backpressure handling:
- `write()` - Accepts compressed data, manages backpressure
- `read()` - Pushes buffered data to consumer

**3. Event Setup (lines 282-289):**
```javascript
require('events').EventEmitter.call(ret, true)
    .createEvent('progress')
    .createEvent('cancel')
    .addMethod('cancel', function(callback) {
        this._cancel = true;
        if(callback!=null) { this.once('cancel', callback); }
    });
```

Adds progress tracking and cancellation capability.

**4. Base Path Detection (lines 300-305):**
```javascript
options._baseFolder = (options.basePath == null ? getBaseFolder(options.files) : options.basePath);
```

Automatically detects common base path if not provided.

**5. File Processing Loop (lines 306-351):**
```javascript
ret._uncompressedReadSink = function(err, bytesRead, buffer) {
    if(self._cancel) {
        // Handle cancellation
        self._compressor.end();
        self.emit('cancel');
        self.end();
        return;
    }

    if(bytesRead == 0) {
        // File complete
        self._header.writeUInt32LE(self._currentCRC, 14);      // CRC
        self._header.writeUInt32LE(compressedSize, 18);       // Compressed size
        self._header.writeUInt32LE(uncompressedSize, 22);     // Uncompressed size
        self.options.files.pop();
        self.write(updatedHeader, next);  // Move to next file
        return;
    }

    // Read chunk, update CRC, compress
    self._currentCRC = crc32(buffer, self._currentCRC);
    self.emit('progress', self._currentFile, percentComplete);
    self._compressor.write(buffer, function() {
        // Read next chunk
        require('fs').read(fd, {buffer}, readSink);
    });
};
```

Processes each file:
- Reads uncompressed data in chunks
- Calculates CRC32
- Compresses via deflate
- Tracks progress
- Handles cancellation

**Return Value:**
- Duplex stream that outputs ZIP archive data
- Stream has additional methods/events:
  - `cancel(callback)` - Abort ZIP creation
  - `progress` event - Per-file progress updates

**Usage Example:**
```javascript
var zipStream = require('zip-writer').write({
    files: ['/path/to/file1.txt', '/path/to/dir', '/path/to/file2.txt'],
    basePath: '/path/to'
});

zipStream.on('progress', function(filename, percent) {
    console.log(filename + ': ' + percent + '%');
});

zipStream.pipe(require('fs').createWriteStream('output.zip'));
```

---

#### checkFiles(files) - Lines 191-219

**Purpose:** Recursively expands directories into file lists, filtering out directories from final list.

**Parameters:**
- `files` (array) - Array of file/directory paths

**Process:**
1. For each path in input array:
   - Check if file or directory via `fs.statSync()`
   - If file: Add to results
   - If directory:
     - Read directory contents via `fs.readdirSync()`
     - Prepend directory path to each entry
     - Recursively call `checkFiles()` on directory contents
     - Add all returned files to results
2. Return flattened list of files only

**Return Value:**
- Array of file paths (directories excluded)

**Example:**
```javascript
Input:  ['/opt/mesh/file.txt', '/opt/mesh/subdir']
Output: ['/opt/mesh/file.txt', '/opt/mesh/subdir/a.js', '/opt/mesh/subdir/b.js']
```

---

#### getBaseFolder(val) - Lines 41-98

**Purpose:** Calculates the common base path shared by all files in an array.

**Parameters:**
- `val` (array) - Array of file paths

**Process:**

**1. Path Splitting (lines 50-60):**
```javascript
for (i = 0; i < val.length; ++i) {
    test.push(val[i].split(D));  // Split by platform delimiter
}
```

Splits all paths into arrays of components.

**2. Common Prefix Detection (lines 69-95):**
```javascript
while (true) {
    ok = true;
    for (i = 0; i < val.length; ++i) {
        if (i == 0) {
            tmp = test[i].shift();
        } else {
            if (tmp != test[i].shift()) {
                ok = false;
                break;
            }
        }
    }
    if (ok) {
        base += (base == '' ? tmp : (D + tmp));
    } else {
        break;
    }
}
```

Iteratively compares first component of each path:
- If all paths have same component, add to base
- If any path differs, stop
- Return common base path

**Return Value:**
- Common base path string with trailing delimiter
- Empty string if no common base

**Examples:**
```javascript
['/opt/mesh/file1.txt', '/opt/mesh/file2.txt']     → '/opt/mesh/'
['/opt/mesh/a/f1.txt', '/opt/mesh/b/f2.txt']       → '/opt/mesh/'
['/opt/mesh/file.txt', '/var/log/app.log']         → ''  (no common base)
```

---

#### next(options) - Lines 150-189

**Purpose:** Processes the next file in the queue, creating its Local File Header and compressing content.

**Parameters:**
- `options` (object) - ZIP creation options (attached as `this.options`)

**Process:**

**1. File Validation (lines 155-156):**
```javascript
while (options.files.length > 0 && !require('fs').existsSync(options.files.peek())) {
    options.files.pop();
}
```

Skips non-existent files (may have been deleted during operation).

**2. Completion Check (line 156):**
```javascript
if (options.files.length == 0) {
    finished.call(this, options);
    return;
}
```

If all files processed, moves to finalization phase.

**3. File Metadata Collection (lines 157-167):**
```javascript
var fstat = require('fs').statSync(options.files.peek());
this._currentFile = options.files.peek();
this._currentFD = require('fs').openSync(this._currentFile, O_RDONLY);
this._currentName = this._currentFile.substring(options._baseFolder.length);
this._currentFileLength = fstat.size;
this._timestamp = convertToMSDOSTime(fstat.mtime);
```

Gets file metadata and calculates ZIP entry name.

**4. Local File Header Creation (lines 169-181):**
```javascript
this._header = Buffer.alloc(30 + nameBuffer.length);

this._header.writeUInt32LE(LFR, 0);                      // Signature
this._header.writeUInt16LE(0x08 | 2048, 6);              // General Purpose Flag
this._header.writeUInt16LE(8, 8);                        // Compression Method (deflate)
this._header.writeUInt16LE(this._timestamp.time, 10);    // Mod Time
this._header.writeUInt16LE(this._timestamp.date, 12);    // Mod Date
this._header.writeUInt32LE(this._currentFileLength, 22); // Uncompressed size
this._header.writeUInt16LE(nameBuffer.length, 26);       // Filename length
nameBuffer.copy(this._header, 30);                       // Filename
```

Creates ZIP Local File Header with metadata.

**5. Compression Setup (lines 183-188):**
```javascript
this.write(this._header);
this._compressor = require('compressed-stream').createCompressor({ WBITS: -15 });
this._compressor.pipe(this, { end: false });
require('fs').read(this._currentFD, { buffer: this._ubuffer }, this._uncompressedReadSink);
```

Writes header, creates deflate compressor, begins reading file.

---

#### finished(options) - Lines 100-148

**Purpose:** Writes Central Directory Records and End of Central Directory Record to complete ZIP file.

**Process:**

**1. Central Directory Record Creation (lines 111-143):**
```javascript
for(pos in options._localFileTable) {
    CD = Buffer.alloc(46 + namelen);

    // Copy data from Local File Header
    localHeader.copy(CD, 46, 30, 30 + namelen);  // Filename
    localHeader.copy(CD, 16, 14, 26);            // CRC, sizes, timestamp

    CD.writeUInt32LE(CDR, 0);                    // Signature
    CD.writeUInt16LE(20, 4);                     // Version made by
    CD.writeUInt16LE(20, 6);                     // Version needed
    CD.writeUInt16LE(0x08 | 2048, 8);            // General Purpose Flag
    CD.writeUInt16LE(8, 10);                     // Compression Method
    CD.writeUInt32LE(parseInt(pos), 42);         // Local Header offset

    this._pendingCDR.unshift(CD);
}
```

Creates Central Directory Record for each file, storing metadata and Local Header offset.

**2. Central Directory Writing (line 147):**
```javascript
this.write(this._pendingCDR.pop(), this._writeCDR);
```

Begins writing Central Directory Records sequentially.

**3. End of Central Directory (lines 363-373):**
```javascript
var ecdr = Buffer.alloc(22);
ecdr.writeUInt32LE(EOCDR, 0);                    // Signature
ecdr.writeUInt16LE(this._NumberOfCDR, 8);        // Number of CDR
ecdr.writeUInt16LE(this._NumberOfCDR, 10);       // Total CDR
ecdr.writeUInt32LE(this._CDRSize, 12);           // CDR size in bytes
ecdr.writeUInt32LE(this._CDRPosition, 16);       // CDR offset
this.write(ecdr, function() {
    this.end();
});
```

Writes final EOCDR and ends stream.

---

#### convertToMSDOSTime(datetimestring) - Lines 24-39

**Purpose:** Converts ISO 8601 timestamp to MS-DOS date/time format used in ZIP files.

**Parameters:**
- `datetimestring` (string) - ISO 8601 format: `'2020-06-17T20:58:29Z'`

**Process:**
```javascript
var datepart = datetimestring.split('T')[0].split('-');
dt = (parseInt(datepart[0]) - 1980) << 9;  // Year (since 1980)
dt |= (parseInt(datepart[1]) << 5);        // Month
dt |= (parseInt(datepart[2]));             // Day

var timepart = datetimestring.split('T')[1].split(':');
tmp = (parseInt(timepart[0]) << 11);       // Hour
tmp |= (parseInt(timepart[1]) << 5);       // Minute
tmp |= (parseInt(timepart[2].split('Z')[0]) / 2);  // Second / 2
```

Encodes date/time into 16-bit MS-DOS format.

**Return Value:**
- Object: `{date: dateValue, time: timeValue}`
- Both values are 16-bit integers in MS-DOS format

---

### Dependencies

#### Node.js Core Modules
- `fs` (lines 39, 41, 155, 157, 160, 199, 206, 334, 349) - File system operations:
  - `statSync()` - Get file metadata
  - `existsSync()` - Check file existence
  - `openSync()` - Open file descriptor
  - `closeSync()` - Close file descriptor
  - `readdirSync()` - Read directory contents
  - `read()` - Read file chunks
- `stream.Duplex` (line 22) - Duplex stream base class

#### MeshAgent Module Dependencies

**Core Required Modules:**

- **`compressed-stream`** (line 184)
  - Compression/decompression streams
  - Method: `createCompressor({WBITS: -15})`
  - WBITS: -15 indicates raw deflate (no zlib header)
  - Pipes compressed data to ZIP stream

#### Global Functions

- **`crc32(buffer, previousCRC)`** (line 346)
  - CRC32 checksum calculation
  - Incrementally updates CRC with each chunk
  - Not defined in this module (assumed global or required elsewhere)

#### Global Constants (lines 17-20)

```javascript
var EOCDR = 101010256;  // 0x06054b50 - End of Central Directory Record
var CDR = 33639248;     // 0x02014b50 - Central Directory Record
var LFR = 67324752;     // 0x04034b50 - Local File Record
var DDR = 134695760;    // 0x08074b50 - Data Descriptor Record (unused)
```

### Technical Notes

**ZIP Format Structure:**

The module creates standard ZIP files in this order:
1. For each file:
   - Local File Header (30 bytes + filename)
   - Compressed file data
2. Central Directory:
   - Central Directory Record per file (46 bytes + filename)
3. End of Central Directory Record (22 bytes)

**Compression Method:**

Uses deflate compression (ZIP method 8):
```javascript
this._compressor = require('compressed-stream').createCompressor({ WBITS: -15 });
```

WBITS: -15 creates raw deflate:
- No zlib header/footer
- 32KB sliding window (2^15)
- Standard ZIP compression

**General Purpose Flag:**

```javascript
0x08 | 2048
```

- Bit 3 (0x08): Data descriptor follows compressed data
- Bit 11 (2048): UTF-8 filename encoding

**MS-DOS Timestamp Format:**

Date (16 bits):
- Bits 0-4: Day (1-31)
- Bits 5-8: Month (1-12)
- Bits 9-15: Year (since 1980)

Time (16 bits):
- Bits 0-4: Seconds/2 (0-29)
- Bits 5-10: Minutes (0-59)
- Bits 11-15: Hours (0-23)

**Stream Backpressure:**

The duplex stream handles backpressure:
```javascript
if (this._pushOK) {
    this._pushOK = this.push(chunk);
    if (!this._pushOK) {
        this._flush = flush;  // Save flush callback
    }
} else {
    this._pendingData.push(chunk);  // Buffer data
}
```

When consumer is slow:
- Buffers compressed data in `_pendingData`
- Pauses compression until consumer catches up
- Prevents memory overflow

**Cancellation Mechanism:**

```javascript
ret._cancel = true;
```

Setting `_cancel` flag:
- Stops file reading
- Ends compressor
- Clears file queue
- Emits 'cancel' event
- Ends ZIP stream

**Progress Events:**

```javascript
var ratio = self._currentFileReadBytes / self._currentFileLength;
ratio = Math.floor(ratio * 100);
self.emit('progress', self._currentFile, ratio);
```

Emits per-file progress as percentage (0-100).

**Local File Header Updates:**

Headers are written before file data, but final sizes/CRC are unknown:
```javascript
// Initial header with placeholder values
this._header.writeUInt32LE(0, 14);  // CRC (placeholder)
this._header.writeUInt32LE(0, 18);  // Compressed size (placeholder)

// After compression completes, write updated header
this._header.writeUInt32LE(actualCRC, 14);
this._header.writeUInt32LE(actualCompressedSize, 18);
this.write(this._header.slice(14, 26), next);
```

This avoids needing to compress files twice (once for size, once for data).

**Central Directory as Index:**

The Central Directory stores:
- Filename
- Compression info
- CRC checksum
- Compressed/uncompressed sizes
- **Offset to Local File Header**

This allows ZIP readers to quickly locate and extract files without scanning entire archive.

**Platform Path Handling:**

```javascript
var D = process.platform == 'win32' ? '\\' : '/';
```

Uses platform-specific separators for file system operations, but ZIP entries always use forward slash (ZIP spec requires `/`).

## Summary

The zip-writer.js module creates standard ZIP archives for **Windows, Linux, macOS, and FreeBSD** with streaming compression, progress tracking, and cancellation capability. It supports deflate compression (ZIP method 8), recursive directory traversal, automatic base path detection, and CRC32 validation.

The module uses memory-efficient duplex streams to generate ZIP data on-the-fly without loading entire files into memory. It handles backpressure properly to prevent memory overflow when compressing faster than the consumer can process.

Key features include per-file progress events, cancellation support, automatic platform path normalization, and full ZIP specification compliance including proper Local File Headers, Central Directory Records, and End of Central Directory Record generation.

The module integrates with MeshAgent's compressed-stream module for deflate compression while remaining usable for general-purpose ZIP creation with comprehensive error handling and resource management.
