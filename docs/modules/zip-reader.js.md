# zip-reader.js

Cross-platform ZIP archive reading utility providing extraction, streaming, and file enumeration with CRC validation. Supports reading from both file paths and in-memory buffers, with promise-based async operations for reliability and error handling.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support
- macOS (darwin) - Full support
- FreeBSD - Full support

## Functionality

### Purpose

The zip-reader module provides comprehensive ZIP archive manipulation:

- **ZIP Detection** - Verify if a file is a valid ZIP archive
- **File Enumeration** - List contents of ZIP archives
- **Streaming Extraction** - Extract individual files as streams
- **Bulk Extraction** - Extract all files to destination folder
- **CRC Validation** - Verify file integrity during extraction
- **Decompression** - Handles both stored (uncompressed) and deflated files
- **Memory/File Support** - Read from file paths or in-memory buffers

This module is used for:
- Agent update packages (often distributed as ZIP)
- Module deployment
- Configuration archive extraction
- Compressed data transfer

### ZIP File Structure

The module parses standard ZIP file format:

1. **Local File Headers** (LFR) - Precede each compressed file
2. **File Data** - Compressed or stored file content
3. **Central Directory Records** (CDR) - File metadata index
4. **End of Central Directory** (EOCDR) - Archive terminator and index pointer

The module reads ZIP files by:
1. Finding EOCDR at end of file
2. Using EOCDR to locate Central Directory
3. Parsing Central Directory to build file table
4. Using file table to extract individual files

### Key Functions

#### isZip(path) - Lines 445-458

**Purpose:** Quickly determines if a file is a ZIP archive by checking magic bytes.

**Parameters:**
- `path` (string) - File path to check

**Process:**
1. Checks file size >= 30 bytes (minimum ZIP size)
2. Opens file in read-binary mode
3. Reads first 4 bytes
4. Checks for ZIP magic signature: `0x50 0x4B 0x03 0x04` ("PK\x03\x04")
5. Closes file
6. Returns true if signature matches

**Return Value:**
- `true` if file is ZIP archive
- `false` if not ZIP or file too small

**Magic Bytes:**
```
0x50 0x4B 0x03 0x04 = "PK" (Phil Katz) + LFR signature
```

---

#### read(path) - Lines 351-443

**Purpose:** Reads and parses a ZIP archive from file path or buffer, returning a promise that resolves with a `zippedObject`.

**Parameters:**
- `path` (string|Buffer) - File path or in-memory buffer containing ZIP data

**Process:**

**1. Setup (lines 353-369):**
```javascript
var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });

if (typeof (path) == 'string') {
    // File path
    ret._len = require('fs').statSync(path).size;
    ret._fd = require('fs').openSync(path, O_RDONLY);
} else {
    // Buffer
    ret._len = path.length;
    ret._fd = { _ObjectID: 'fs.bufferDescriptor', buffer: path, position: 0 };
}
```

Supports both file paths and in-memory buffers. For buffers, creates a fake file descriptor object.

**2. Find EOCDR (lines 416-441):**
```javascript
ret._eocdr = function _eocdr(err, bytesRead, buffer) {
    for (i = 20; i < buffer.length; ++i) {
        if (buffer.slice(buffer.length - i).readUInt32LE() == EOCDR) {
            // Found End of Central Directory Record
            // Read Central Directory size and offset
            var cdSize = record.readUInt32LE(12);
            var cdOffset = record.readUInt32LE(16);

            // Read Central Directory
            require('fs').read(fd, {buffer: Buffer.alloc(cdSize), position: cdOffset}, _cdr);
        }
    }
};
```

Searches last 100 bytes for EOCDR signature (0x06054b50).

**3. Parse Central Directory (lines 370-415):**
```javascript
ret._cdr = function _cdr(err, bytesRead, buffer) {
    var table = {};
    while (buffer.length > 0) {
        // Parse CDR entry
        var name = buffer.slice(46, 46 + nameLength).toString();

        table[name] = {
            name: name,
            compressedSize: buffer.readUInt32LE(20),
            uncompressedSize: buffer.readUInt32LE(24),
            offset: buffer.readUInt32LE(42),  // Local File Header offset
            fd: fd,
            compression: buffer.readUInt16LE(10),
            crc: buffer.readUInt32LE(16)
        };

        buffer = buffer.slice(46 + nameLength + efLength + comLength);
    }

    _cdr.self._res(new zippedObject(table));
};
```

Builds file table from Central Directory Records.

**Return Value:**
- Promise that resolves with `zippedObject` instance
- Promise rejects if:
  - File not found
  - Invalid ZIP structure
  - Parse errors

---

### zippedObject Class

Object representing an opened ZIP archive with methods for extraction.

#### Properties

- **files** (getter, lines 95-106) - Array of filenames in archive
- **_table** - Internal file metadata table
- **_FD** - File descriptor for ZIP file

#### Methods

##### getStream(name) - Lines 111-240

**Purpose:** Creates a readable stream for a file in the archive.

**Parameters:**
- `name` (string) - Filename to extract

**Process:**

**1. Stream Creation (lines 117-188):**
```javascript
if (info.compression == 0) {
    // Uncompressed - pass-through stream
    ret = new duplex({ write, final, read });
} else {
    // Compressed - decompression stream
    ret = require('compressed-stream').createDecompressor({ WBITS: -15 });
}
```

Creates appropriate stream based on compression method:
- Method 0: Stored (uncompressed) - pass-through duplex stream
- Method 8: Deflate - decompression stream with raw deflate (WBITS: -15)

**2. Local File Header Reading (lines 213-229):**
```javascript
require('fs').read(fd, {buffer: Buffer.alloc(30), position: info.offset}, function() {
    // Parse header to get filename length and extra field length
    var filenameLen = buffer.readUInt16LE(26);
    var extraLen = buffer.readUInt16LE(28);

    // Start reading compressed data after header
    var dataOffset = info.offset + 30 + filenameLen + extraLen;
    require('fs').read(fd, {buffer, length: bytesToRead, position: dataOffset}, readSink);
});
```

Reads Local File Header to determine where compressed data starts.

**3. Data Reading (lines 190-210):**
```javascript
ret._readSink = function(err, bytesRead, buffer) {
    this._bytesLeft -= bytesRead;
    this.write(buffer.slice(0, bytesRead), function() {
        if(this._bytesLeft == 0) {
            this.end();  // Done
        } else {
            // Read next chunk
            require('fs').read(fd, {buffer, length: min(4096, bytesLeft)}, readSink);
        }
    });
};
```

Reads compressed data in 4KB chunks, writes to decompression stream.

**Return Value:**
- Readable stream of decompressed file data
- Stream has `crc` property after completion (for validation)

**Stream Events:**
- `drain` - Triggered to begin reading from ZIP
- `data` - Emitted as file data is decompressed
- `end` - Emitted when file is fully extracted

---

##### extractAll(destFolder) - Lines 242-266

**Purpose:** Extracts all files from ZIP archive to destination folder.

**Parameters:**
- `destFolder` (string) - Target directory path (absolute or relative)

**Process:**
1. Normalizes destination path to absolute
2. Creates promise for tracking extraction
3. Queues all files for extraction
4. Calls `extractNext()` to process queue
5. For each file:
   - Creates necessary parent directories
   - Streams file data to disk
   - Validates CRC checksum
   - Moves to next file
6. Resolves promise when all files extracted
7. Closes ZIP file descriptor

**Return Value:**
- Promise that resolves when extraction complete
- Promise rejects on:
  - CRC mismatch
  - File system errors
  - Directory creation failures

**CRC Validation:**
```javascript
if (stream.crc != zip.crc(filename)) {
    promise._rej('CRC Check failed');
}
```

---

##### extractAllStreams() - Lines 298-306

**Purpose:** Extracts all files as in-memory streams (doesn't write to disk).

**Process:**
1. Creates promise with results array
2. For each file in archive:
   - Creates stream via `getStream()`
   - Buffers stream data in memory
   - Stores in results array as: `{name, stream, buffer}`
3. Resolves with array of file objects

**Return Value:**
- Promise resolving with array of objects:
  ```javascript
  [
      {name: "file.txt", stream: ReadableStream, buffer: Buffer},
      ...
  ]
  ```

**Use Case:**
- In-memory extraction for small archives
- Processing files without disk I/O
- Testing and validation

---

##### crc(name) - Lines 107-110

**Purpose:** Returns the expected CRC32 checksum for a file.

**Parameters:**
- `name` (string) - Filename

**Return Value:**
- CRC32 value from Central Directory Record

---

##### close() - Lines 338-346

**Purpose:** Closes the ZIP file descriptor and releases resources.

**Process:**
- Closes file descriptor via `fs.closeSync()`
- Nulls out internal references
- Automatically called on object finalization

---

### Helper Functions

#### checkFolderPath(dest) - Lines 23-44

**Purpose:** Ensures all parent directories exist for a file path.

**Parameters:**
- `dest` (string) - Target file path

**Process:**
1. Converts path separators to platform-specific (`\` on Windows, `/` elsewhere)
2. Splits path into directory components
3. Iteratively builds path from root
4. Creates each directory if it doesn't exist via `fs.mkdirSync()`

---

#### extractNext(p) - Lines 45-84

**Purpose:** Recursively extracts the next file from extraction queue.

**Parameters:**
- `p` (promise) - Extraction promise with `pending` array and configuration

**Process:**
1. Checks if extraction queue is empty
2. Pops next filename from queue
3. Builds destination path with platform separators
4. Creates parent directories
5. Opens file write stream
6. Gets read stream from ZIP
7. Pipes ZIP stream to file stream
8. Validates CRC on stream close
9. Recursively calls self for next file

---

### Dependencies

#### Node.js Core Modules
- `fs` (lines 39-41, 71, 161, 224, 321, 342, 356, 362, 448) - File system operations:
  - `existsSync()` - Check if file/directory exists
  - `mkdirSync()` - Create directory
  - `createWriteStream()` - Write stream to file
  - `read()` - Read from file descriptor
  - `openSync()` - Open file
  - `closeSync()` - Close file
  - `statSync()` - Get file size
- `stream.Duplex` (line 21) - Duplex stream base class for pass-through

#### MeshAgent Module Dependencies

**Core Required Modules:**

- **`promise`** (line 20)
  - Custom promise implementation
  - Used throughout for async operations
  - Methods: `_res`, `_rej` for resolution/rejection

- **`MemoryStream`** (line 22)
  - In-memory stream buffer
  - Used to accumulate HTTP response data
  - Methods: `pipe()` destination for buffering

- **`compressed-stream`** (line 187)
  - Compression/decompression streams
  - Method: `createDecompressor({WBITS: -15})`
  - WBITS: -15 indicates raw deflate (no zlib header)
  - Used for extracting deflated files

#### Global Constants (lines 16-18)

```javascript
var EOCDR = 101010256;  // 0x06054b50 - End of Central Directory Record
var CDR = 33639248;     // 0x02014b50 - Central Directory Record
var LFR = 67324752;     // 0x04034b50 - Local File Record
```

ZIP file format signatures for structure parsing.

### Technical Notes

**ZIP Format Parsing:**

The module reads ZIP files backwards:
1. Seek to end - 100 bytes
2. Search for EOCDR signature
3. Parse EOCDR to get Central Directory offset
4. Read Central Directory
5. Build file table from CDR entries
6. Use table to extract files

This is efficient because:
- Central Directory is at end of file
- One pass through Central Directory builds complete file index
- Individual files extracted on-demand

**Compression Method Support:**

- **Method 0 (Stored)**: Uncompressed, copied as-is
- **Method 8 (Deflate)**: Standard ZIP compression using deflate algorithm

Other methods (bzip2, LZMA, etc.) are not supported.

**WBITS Parameter:**

```javascript
createDecompressor({ WBITS: -15 })
```

WBITS: -15 indicates:
- Raw deflate stream (no zlib wrapper)
- 32KB window size (2^15)
- Negative value = no zlib header

ZIP uses raw deflate, not zlib format.

**CRC32 Validation:**

CRC is calculated during extraction:
```javascript
this.crc = crc32(chunk, this.crc);
```

Global `crc32()` function (not shown, assumed available) incrementally updates CRC as data is processed.

**Buffer vs File Path:**

The module accepts either:
- **String**: Treated as file path, opens file descriptor
- **Buffer**: Treated as in-memory ZIP data, creates virtual descriptor

Virtual descriptor:
```javascript
{
    _ObjectID: 'fs.bufferDescriptor',
    buffer: data,
    position: 0
}
```

This allows testing and processing of in-memory ZIP data without file I/O.

**Platform Path Handling:**

```javascript
if (process.platform == 'win32') {
    dest = dest.split('/').join('\\');
} else {
    dest = dest.split('\\').join('/');
}
```

Normalizes paths to platform-specific separators before file operations.

**Stream Backpressure:**

The pass-through stream for uncompressed files handles backpressure:
```javascript
if (this._pushOK) {
    this._pushOK = this.push(chunk);
    if (this._pushOK) {
        flush();
    } else {
        this._flush = flush;  // Wait for drain
    }
}
```

This prevents memory overflow when reading faster than consumer can process.

**Resource Cleanup:**

The `zippedObject` finalizer ensures file descriptor is closed:
```javascript
this.on('~', function () { this.close(); });
```

Prevents file descriptor leaks even if caller forgets to close.

## Summary

The zip-reader.js module provides comprehensive ZIP archive reading and extraction for **Windows, Linux, macOS, and FreeBSD**. It supports reading from both file paths and in-memory buffers, with promise-based async operations for reliability.

The module offers multiple extraction modes:
- **Streaming**: Extract individual files as readable streams
- **Bulk extraction**: Extract all files to disk with CRC validation
- **Memory extraction**: Extract files into memory buffers

Key features include automatic CRC32 validation, support for both stored and deflated compression methods, platform-specific path handling, and efficient parsing via the ZIP Central Directory structure. The module uses stream-based processing for memory efficiency when handling large archives.

The module integrates with MeshAgent's compressed-stream and promise modules while remaining usable for general-purpose ZIP processing with comprehensive error handling and resource management.
