# tar-encoder.js

USTAR (Unix Standard Tar) format encoder that creates tar archive streams from files and directories. This module generates POSIX-compliant tar archives compatible with GNU tar, BSD tar, and other standard tar implementations. It supports streaming encoding of files with proper USTAR headers, checksums, ownership information, and file metadata.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support with platform-specific ownership defaults
- Linux - Full support with POSIX permissions and user/group names
- FreeBSD - Full support with POSIX permissions and user/group names
- macOS (darwin) - Full support with POSIX permissions and user/group names

**Platform Implementation Status:**

This module is fully cross-platform with platform-aware implementations:

1. **Windows** - Uses default root:root ownership with standard permissions (0666)
2. **POSIX (Linux/FreeBSD/macOS)** - Preserves actual file ownership, permissions, and user/group names

**No Exclusions:**
All platforms are fully supported. The module adapts its behavior based on platform capabilities while generating compatible USTAR archives across all systems.

## Functionality

### Purpose

The tar-encoder module provides streaming tar archive creation capabilities for JavaScript applications. It enables:

- Creating USTAR-format tar archives from files and directories
- Streaming encoding to avoid loading entire archives into memory
- Preserving file metadata (permissions, ownership, timestamps)
- Recursive directory traversal with configurable recursion
- Platform-aware ownership and permission handling
- POSIX.1-1988 (ustar) format compliance

This module is typically used for:
- Creating backup archives
- Packaging files for transfer
- Generating deployment packages
- Implementing file upload functionality
- Creating compressed archives (when piped to compression streams)

### Architecture

The module exports three main functions:

1. **encodeFiles(files, basePath)** - Encodes a specific list of files
2. **encodeFolder(folderPath, recurse)** - Encodes entire directory trees
3. **showHeader(path, offset)** - Debug utility to display USTAR headers

All encoding functions return Node.js Readable streams that emit 512-byte USTAR records.

### Key Functions with Line References

#### generateUstarHeader(path, basePath, uidtable, gidtable) - Lines 50-116

**Purpose:** Generates a 512-byte USTAR header for a file or directory.

**Parameters:**
- `path` - Full path to file or directory
- `basePath` - Base path to strip from archive names (optional)
- `uidtable` - Cache mapping UIDs to usernames (for POSIX platforms)
- `gidtable` - Cache mapping GIDs to group names (for POSIX platforms)

**Returns:** Buffer (512 bytes) with populated USTAR header and checksum

**USTAR Header Structure:**

The function generates a standard POSIX.1-1988 USTAR header:

```
Offset  Size  Field
------  ----  -----
0       100   File name
100     8     File mode (octal)
108     8     Owner's numeric user ID (octal)
116     8     Owner's numeric group ID (octal)
124     12    File size in bytes (octal)
136     12    Last modification time (Unix timestamp, octal)
148     8     Checksum for header (octal)
156     1     Type flag ('0'=file, '5'=directory)
157     100   Link name (unused)
257     6     USTAR indicator ("USTAR\0")
263     2     USTAR version ("00")
265     32    Owner user name
297     32    Owner group name
329     8     Device major number (unused)
337     8     Device minor number (unused)
345     155   Filename prefix (unused)
```

**Process:**

1. **File Statistics** (line 53)
   - Calls `fs.statSync(path)` to get file metadata
   - Retrieves size, timestamps, ownership, permissions

2. **Path Normalization** (lines 54-55)
   - Converts Windows backslashes to forward slashes
   - Strips basePath prefix if provided
   - Appends '/' to directory names (line 66)

3. **Size Field** (lines 57-67)
   - Files: Write size in bytes as octal string (line 59)
   - Directories: Write '0' (lines 63-64)
   - Sets isFile property on return buffer (lines 60, 65)

4. **Name Field** (line 69)
   - Writes normalized path to offset 0 (max 100 bytes)

5. **Type Flag** (line 70)
   - '0' (ASCII 48) for regular files
   - '5' (ASCII 53) for directories

6. **Modification Time** (line 71)
   - Converts JavaScript Date to Unix timestamp (milliseconds → seconds)
   - Writes as octal string to offset 136

7. **USTAR Marker** (line 72)
   - Writes "USTAR" at offset 257 (5 bytes)
   - Version bytes at 263-264 are left as zeros (representing "00")

8. **Platform-Specific Ownership:**

   **Windows** (lines 74-87):
   - Sets UID/GID to '0' (lines 77-78)
   - Sets uname/gname to 'root' (lines 81-82)
   - Calculates default mode: `S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH` (line 86)
   - Translates to octal: 0666 (rw-rw-rw-)

   **POSIX** (lines 88-102):
   - Writes actual UID/GID from fs.statSync (lines 91-92)
   - Looks up username via `user-sessions.getUsername(uid)` (line 94)
   - Looks up group name via `user-sessions.getGroupname(gid)` (line 95)
   - Caches username/groupname in uidtable/gidtable for performance
   - Writes actual file mode (permissions) (line 101)

9. **Checksum Calculation** (lines 105-114)
   - Blanks checksum field with spaces (ASCII 32) (lines 106-109)
   - Sums all 512 bytes (lines 110-113)
   - Writes checksum as octal string to offset 148 (line 114)

**Return Value:**
- Buffer with `isFile` property (true for files, false for directories)

---

#### loadUstarHeader(path, offset) - Lines 20-48

**Purpose:** Reads and validates a USTAR header from an existing tar file.

**Parameters:**
- `path` - Path to tar archive file
- `offset` - Byte offset to read header from (0 for first header)

**Returns:** Buffer (512 bytes) if valid header, null if invalid checksum

**Process:**

1. **Read Header** (lines 22-25)
   - Opens file in read-binary mode
   - Allocates 512-byte buffer
   - Reads from specified offset
   - Closes file

2. **Checksum Validation** (lines 27-38)
   - Calculates checksum by summing all bytes
   - Treats checksum field (148-155) as spaces (ASCII 32)
   - Sums all 512 bytes into variable `v`

3. **Verification** (lines 40-46)
   - Extracts stored checksum from offset 148-156 (8 bytes octal string)
   - Parses as base-8 integer
   - Compares with calculated checksum
   - Returns null if mismatch, buffer if valid

**Usage:**
```javascript
var header = loadUstarHeader('archive.tar', 0);
if (header) {
    var filename = header.slice(0, 100).toString();
    var size = parseInt(header.slice(124, 136).toString(), 8);
}
```

---

#### encodeFiles(files, basePath) - Lines 118-162

**Purpose:** Creates a streaming tar encoder for a specific list of files.

**Parameters:**
- `files` - Array of file/directory paths to encode
- `basePath` - Base path to strip from archive names

**Returns:** Readable stream that emits 512-byte tar records

**Process:**

The function returns a custom Readable stream with:

**State Properties:**
- `files` - Array of remaining files to encode (line 155)
- `_basePath` - Base path for name stripping (line 156)
- `_fd` - Current file descriptor (null when processing headers) (line 157)
- `_buffer` - 512-byte working buffer (line 158)
- `_uidTable` - Username cache (line 159)
- `_gidTable` - Group name cache (line 160)

**read() Implementation - Lines 122-153:**

1. **Header Processing** (lines 126-141)
   - When `_fd == null` and files remain:
     - Shifts next path from files array (line 130)
     - Generates USTAR header with `generateUstarHeader()` (line 131)
     - Opens file descriptor if header.isFile (line 132)
     - Pushes 512-byte header to stream (line 133)
   - When files exhausted:
     - Pauses stream (line 137)
     - Pushes null to signal end-of-stream (line 138)

2. **File Data Processing** (lines 142-152)
   - Reads 512 bytes from file (line 144)
   - Zero-pads buffer if less than 512 bytes read (line 145)
   - Closes file descriptor when less than 512 bytes read (lines 146-150)
   - Pushes buffer to stream (line 151)
   - Continues while `ok` is true (backpressure handling)

**Stream Behavior:**
- Emits header, then file data in 512-byte blocks
- Zero-pads last block if file size not multiple of 512
- Automatically handles backpressure via `push()` return value
- Closes file descriptors automatically

**Example:**
```javascript
var encoder = encodeFiles(['/path/file1.txt', '/path/file2.txt'], '/path');
encoder.pipe(fs.createWriteStream('archive.tar'));
```

---

#### expandFolderPaths(folderPath, recurse, arr) - Lines 164-182

**Purpose:** Recursively expands a folder path into a flat array of files and subdirectories.

**Parameters:**
- `folderPath` - Directory path to expand
- `recurse` - Boolean: true to recurse into subdirectories
- `arr` - Array to populate with file paths (modified in place)

**Process:**

1. **Directory Enumeration** (line 166)
   - Reads directory contents with `fs.readdirSync()`

2. **Item Processing** (lines 167-181)
   - For each item in directory:
     - Checks if item is directory via `fs.statSync().isDirectory()` (line 169)
     - If directory and `recurse` is true:
       - Adds directory path to array (line 173)
       - Recursively calls self for subdirectory (line 174)
     - If file:
       - Adds file path to array (line 179)

**Behavior:**
- Non-recursive mode: Only adds files from top-level directory
- Recursive mode: Adds directories before their contents (depth-first)
- Builds flat array structure suitable for sequential encoding

**Example:**
```javascript
var files = [];
expandFolderPaths('/var/log', true, files);
// files = ['/var/log/dir1', '/var/log/dir1/file1', '/var/log/file2', ...]
```

---

#### encodeFolder(folderPath, recurse) - Lines 184-189

**Purpose:** Convenience wrapper that encodes an entire directory tree.

**Parameters:**
- `folderPath` - Directory path to encode
- `recurse` - Boolean: true to include subdirectories recursively

**Returns:** Readable stream (same as encodeFiles)

**Process:**
1. Creates empty array (line 186)
2. Calls `expandFolderPaths()` to populate array (line 187)
3. Returns `encodeFiles(files, folderPath)` (line 188)

**Usage:**
```javascript
// Encode single directory (non-recursive)
var stream1 = encodeFolder('/opt/myapp', false);

// Encode directory tree (recursive)
var stream2 = encodeFolder('/var/log', true);
stream2.pipe(require('fs').createWriteStream('logs.tar'));
```

---

#### showHeader(path, offset) - Lines 191-258

**Purpose:** Debug utility that displays USTAR header information from a tar file.

**Parameters:**
- `path` - Path to tar archive
- `offset` - Starting byte offset (null/undefined for offset 0)

**Output:** Prints header fields to console for each header in archive

**Process:**

1. **Header Loop** (lines 193-257)
   - Reads header at current offset (line 195)
   - Breaks if checksum invalid (line 196)
   - Exits on NaN offset (line 197)

2. **Field Display** (lines 199-214)
   - Separator line (line 198)
   - Current offset (line 199)
   - File name (offset 0, 100 bytes)
   - File size (offset 124, 12 bytes octal)
   - Modification time (offset 136, 12 bytes octal → Date)
   - Type flag (offset 156, 1 byte)
   - Link name (offset 157, 100 bytes)
   - Magic string (offset 257, 6 bytes) - Should be "USTAR\0"
   - Version (offset 263, 2 bytes hex)
   - Owner username (offset 265, 32 bytes)
   - Owner UID (offset 108, 8 bytes octal)
   - Owner group name (offset 297, 32 bytes)
   - Owner GID (offset 116, 8 bytes octal)
   - Filename prefix (offset 345, 155 bytes)
   - File mode (offset 100, 8 bytes octal)
   - Stored checksum (offset 148, 8 bytes octal)

3. **Checksum Verification** (lines 216-229)
   - Blanks checksum field
   - Recalculates checksum
   - Displays computed checksum for comparison

4. **Offset Advancement** (lines 231-256)
   - For directories (type '5'): Advance 512 bytes (lines 232-240)
   - For files: Calculate records needed (filesize / 512, rounded up) (lines 243-246)
   - Advance offset to next header (lines 247-255)

**Usage:**
```bash
node -e "require('tar-encoder').showHeader('archive.tar', null)"
```

**Example Output:**
```
-----------------------------
THIS Offset: 0
name: file.txt
size: 1234
mtime: Mon Jan 01 2024 12:00:00 GMT-0800 (PST)
type: 0
linkname:
magic: USTAR
version: 0000
uname: john
uid: 1000
gname: staff
gid: 50
prefix:
mode: 100644
checksum: 5432
Computed Checksum: 5432
```

---

### Usage Examples

#### Example 1: Create Tar from File List

```javascript
var tarEncoder = require('tar-encoder');
var fs = require('fs');

var files = [
    '/opt/myapp/app.js',
    '/opt/myapp/config.json',
    '/opt/myapp/data.db'
];

var encoder = tarEncoder.encodeFiles(files, '/opt/myapp');
encoder.pipe(fs.createWriteStream('backup.tar'));

encoder.on('end', function() {
    console.log('Tar archive created successfully');
});
```

#### Example 2: Create Recursive Directory Archive

```javascript
var tarEncoder = require('tar-encoder');
var fs = require('fs');

// Archive entire directory tree
var stream = tarEncoder.encodeFolder('/var/log/myapp', true);
var output = fs.createWriteStream('logs-backup.tar');

stream.pipe(output);

output.on('finish', function() {
    console.log('Directory archived');
});
```

#### Example 3: Non-Recursive Directory Archive

```javascript
var tarEncoder = require('tar-encoder');

// Archive only top-level files (no subdirectories)
var stream = tarEncoder.encodeFolder('/etc/config', false);
stream.pipe(process.stdout); // Stream to stdout
```

#### Example 4: Create Compressed Tar Archive

```javascript
var tarEncoder = require('tar-encoder');
var zlib = require('zlib');
var fs = require('fs');

// Create tar.gz archive
var encoder = tarEncoder.encodeFolder('/opt/myapp', true);
var gzip = zlib.createGzip();
var output = fs.createWriteStream('backup.tar.gz');

encoder.pipe(gzip).pipe(output);
```

#### Example 5: Inspect Tar Archive

```javascript
var tarEncoder = require('tar-encoder');

// Display all headers in archive
tarEncoder.showHeader('backup.tar', null);
```

#### Example 6: Stream to HTTP Response

```javascript
var tarEncoder = require('tar-encoder');
var http = require('http');

http.createServer(function(req, res) {
    if (req.url == '/download') {
        res.setHeader('Content-Type', 'application/x-tar');
        res.setHeader('Content-Disposition', 'attachment; filename="archive.tar"');

        var stream = tarEncoder.encodeFolder('/opt/export', true);
        stream.pipe(res);
    }
}).listen(8080);
```

---

### Dependencies

#### Node.js Core Modules

- **`stream.Readable`** (line 17)
  - Base class for streaming tar encoder
  - Provides backpressure handling and streaming infrastructure
  - Methods: `push()`, `pause()`

- **`fs`** (lines 22, 53, 132, 144, 148, 166, 169)
  - File system operations
  - Methods used:
    - `openSync()` - Open file descriptor
    - `readSync()` - Read file data
    - `closeSync()` - Close file descriptor
    - `statSync()` - Get file metadata
    - `readdirSync()` - Read directory contents

- **`Buffer`** (lines 23, 52, and throughout)
  - Binary data manipulation
  - Methods: `alloc()`, `from()`, `copy()`, `readUInt32LE()`, `writeUInt32LE()`

#### MeshAgent Module Dependencies

- **`user-sessions`** (lines 94, 95)
  - POSIX platforms only (Linux, FreeBSD, macOS)
  - Methods:
    - `getUsername(uid)` - Converts UID to username string
    - `getGroupname(gid)` - Converts GID to group name string
  - Used to populate USTAR uname and gname fields
  - Not required on Windows (defaults to 'root')

#### Platform-Specific Dependencies

**Windows:**
- **`fs.CHMOD_MODES`** (line 85)
  - File permission constants
  - Used to calculate default mode (0666)
  - Constants: `S_IRUSR`, `S_IWUSR`, `S_IRGRP`, `S_IWGRP`, `S_IROTH`, `S_IWOTH`

**POSIX (Linux/FreeBSD/macOS):**
- **`user-sessions`** module
  - Required for username/groupname lookup
  - Accesses system user/group databases

No external binary dependencies required on any platform.

---

## Code Structure

The module is organized into functional sections:

1. **Lines 1-16:** Copyright and license header

2. **Lines 17-18:** Module imports
   - stream.Readable

3. **Lines 20-48:** loadUstarHeader() - Header reading and validation

4. **Lines 50-116:** generateUstarHeader() - USTAR header generation
   - Lines 53-72: Core header fields
   - Lines 74-87: Windows platform handling
   - Lines 88-102: POSIX platform handling
   - Lines 105-114: Checksum calculation

5. **Lines 118-162:** encodeFiles() - Streaming encoder implementation
   - Lines 122-153: Readable.read() implementation
   - Lines 155-160: Stream state initialization

6. **Lines 164-182:** expandFolderPaths() - Recursive directory traversal

7. **Lines 184-189:** encodeFolder() - Convenience wrapper

8. **Lines 191-258:** showHeader() - Debug utility

9. **Lines 260-261:** Module exports

---

## Technical Notes

### USTAR Format Compliance

The module generates POSIX.1-1988 (ustar) format archives:
- 512-byte header blocks
- 512-byte data blocks (zero-padded)
- Octal string encoding for numeric fields
- "USTAR" magic string at offset 257
- Version "00" at offset 263-264

**Compatibility:**
- GNU tar (Linux)
- BSD tar (FreeBSD, macOS)
- Windows tar (Windows 10+)
- pax (POSIX archiver)

### Checksum Algorithm

The checksum (lines 105-114) is calculated as:
1. Initialize checksum field (offsets 148-155) to spaces (ASCII 32)
2. Sum all 512 bytes as unsigned 8-bit integers
3. Store sum as octal string in checksum field

This is the standard USTAR checksum algorithm defined in POSIX.1-1988.

### Streaming Architecture

The module uses Node.js Readable streams with these characteristics:

**Backpressure Handling:**
- `push()` returns false when internal buffer is full
- `read()` pauses data reading until buffer drains
- Prevents memory exhaustion on large files

**Memory Efficiency:**
- Only 512 bytes of file data in memory at a time
- Header generation is immediate (no buffering)
- Suitable for archiving multi-gigabyte files

**State Machine:**
```
START
  ↓
EMIT HEADER → EMIT FILE DATA (512-byte blocks) → CLOSE FILE
  ↓                                                    ↓
NEXT FILE ←━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┘
  ↓
END OF STREAM
```

### Path Normalization

Windows paths are converted to Unix-style:
```javascript
// Before: C:\Users\John\file.txt
// After:  Users/John/file.txt
name = path.split('\\').join('/');
```

BasePath stripping:
```javascript
// path = '/opt/myapp/config.json'
// basePath = '/opt/myapp'
// Result in archive: 'config.json'
```

### Username/Groupname Caching

The uidtable and gidtable objects cache username/groupname lookups:
```javascript
if (!uidtable[stats.uid]) {
    uidtable[stats.uid] = require('user-sessions').getUsername(stats.uid);
}
```

Benefits:
- Avoids repeated system calls for same UID/GID
- Improves performance when archiving many files owned by same user
- Cache persists for entire encoding operation

### File Mode Permissions

**Windows Default (0666):**
```
Owner:  rw- (read, write)
Group:  rw- (read, write)
Others: rw- (read, write)
```

**POSIX Preserved:**
Actual file permissions from fs.statSync().mode, for example:
```
0755 → rwxr-xr-x (executable)
0644 → rw-r--r-- (regular file)
0600 → rw------- (private file)
```

### Directory Handling

Directories are encoded as:
- Type flag '5' (ASCII 53)
- Size 0
- Name ending with '/'
- No data blocks (only header)

### File Size Limitations

USTAR format stores file size in 12 bytes octal:
- Maximum value: 777777777777₈ = 8,589,934,591 bytes (8 GB)
- Files larger than 8 GB cannot be encoded in USTAR format
- Consider using GNU tar extensions (not implemented) for larger files

---

## Platform-Specific Analysis

### Windows (win32)

**What Works:**
- Full tar encoding functionality
- Path normalization (backslash → forward slash)
- Default ownership (root:root)
- Default permissions (0666)
- Streaming encoding of large files

**Platform-Specific Behavior:**
- Uses `fs.CHMOD_MODES` constants (line 85)
- Sets UID/GID to '0' (lines 77-78)
- Sets uname/gname to 'root' (lines 81-82)
- Calculates safe default mode (0666)

**Limitations:**
- Does not preserve actual Windows ACLs
- Does not preserve Windows ownership information
- Generated archives use Unix-style ownership

**Compatibility:**
- Windows 10+ includes built-in tar support
- Generated archives can be extracted on Windows, Linux, macOS
- Use Windows tar.exe or 7-Zip to extract

---

### Linux

**What Works:**
- Full tar encoding with POSIX metadata preservation
- UID/GID preservation
- Username/groupname lookup via user-sessions
- File permission preservation
- Symbolic link support (via fs.statSync)

**Platform-Specific Behavior:**
- Reads actual UID/GID from file stats (lines 91-92)
- Looks up username via getUsername() (line 94)
- Looks up groupname via getGroupname() (line 95)
- Preserves exact file mode (line 101)

**Limitations:**
- Extended attributes (xattr) not preserved
- SELinux contexts not preserved
- ACLs not preserved (only standard permissions)

**Use Cases:**
- System backup and restore
- Application deployment packages
- Log file archiving
- Container image creation

---

### FreeBSD

**What Works:**
- Same functionality as Linux
- POSIX metadata preservation
- Username/groupname lookup
- Compatible with BSD tar

**Platform-Specific Behavior:**
- Identical to Linux implementation
- Uses FreeBSD user/group databases

**Compatibility:**
- Archives are compatible with BSD tar
- Can be extracted on Linux, macOS, Windows

---

### macOS (darwin)

**What Works:**
- Full POSIX metadata preservation
- Username/groupname lookup
- Compatible with macOS tar
- Works with macOS code signing (archives can contain signed binaries)

**Platform-Specific Behavior:**
- Same as Linux/FreeBSD
- Uses macOS user/group databases (Directory Services)

**Limitations:**
- Extended attributes not preserved (e.g., com.apple.quarantine)
- Resource forks not preserved (obsolete on modern macOS)
- Finder metadata not preserved

**macOS-Specific Considerations:**
- Generated archives work with Time Machine
- Compatible with Homebrew formula packaging
- Suitable for application bundle distribution (after code signing)

---

### Cross-Platform Archive Compatibility

Archives created on any platform can be extracted on any other platform:

**Windows → Linux/macOS:**
- Files owned by 'root' (UID 0, GID 0)
- Permissions default to 0666
- Paths use forward slashes

**Linux/macOS → Windows:**
- Ownership information ignored by Windows
- Permissions mapped to Windows ACLs if possible
- Paths converted to backslashes automatically

**Linux ↔ macOS:**
- Full metadata preservation
- UID/GID preserved (may need mapping if users differ)
- Permissions preserved exactly

---

## Summary

The tar-encoder.js module provides a lightweight, cross-platform, streaming implementation of USTAR tar archive encoding. It generates POSIX.1-1988 compliant tar archives with proper metadata preservation, checksums, and streaming efficiency.

**Key Capabilities:**
- Stream-based encoding to avoid memory exhaustion
- USTAR format compliance for maximum compatibility
- Platform-aware ownership and permission handling
- Recursive directory traversal
- Username/groupname caching for performance
- Debug utilities for tar inspection

**Platform Support:**
- **Windows:** Full support with sensible defaults (root:root, 0666)
- **Linux:** Full support with POSIX metadata preservation
- **FreeBSD:** Full support with BSD tar compatibility
- **macOS:** Full support with macOS tar compatibility

The module is production-ready and suitable for backup systems, file transfer mechanisms, deployment pipelines, and any application requiring tar archive creation. Its streaming architecture makes it memory-efficient for archiving large files and directory trees, while platform-specific adaptations ensure generated archives work correctly across all major operating systems.

**Typical Use Cases in MeshAgent:**
- Creating file upload archives for transmission to server
- Packaging log files for diagnostic purposes
- Generating backup archives of agent configuration
- Compressing directory trees for efficient transfer
