# update-helper.js

Utility module for handling zipped MeshAgent update files by automatically detecting ZIP archives, extracting their contents, and replacing the original file with the extracted executable. This is a runtime utility module used during the agent update process to simplify update deployment.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support
- macOS (darwin) - Full support
- FreeBSD - Full support

## Functionality

### Purpose

The update-helper module serves as an automated update unpacker for the MeshAgent. When an agent update is downloaded, it may arrive as a ZIP archive containing the actual executable. This module:

- Detects if an update file is a ZIP archive
- Extracts the single executable from the ZIP file
- Replaces the original ZIP file with the extracted executable
- Cleans up temporary files
- Uses promise-based asynchronous operations for reliable file handling

This module is typically used during the agent's self-update process to handle ZIP-packaged updates transparently.

### Update Extraction Flow

When `start(updatePath)` is invoked:

1. **ZIP Detection** - Checks if file is a ZIP archive using `zip-reader.isZip()`
2. **Early Exit** - If not a ZIP file, resolves immediately (nothing to extract)
3. **ZIP Reading** - Opens and reads the ZIP file structure
4. **Validation** - Ensures ZIP contains exactly one file (security check)
5. **Extraction** - Streams the compressed file to a temporary location
6. **Replacement** - Deletes original ZIP and renames extracted file
7. **Cleanup** - Removes temporary extraction file
8. **Resolution** - Promise resolves with 'done' or rejects with error

### Key Functions

#### start(updatePath) - Lines 19-69

**Purpose:** Main entry point that orchestrates the extraction and replacement process.

**Parameters:**
- `updatePath` (string) - Absolute path to the update file (potentially zipped)

**Process:**
1. Creates promise for async operation tracking
2. Checks if file is ZIP using `zip-reader.isZip()` (line 22)
3. If not ZIP: Resolves immediately and returns
4. If ZIP: Initiates ZIP reading with `zip-reader.read()` (line 23)
5. Validates ZIP contains exactly one file (line 27-31)
   - Multiple files → Rejects with 'Unexpected contents in zip file'
   - Ensures security by preventing multi-file extraction
6. Creates write stream to temporary file `updatePath + '_unzipped'` (line 36)
7. Pipes extracted data from ZIP to temporary file (line 47)
8. On stream close: Performs file replacement (lines 51-64)
   - Deletes original ZIP file
   - Copies extracted file to original path
   - Deletes temporary file
9. Resolves with 'done' or rejects with errors

**Dependencies:**
- `promise` module (line 17) - Custom promise implementation
- `zip-reader` module (lines 22-23) - ZIP detection and extraction
- `fs` module (lines 36, 55-57) - File system operations

**Error Handling:**
- ZIP with multiple files → 'Unexpected contents in zip file'
- File system errors → Caught and rejected through promise
- Stream errors → Propagated through promise chain

**Platform Behavior:**
- All platforms supported via Node.js fs module
- File path handling is platform-agnostic (uses standard paths)
- Temporary file uses same directory as update file

---

### Dependencies

#### Node.js Core Modules
- `fs` (lines 36, 55-57) - File system operations for:
  - Creating write streams
  - File deletion (`unlinkSync`)
  - File copying (`copyFileSync`)

#### MeshAgent Module Dependencies

**Core Required Modules:**

- **`promise`** (line 17)
  - Custom promise implementation for async orchestration
  - Used for chaining extraction operations
  - Not Node.js native promises
  - Methods used: constructor with `_res`/`_rej` pattern

- **`zip-reader`** (lines 22-23)
  - ZIP file detection and reading
  - Methods used:
    - `isZip(path)` - Detects if file is ZIP archive
    - `read(path)` - Returns promise that resolves with ZIP object
    - `getStream(filename)` - Creates readable stream for file in archive
  - Properties accessed:
    - `files` array - List of files in ZIP
  - Methods on ZIP object:
    - `close()` - Closes file descriptor

### Technical Notes

**Promise Chaining Pattern:**
The module uses a custom promise implementation with manual resolution control:
```javascript
var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
```

This allows the promise to be resolved or rejected from nested callbacks outside the promise constructor scope.

**File Replacement Strategy:**
Instead of directly extracting to the target path, the module uses a three-step approach:
1. Extract to temporary file (`updatePath + '_unzipped'`)
2. Delete original file
3. Copy temporary to original path
4. Delete temporary file

This ensures atomicity - if extraction fails, the original file remains intact.

**Security Consideration:**
The module explicitly checks that ZIP files contain exactly one file (line 27). This prevents:
- Directory traversal attacks via multiple files
- Confusion about which file is the executable
- Accidental extraction of unwanted files

**Stream-Based Extraction:**
The module uses Node.js streams for efficient memory usage:
```javascript
zipped.getStream(zipped.files[0]).pipe(p.dest);
```

This allows large files to be extracted without loading the entire compressed data into memory.

**Error Propagation:**
Errors are caught at multiple levels and propagated through the promise chain:
- ZIP reading errors
- File system errors (write stream creation, file operations)
- Stream errors

## Summary

The update-helper.js module is a cross-platform utility for **Windows, Linux, macOS, and FreeBSD** that transparently handles zipped agent updates. When an update file is a ZIP archive containing a single executable, this module automatically extracts it, replaces the ZIP with the extracted file, and cleans up temporary files.

The module is platform-agnostic and supports all major operating systems through standard Node.js file system APIs. It uses promise-based asynchronous operations to ensure reliable extraction with proper error handling. The security-conscious design validates that ZIP files contain exactly one file before extraction, preventing potential security issues.

This is a runtime utility invoked during MeshAgent's self-update process to seamlessly handle both raw executables and ZIP-packaged updates without manual intervention.
