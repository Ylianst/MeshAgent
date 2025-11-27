# PostBuild.js

Build post-processing utility that generates SHA-384 hashes of compiled binaries and archives them with dated/hashed folder organization. Enables build artifact management and version tracking on Windows systems.

## Platform

**Supported Platforms:**
- Windows - Full support

**Excluded Platforms:**
- macOS - Not supported
- Linux - Not supported

**Placement in modules_macos_NEVER:**

macOS is excluded because:

1. **Windows-Specific Paths** - Lines 15 and 20 use Windows backslash path separators (`\\`) and `process.platform == 'win32'` checks. The path construction at lines 24, 28-30 assumes Windows drive letters and directory structure.

2. **Windows PDB Files** - Lines 25, 29-30 specifically handle .pdb (Program Database) files which are Windows Visual Studio debugging artifacts. Not used on macOS.

3. **Windows Archival Strategy** - The entire archival structure (lines 22-30) is designed around Windows executable + PDB pairs organized in Windows directories.

4. **No Cross-Platform Fallback** - Lines 52-53 explicitly fail on non-Windows platforms with error message and exit.

**Code Reference (Lines 15-53):**
```javascript
if (process.platform == 'win32') {
    // Windows-specific implementation
    ...
} else {
    console.log(process.platform + ' is not supported');
    process.exit();
}
```

## Functionality

### Core Purpose

Post-build processing script that:
1. Computes SHA-384 hash of compiled executable
2. Archives exe + pdb files with hash-based naming
3. Organizes builds by date and hash for version tracking and debugging

### Build Pipeline Context

**Typical MeshAgent Build Sequence:**
1. Compile C/C++ components to produce exe + pdb
2. Optionally integrate JavaScript with exe.js
3. Run PostBuild.js for archival and hashing
4. Use archived versions for distribution and troubleshooting

### Hash Computation (Lines 6, 12-55)

```javascript
var hash = require('SHA384Stream').create();

hash.on('hash', function (buffer) {
    var h = buffer.toString('hex');
    if (process.platform == 'win32') {
        // Archive logic...
    } else {
        console.log(process.platform + ' is not supported');
        process.exit();
    }
});
```

**Hash Event Handler (Line 12):**
- Triggered when SHA384Stream finishes processing
- Receives hash buffer
- Converts to hex string

**Hash Usage (Line 24):**
```javascript
var newFolderPath = archiveFolder + "\\" + localFile + "_" + h.substring(0, 16);
```

Creates folder using first 16 characters of hash for unique identification.

### File and Path Processing (Lines 19-30)

**Extract Executable Filename (Line 19):**
```javascript
var localFile = process.execPath.lastIndexOf('\\') < 0 ?
    process.execPath.substring(0, process.execPath.length - 4) :
    process.execPath.substring(process.execPath.lastIndexOf('\\') + 1, process.execPath.length - 4);
```

- Find last backslash in exec path
- If not found: Take whole path minus .exe extension
- If found: Take filename only, minus .exe extension

**Example:** `C:\build\MeshService.exe` → `MeshService`

**Archive Folder Creation (Lines 20, 22):**
```javascript
var archiveFolder = process.execPath.substring(0, 1 + process.execPath.lastIndexOf("\\")) + "archive"
if (!fs.existsSync(archiveFolder)) { fs.mkdirSync(archiveFolder); }
```

Creates `archive` subfolder in same directory as executable.

**Path Examples:**
```
Original exe:  C:\build\MeshService.exe
Archive folder: C:\build\archive\
New folder:    C:\build\archive\MeshService_a1b2c3d4e5f6g7h8\
```

### Hashed Folder Structure (Lines 24-35)

**Archive Folder Names (Line 24):**
```javascript
var newFolderPath = archiveFolder + "\\" + localFile + "_" + h.substring(0, 16);
```

**Format:** `{ExeName}_{First16CharsOfHash}`

**Purpose:**
- Unique identification of each build
- Chronological ordering (hashes represent file content)
- Easy matching of exe to pdb for debugging

**File Organization (Lines 28-30):**
```javascript
var newFileName = newFolderPath + '\\' + localFile + '.exe';
var newPdbFileName = newFolderPath + '\\' + localFile + '.pdb';
```

**Stored Structure:**
```
archive/
└── MeshService_a1b2c3d4e5f6g7h8/
    ├── MeshService.exe
    └── MeshService.pdb
```

### Stream-Based File Copying (Lines 40-48)

**Executable Copy (Lines 40-43):**
```javascript
stream1 = fs.createReadStream(process.execPath, { flags: "rb" });
stream1.output = fs.createWriteStream(newFileName, { flags: "wb+" });
stream1.output.on('finish', OnFinish);
stream1.pipe(stream1.output);
```

**PDB Copy (Lines 45-48):**
```javascript
stream2 = fs.createReadStream(pdbFileName, { flags: "rb" });
stream2.output = fs.createWriteStream(newPdbFileName, { flags: "wb+" });
stream2.output.on('finish', OnFinish);
stream2.pipe(stream2.output);
```

**Streaming Approach:**
- Uses pipes for memory efficiency with large files
- Attaches output stream as property to source stream
- Registers finish handler for synchronization

### Synchronization: OnFinish Callback (Lines 57-64)

```javascript
function OnFinish() {
    if (--pending == 0) {
        console.log('Finished!');
        process.exit();
    }
}
```

**Counter Pattern:**
- `pending` starts at 2 (one for exe, one for pdb)
- Each stream finish decrements counter
- When both complete (counter reaches 0), exit

**Ensures:** Both files finish copying before process exits.

### Main Pipeline (Lines 66-67)

```javascript
var exeStream = fs.createReadStream(process.execPath, { flags: "rb" });
exeStream.pipe(hash);
```

**Execution Flow:**
1. Create read stream of executable
2. Pipe to SHA384Stream
3. Hash processing starts
4. On 'hash' event: archive logic runs
5. Both streams finish, exit

## Dependencies

### MeshAgent Module Dependencies

#### SHA384Stream (Line 6)

```javascript
var hash = require('SHA384Stream').create();
```

**Purpose:** Compute SHA-384 cryptographic hash of binary data

**Usage:**
```javascript
hash.on('hash', function (buffer) { ... });
var exeStream = fs.createReadStream(...);
exeStream.pipe(hash);
```

**Event:**
- 'hash' - Emitted with hash result after stream ends
- Buffer parameter contains raw 48-byte SHA-384 hash

**Source:** Custom MeshAgent streaming hash module

### Node.js Core Module Dependencies

#### fs (Lines 5, 22, 35, 40-41, 45-46, 66)

```javascript
var fs = require('fs');
```

**Methods Used:**
- `existsSync(path)` - Check if archive folder exists
- `mkdirSync(path)` - Create archive folder
- `createReadStream(path, options)` - Stream read exe and pdb files
- `createWriteStream(path, options)` - Stream write archived files

**Purpose:** File system operations for archive management

**File Flags:**
- `"rb"` - Read binary
- `"wb+"` - Write binary, create if not exists, allow read/write

#### console (Lines 32-33, 52, 61)

```javascript
console.log('...');
```

**Output:**
- Progress messages during archival
- Completion notification

### Platform Binary Dependencies

**None** - Pure JavaScript with Node.js streams

## Technical Notes

### SHA-384 Hash Purpose

**Why Hash Binaries?**

1. **Version Identification** - Different builds produce different hashes
2. **Integrity Verification** - Detect corruption or tampering
3. **Debugging** - Match crashes to specific builds via hash
4. **Archive Organization** - Unique folder names prevent collisions

**Hash Complexity:**
- SHA-384 outputs 384 bits (48 bytes)
- 16 hex characters represents 64 bits, still highly unique
- Extremely unlikely two different builds have same first 16 chars

### PDB File Significance

**Program Database (.pdb):**
- Debug symbols (function names, line numbers, variables)
- Generated by Visual Studio compiler alongside exe
- Required for meaningful debugging of crashes
- Same version must match exe exactly

**Archive Strategy:**
- Stores exe + pdb together in same folder
- Hash applies to exe (executable)
- PDB stored alongside for debugging that specific build

### Streaming for Efficiency

**Why Use Streams? (Lines 40-48)**

Large binaries (10+ MB) would load entirely into memory if using `fs.readFileSync()` and `fs.writeFileSync()`.

Streams provide:
- Constant memory usage regardless of file size
- Automatic buffering and back-pressure handling
- Pipeline-based processing

### Counter Pattern for Synchronization (Lines 17, 59)

```javascript
var pending;

hash.on('hash', function (buffer) {
    ...
    pending = 2;
    ...
    stream1.output.on('finish', OnFinish);
    stream2.output.on('finish', OnFinish);
    ...
});

function OnFinish() {
    if (--pending == 0) {
        console.log('Finished!');
        process.exit();
    }
}
```

**Problem Solved:** Ensure both async file copies complete before exiting

**Solution:** Counter approach
1. Set pending = 2 before starting copies
2. Each finish handler decrements counter
3. When counter reaches 0, all complete

### File Naming Stability

**Why First 16 Hex Characters of Hash? (Line 24)**

```javascript
h.substring(0, 16)  // SHA384 hash → 16 hex chars
```

- Full hash: 128 hex characters (48 bytes)
- 16 hex chars: Still provides ~64 bits of uniqueness
- Windows filename limitation: Keep paths reasonable length
- Sufficient for practical build version tracking

### Archive Folder Structure

**Benefits:**
```
archive/
├── MeshService_a1b2c3d4e5f6g7h8/     ← Grouped by hash
│   ├── MeshService.exe
│   └── MeshService.pdb
├── MeshService_b2c3d4e5f6g7h8i9/     ← Different builds separate
│   ├── MeshService.exe
│   └── MeshService.pdb
```

- Each build in separate folder
- Paired exe/pdb together
- Easy to identify and retrieve specific versions
- Prevents overwriting previous builds

## Summary

PostBuild.js archives compiled Windows binaries with SHA-384 hash-based folder organization. Enables post-build processing, version tracking, and organized artifact storage for debugging and distribution.

**Placed in modules_macos_NEVER** because:
- Explicitly Windows-only (platform check at lines 15, 52-53)
- Handles Windows PDB debug symbols
- Uses Windows path separators and file structures
- No fallback implementation for other platforms

**Key Features:**
- SHA-384 hash computation for version identification
- Automated exe + pdb pairing and archival
- Stream-based copying for memory efficiency
- Hash-based folder naming for unique identification
- Counter-based synchronization for multiple async operations

**Build Integration:**
- Typically runs after compilation
- Before distribution or testing phases
- Creates historical archive of all builds
- Enables matching crashes to specific builds

**Related Components:**
- exe.js - May be run before PostBuild to integrate JavaScript
- SHA384Stream - Computes hash of executable
