# AgentHashTool.js

Utility for calculating cryptographic hashes of MeshAgent executables while excluding signatures and embedded data. Enables verification of binary integrity independent of platform-specific metadata like code signatures (Windows Authenticode, macOS codesign) and embedded .msh policy files.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support with PE parser, excludes Authenticode certificate table
- Linux - Full support, excludes embedded .msh file
- macOS (darwin) - Full support, excludes embedded .msh file
- FreeBSD - Likely supported (same hash fallback as Linux, untested)

**Excluded Platforms:**
- None - This module supports all platforms

## Functionality

### Purpose

The AgentHashTool module provides consistent binary hash calculation across platforms by excluding variable sections. It ensures:

- Hash consistency regardless of code signing status
- Verification of binary integrity independent of signatures
- Detection of binary modifications (excluding signatures)
- Cross-platform hash comparison for same binary version

This module is critical for:
- Verifying agent binary integrity during updates
- Detecting unauthorized binary modifications
- Cross-platform version verification
- Build system integrity checks

### Key Functions

#### hashFile(options) - Lines 24-98 (Main Export Function)

**Purpose:** Streams executable file through hash function while excluding platform-specific variable sections.

**Parameters:**
```javascript
{
  sourcePath: '/path/to/meshagent',  // Input binary path
  targetStream: hashStream,           // crypto.createHash('sha384') stream
  platform: 'darwin'                  // Optional: 'win32', 'linux', 'darwin', 'freebsd'
}
```

**Process:**

**1. Platform Detection** (lines 26-39):
- If `platform` not specified, auto-detect via PE parser test
- Reads first few bytes of file
- Attempts PE header parsing
- If PE parse succeeds → Windows
- If PE parse fails → Unix/macOS

**2. Windows PE Format** (lines 42-92):
```javascript
// Parse PE structure
var pe = require('PE_Parser').parse(sourcePath);
var endIndex = pe.CertificateTableAddress || filesize;

// Three-part streaming (excluding checksum and cert):
// Part 1: Start → CheckSumPos (write zeros for checksum)
writeZeroChunk(pe.CheckSumPos);

// Part 2: After checksum → CertificateTableSizePos (write zeros for size)
writeZeroChunk(pe.CertificateTableSizePos);

// Part 3: After table size → endIndex (code section, before cert)
pipeToHash(startPos, endIndex);
```

**Excluded from Hash:**
- **CheckSum** field (offset from OptionalHeader) - Varies by content
- **Certificate Table** size field - Varies by signature
- **Certificate Table** data - Authenticode signature at end of file

**3. Unix/macOS Format** (lines 53-71):
```javascript
// Check for embedded .msh policy file
var guidBytes = Buffer.alloc(16);
fs.readSync(fd, guidBytes, 0, 16, filesize - 16);
var guid = guidBytes.toString('hex').toUpperCase();

if (guid === 'B996015880544A19B7F7E9BE44914C19') {
    // .msh present, read size from -20 offset
    var sizeBytes = Buffer.alloc(4);
    fs.readSync(fd, sizeBytes, 0, 4, filesize - 20);
    var mshSize = sizeBytes.readUInt32LE(0);

    // Exclude .msh section
    endIndex = filesize - 20 - mshSize;
} else {
    // No .msh, hash entire file
    endIndex = filesize;
}
```

**Embedded .msh Structure:**
```
[Binary Code...][.msh Data][4 bytes: mshSize][16 bytes: GUID B996...4C19]
                          ^                  ^                           ^
                          |                  |                           |
                     Start of .msh      Size field               End of file
```

**Excluded from Hash:**
- **Embedded .msh policy** (last N bytes if GUID present)
- **Size field** (4 bytes before GUID)
- **GUID marker** (16 bytes at end)

**4. Streaming to Hash** (lines 73-97):
- Opens file descriptor
- Creates readable stream from calculated range
- Pipes to `targetStream` (provided hash function)
- Closes file on completion

**Return Value:** None (streaming operation, hash calculated in targetStream)

---

### Module Exports

**Line 100:**
```javascript
module.exports = hashFile;
```

### Dependencies

#### Node.js Core Modules
- **`fs`** (lines 28, 56, 61, 67, 94) - File I/O operations
  - Methods: `statSync()`, `openSync()`, `readSync()`, `closeSync()`, `createReadStream()`
  - File descriptor management for byte-range reading

#### MeshAgent Module Dependencies

**Windows-Specific:**
- **`PE_Parser`** (lines 31, 46) - Portable Executable parser
  - Method: `parse(filepath)`
  - Returns: `{ CheckSumPos, CertificateTableSizePos, CertificateTableAddress }`
  - Parses PE header structure
  - Locates variable sections (checksum, certificate)

**Unix/macOS:**
- None - Uses only Node.js `fs` module

#### External Dependencies
- None - No external binaries

### Usage

#### Basic Usage

```javascript
var crypto = require('crypto');
var hashStream = crypto.createHash('sha384');

require('AgentHashTool')({
    sourcePath: '/usr/local/mesh/meshagent',
    targetStream: hashStream
});

hashStream.on('finish', function() {
    var hash = this.digest('hex');
    console.log('Binary hash:', hash);
    // Compare with known-good hash for verification
});
```

#### With Explicit Platform

```javascript
var hashStream = crypto.createHash('sha256');

require('AgentHashTool')({
    sourcePath: '/path/to/meshagent.exe',
    targetStream: hashStream,
    platform: 'win32'  // Skip PE detection
});

hashStream.on('finish', function() {
    console.log('Windows binary hash:', this.digest('hex'));
});
```

#### Version Verification

```javascript
// Verify binary matches expected version
var expectedHash = 'abc123...';
var actualHash = crypto.createHash('sha384');

require('AgentHashTool')({
    sourcePath: process.execPath,
    targetStream: actualHash
});

actualHash.on('finish', function() {
    if (this.digest('hex') === expectedHash) {
        console.log('Binary verified');
    } else {
        console.log('Binary modified or wrong version');
    }
});
```

### Technical Notes

**Why Exclude Signatures:**

**Windows Authenticode:**
- Signature added after binary compilation
- Changes with every signing operation
- Different signing certificates = different signatures
- Hash would differ for same binary with different signatures

**macOS Code Signing:**
- Extended attributes or resource fork (not embedded in binary)
- Handled by filesystem, not AgentHashTool
- Binary contents remain unchanged by codesign

**Embedded .msh Policy:**
- Configuration data appended to binary
- Changes per deployment (MeshServer URL, MeshID)
- Would cause hash mismatch for same binary with different configs
- Exclusion allows binary version verification independent of configuration

**PE Structure (Windows):**
```
DOS Header
PE Signature
File Header
Optional Header
  ├─ CheckSum (varies by content) ← Zero out
  └─ Data Directories
      └─ Security Directory
          ├─ Size (varies) ← Zero out
          └─ Address (points to cert at end)
Section Headers
.text (code)
.data
.rdata
... other sections ...
Certificate Table ← Exclude from hash
```

**Embedded .msh Detection:**
- **GUID:** `B996015880544A19B7F7E9BE44914C19` (fixed identifier)
- **Location:** Last 16 bytes of file
- **Size Field:** 4 bytes before GUID (UInt32LE)
- **Data:** N bytes before size field

**Hash Algorithm Choice:**
- Module accepts any hash algorithm (sha256, sha384, sha512)
- Typically sha384 used for consistency with NodeID (also sha384)
- Stronger than sha256, faster than sha512

**Streaming Implementation:**
- Efficient for large binaries (no full-file memory load)
- Uses file descriptor for precise byte-range reading
- Pipes to provided hash stream for flexibility

**Auto-Detection Logic:**
```javascript
if (platform === undefined) {
    try {
        require('PE_Parser').parse(sourcePath);
        // Parse succeeded → Windows PE format
        platform = 'win32';
    } catch (e) {
        // Parse failed → Unix/macOS format
        platform = 'other';
    }
}
```

### Platform-Specific Analysis

**What Works on macOS:**
- Full functionality for Mach-O binaries
- Embedded .msh detection and exclusion
- Hash calculation for binary integrity
- Cross-platform hash comparison

**macOS-Specific Behavior:**
- Handles Mach-O binary format (ELF-like)
- Checks for embedded .msh at file end
- No special handling for macOS code signatures (not embedded in binary)
- Identical logic to Linux and FreeBSD

**Platform Differences:**

**Windows:**
- PE (Portable Executable) format
- Authenticode signature embedded in binary (Certificate Table)
- CheckSum field varies by content
- Three-part streaming (before/between/after excluded sections)
- Requires PE_Parser module

**Unix/macOS/FreeBSD:**
- ELF/Mach-O format
- No embedded signatures in binary data
- Optional embedded .msh policy file
- Two-part streaming (code vs .msh)
- No special parser needed

**Code Signing Differences:**

**Windows:**
- Signature stored IN binary (appended to file)
- Certificate Table at end of file
- Must be excluded from hash

**macOS:**
- Signature stored in extended attributes OR resource fork
- NOT part of main binary data stream
- `fs.readFile()` doesn't include extended attributes
- No exclusion needed (not in binary)

**Linux:**
- No standard code signing mechanism
- Some distros use detached signatures (.sig files)
- Binary data unaffected

**Verification Use Cases:**

1. **Update Integrity:**
   - Server sends: binary + hash
   - Agent calculates hash (excluding signature)
   - Compare hashes to verify download

2. **Version Detection:**
   - Known hashes for each binary version
   - Calculate hash of running agent
   - Match to known version

3. **Tamper Detection:**
   - Record hash at installation
   - Periodically recalculate hash
   - Alert if hash changed (code modification)

4. **Cross-Platform Builds:**
   - Same source code compiled on Windows/Linux/macOS
   - Different signatures/configs
   - Hash comparison verifies identical binaries

### Example Scenarios

**Scenario 1: Verify Windows Binary (Signed)**
```javascript
// Binary: meshagent.exe (with Authenticode signature)
// Hash excludes: CheckSum, Certificate Table
var hash = require('crypto').createHash('sha384');
require('AgentHashTool')({
    sourcePath: 'meshagent.exe',
    targetStream: hash
});
// Result: Hash of code only, consistent across different signatures
```

**Scenario 2: Verify macOS Binary (with .msh)**
```javascript
// Binary: meshagent (with embedded .msh policy)
// Hash excludes: .msh data at end
var hash = require('crypto').createHash('sha384');
require('AgentHashTool')({
    sourcePath: '/opt/mesh/meshagent',
    targetStream: hash
});
// Result: Hash of code only, consistent across different .msh configs
```

**Scenario 3: Cross-Platform Comparison**
```javascript
// Compare Windows and Linux builds of same version
var winHash = hashBinary('meshagent.exe');  // Exclude cert
var linuxHash = hashBinary('meshagent');    // Exclude .msh
// If same source: winHash === linuxHash (proves same code)
```

## Summary

The AgentHashTool.js module provides consistent cryptographic hash calculation for MeshAgent binaries across all platforms (Windows, Linux, macOS, FreeBSD). It intelligently excludes platform-specific variable sections (signatures, embedded configs) to enable binary integrity verification and version detection.

**Key capabilities:**
- Platform-specific variable section exclusion
- Windows: PE parser, excludes Authenticode Certificate Table and CheckSum
- Unix/macOS: GUID-based detection, excludes embedded .msh policy
- Auto-detection of binary format (PE vs ELF/Mach-O)
- Streaming implementation for memory efficiency

**macOS support:**
- Full support for Mach-O binaries
- Embedded .msh detection via GUID marker
- No special code signature handling (not embedded in binary)
- Identical behavior to Linux and FreeBSD

**Critical dependencies:**
- `fs` for file I/O operations
- `PE_Parser` for Windows binary parsing (Windows only)

The module enables reliable binary verification independent of code signing and deployment-specific configuration, essential for secure agent updates and integrity monitoring.
