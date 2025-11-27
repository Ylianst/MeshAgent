# MSH_Installer.js

Mesh policy (MSH) integration tool for embedding MeshAgent policy data into Windows PE executables with support for both unsigned and signed binaries. Handles binary manipulation at the PE certificate table level to preserve Authenticode signatures while embedding policy configuration.

## Platform

**Supported Platforms:**
- Windows - Full support for PE binary manipulation
- Linux - Partial support (unsigned binaries only)

**Excluded Platforms:**
- macOS - No support

**Placement in modules_macos_NEVER:**

macOS is excluded because:

1. **Windows PE Binary Format** - The entire implementation is built around Windows PE (Portable Executable) file structure. Lines 64 and 81 explicitly use PE_Parser to read PE headers. macOS uses Mach-O binary format with completely different structure and certificate mechanisms.

2. **Authenticode Certificate Handling** - Lines 106-169 implement complex logic for handling Windows Authenticode signatures, reading and modifying certificate table sizes (CertificateTableAddress, CertificateTableSize, certificateDwLength). macOS uses code signing infrastructure that is incompatible.

3. **Certificate Table Manipulation** - The module directly manipulates the PE certificate table (lines 120, 127-128, 131, 138-139, 142, 155-156) using little-endian 32-bit integers specific to PE format. This is Windows-specific binary structure.

4. **Output Format** - Designed to create .exe files with embedded MSH policies. macOS doesn't use .exe format.

**Technical Note:** The module would require a completely different implementation for macOS, using Mach-O binary parsing instead of PE parsing.

## Functionality

### Core Purpose

Embeds Mesh Service Host (MSH) policy configuration data into Windows executables while preserving binary signatures. Supports both unsigned binaries (direct embedding) and signed binaries (certificate-aware embedding with signature preservation).

### API Functions

#### addMsh(options) - Line 51

**Primary embedding function for signed and unsigned binaries.**

**Options Object (Lines 43-50):**
```javascript
options = {
    platform: 'win32' or 'linux',          // Target platform (auto-detected if omitted)
    sourceFileName: 'pathToBinary',        // Input executable path
    destinationStream: 'outputStream',     // Write stream for output binary (REQUIRED)
    msh: 'mshContent',                     // MSH policy data as Buffer
    peinfo: {}                              // Optional pre-parsed PE header info
}
```

#### mshLength() - Line 22

**Reads embedded MSH length from integrated binary.**

**Implementation (Lines 22-37):**
```javascript
function mshLength() {
    var exesize = require('fs').statSync(process.execPath).size;
    var fd = require('fs').openSync(process.execPath, "rb");
    var buffer = Buffer.alloc(20);
    require('fs').readSync(fd, buffer, 0, buffer.length, exesize - 20);

    if(buffer.slice(4).toString('hex') == exeMeshPolicyGuid) {
        return (buffer.readUInt32BE(0));
    } else {
        return (0);
    }
}
```

**Returns:** Length of embedded MSH data in current executable, or 0 if none found

**Magic GUID Check (Line 29):**
- Reads final 20 bytes of executable
- Checks if bytes 4-19 match exeMeshPolicyGuid
- Bytes 0-3 contain MSH length in big-endian format

#### Platform Detection (Lines 59-71)

```javascript
if (!options.platform) {
    try {
        options.peinfo = require('PE_Parser')(options.sourceFileName);
        options.platform = 'win32';
    } catch(e) {
        options.platform = 'other';
    }
}
```

**Auto-detects Windows binaries** by attempting PE parsing. Falls back to 'other' if parsing fails.

### Unsigned Binary Embedding (Lines 86-105)

**For unsigned Windows and Linux binaries:**

```javascript
if ((options.platform == 'win32' && options.peinfo.CertificateTableAddress == 0) ||
    options.platform != 'win32') {

    // Stream source binary
    options.destinationStream.sourceStream = require('fs').createReadStream(
        options.sourceFileName, { flags: 'rb' });

    // On stream end, append MSH + length + GUID
    options.destinationStream.sourceStream.on('end', function () {
        // Write MSH content
        this.options.destinationStream.write(this.options.msh);

        // Write MSH length (4 bytes, big-endian)
        var sz = Buffer.alloc(4);
        sz.writeUInt32BE(this.options.msh.length, 0);
        this.options.destinationStream.write(sz);

        // Write magic GUID (16 bytes)
        var mshBuf = Buffer.from(exeMeshPolicyGuid, 'hex');
        if (this.options.randomGuid) { mshBuf.randomFill(); }
        this.options.destinationStream.write(mshBuf, function () { this.end(); });
    });

    // Pipe entire source binary without ending stream
    options.destinationStream.sourceStream.pipe(options.destinationStream, { end: false });
}
```

**Binary Layout:**
```
[Original Binary] [MSH Content] [Length(4)] [GUID(16)]
```

### Signed Binary Embedding (Lines 106-169)

**For Authenticode-signed Windows binaries with certificate table preservation:**

**Challenge:** Signed binaries have PE certificate table. Adding data after the binary invalidates the signature. Solution: Insert MSH data inside the certificate table, updating table size fields accordingly.

#### Step 1: Calculate Padding (Line 109)

```javascript
options.mshPadding = (8 - ((options.peinfo.certificateDwLength + options.msh.length + 20) % 8)) % 8;
```

QuadWord-align the combined size of existing certificate + MSH data + metadata.

#### Step 2: Update Certificate Table Size (Lines 111-116)

```javascript
console.log('old table size = ' + options.peinfo.CertificateTableSize);
options.peinfo.CertificateTableSize += (options.msh.length + 20 + options.mshPadding);
console.log('new table size = ' + options.peinfo.CertificateTableSize);
console.log('old certificate dwLength = ' + options.peinfo.certificateDwLength);
options.peinfo.certificateDwLength += (options.msh.length + 20 + options.mshPadding);
console.log('new certificate dwLength = ' + options.peinfo.certificateDwLength);
```

Both the PE certificate table size and the internal Authenticode certificate dwLength field need updating.

#### Step 3: Multi-Block Streaming (Lines 120-168)

Three-stage write process to reconstruct binary with updated certificate sizes:

**Block 1: Binary up to CertificateTableSize field (Lines 120-128)**
```javascript
options.destinationStream.sourceStream = require('fs').createReadStream(
    options.sourceFileName,
    { flags: 'rb', start: 0, end: options.peinfo.CertificateTableSizePos - 1});
// On end: Write new CertificateTableSize (4 bytes, little-endian)
sz.writeUInt32LE(this.options.peinfo.CertificateTableSize, 0);
```

**Block 2: Data between CertificateTableSize and certificate dwLength field (Lines 131-139)**
```javascript
var source2 = require('fs').createReadStream(
    options.sourceFileName,
    { flags: 'rb',
      start: this.options.peinfo.CertificateTableSizePos + 4,
      end: this.options.peinfo.CertificateTableAddress - 1});
// On end: Write new certificateDwLength (4 bytes, little-endian)
sz.writeUInt32LE(this.options.peinfo.certificateDwLength, 0);
```

**Block 3: Rest of binary + MSH + padding + length + GUID (Lines 142-162)**
```javascript
var source3 = require('fs').createReadStream(
    options.sourceFileName,
    { flags: 'rb', start: this.options.peinfo.CertificateTableAddress + 4 });
// On end:
// - Write padding (if needed)
// - Write MSH content
// - Write MSH length (4 bytes, big-endian)
// - Write GUID (16 bytes)
```

**Binary Layout (Signed):**
```
[Block 1: Up to CertSize]
[Updated CertSize(4)]
[Block 2: Between CertSize and CertDwLength]
[Updated CertDwLength(4)]
[Block 3: Rest of binary]
[Padding]
[MSH Content]
[Length(4)]
[GUID(16)]
```

### Command-Line Usage (Lines 172-232)

```bash
MSH_Installer.js -o outputFile -i mshFile
MSH_Installer.js -mshlen
```

**Parameters (Lines 185-202):**
- `-o <file>` - Output filename (REQUIRED)
- `-i <file>` - Input MSH file (REQUIRED)
- `-mshlen` - Display integrated MSH length and exit

**Validation (Line 206):**
```javascript
if (process.argv.length != 5 || outputFile == null || inputFile == null) {
    console.log('usage: ... MSH_Installer.js -o outputFile -i mshFile');
    process.exit();
}
```

**Execution (Lines 213-232):**
1. Read MSH file (Line 215)
2. Create output write stream (Line 225)
3. Call addMsh() with options (Line 232)
4. Exit on stream close (Line 231)

## Dependencies

### MeshAgent Module Dependencies

#### PE_Parser (Lines 64, 81)

```javascript
options.peinfo = require('PE_Parser')(options.sourceFileName);
```

**Purpose:** Parses Windows PE headers to extract certificate information

**Used Properties:**
- `CertificateTableAddress` - File offset of certificate table
- `CertificateTableSize` - Total size of certificate table
- `CertificateTableSizePos` - Position of CertificateTableSize field in PE header
- `certificateDwLength` - Internal Authenticode dwLength field

**Source:** Custom MeshAgent module for PE binary parsing

### Node.js Core Module Dependencies

#### fs (Lines 24-27, 89, 120, 131, 142, 215, 225)

```javascript
require('fs')
```

**Methods Used:**
- `statSync(path)` - Get executable file size
- `openSync(path, flags)` - Open file descriptor
- `readSync(fd, buffer, offset, length, position)` - Read bytes at specific position
- `closeSync(fd)` - Close file descriptor
- `createReadStream(path, options)` - Stream file with start/end options
- `createWriteStream(path, options)` - Write output binary
- `readFileSync(path)` - Read MSH policy file

**Purpose:** File system access for reading and writing binaries

### Platform Binary Dependencies

**None** - Pure JavaScript implementation using Buffer manipulation

## Technical Notes

### Authenticode Signature Preservation

**Key Insight:** Windows validates certificate table size fields before validating signature:
- PE CertificateTableSize field (offset in PE optional header)
- Authenticode dwLength field inside certificate structure

By updating both fields, the binary can be extended while preserving Authenticode validation.

**Why It Works:**
1. Windows OS reads CertificateTableSize from PE header
2. Uses that size to extract and verify certificate
3. As long as table size is correct, certificate validates
4. MSH data placed after certificate doesn't affect signature

### Big-Endian vs Little-Endian

**Little-Endian (LE):** PE header fields and certificateDwLength
```javascript
sz.writeUInt32LE(value, 0);
```

**Big-Endian (BE):** MSH length appended to binary
```javascript
sz.writeUInt32BE(this.options.msh.length, 0);
```

Different conventions for different sections of the binary.

### Magic GUIDs

**JavaScript GUID (Line 35):**
```javascript
const exeJavaScriptGuid = 'B996015880544A19B7F7E9BE44914C18';
```

**MSH Policy GUID (Line 18):**
```javascript
const exeMeshPolicyGuid = 'B996015880544A19B7F7E9BE44914C19';
```

These unique identifiers allow different types of embedded data to coexist and be identified.

### Randomized GUID Option (Line 100, 159)

```javascript
if (this.options.randomGuid) { mshBuf.randomFill(); }
```

Optional feature to randomize GUID for uniqueness. Useful for tracking different binary builds.

### QuadWord Alignment (Line 109)

```javascript
options.mshPadding = (8 - ((options.peinfo.certificateDwLength + options.msh.length + 20) % 8)) % 8;
```

Ensures binary data aligns to 8-byte boundaries for performance and reliability.

### Stream Piping Design (Lines 104, 165, 168)

```javascript
options.destinationStream.sourceStream.pipe(options.destinationStream, { end: false });
```

Uses `{ end: false }` to prevent auto-closing the write stream. Allows multiple sequential writes before closing.

## Summary

MSH_Installer.js enables embedding Mesh Service Host policy configuration into Windows executables while maintaining Authenticode signatures. It intelligently handles both unsigned binaries (simple append) and signed binaries (certificate-aware manipulation).

**Placed in modules_macos_NEVER** because:
- Windows PE binary format is fundamentally Windows-only
- Authenticode signing is Windows-specific mechanism
- Certificate table manipulation is PE-specific
- No equivalent for macOS code signing or Mach-O binaries

**Key Strengths:**
- Preserves Authenticode signatures on signed binaries
- Supports both signed and unsigned binary integration
- Auto-detects platform and binary format
- Multiple integration methods (module export and command-line)
- Proper QuadWord alignment for binary stability

**Related Modules:**
- exe.js - Embeds JavaScript (uses exeJavaScriptGuid)
- PE_Parser.js - Parses PE headers (required dependency)
