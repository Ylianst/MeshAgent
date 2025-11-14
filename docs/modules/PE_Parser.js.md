# PE_Parser.js

Windows PE (Portable Executable) binary format parser extracting header information, section data, version resources, and certificate details from .exe and .dll files. Provides comprehensive analysis of PE binary structure including DOS header, NT header, optional header, sections, and Authenticode certificate data.

## Platform

**Supported Platforms:**
- Windows - Full support for PE binary analysis
- Linux - Full support (can parse Windows binaries on Linux systems)
- FreeBSD - Full support (cross-platform binary analysis)

**Excluded Platforms:**
- macOS - Not excluded due to lack of technical capability, but typically not used since macOS lacks native Windows binaries

**Placement in modules_macos_NEVER:**

While technically capable of cross-platform operation, PE_Parser.js is in this directory because:

1. **Windows Binary Analysis Focus** - The module exclusively parses Windows PE format (lines 20-54 validate DOS and PE headers with magic numbers '5A4D' for MZ header and '50450000' for PE signature). macOS doesn't produce PE binaries.

2. **Authenticode Certificate Extraction** - Lines 126-135 extract Authenticode certificates which are Windows-specific signing mechanism. macOS uses code signing with different infrastructure.

3. **Windows Version Resources** - Lines 91-94, 136-343 parse Windows VERSIONINFO resource structures (VS_FIXEDFILEINFO, StringFileInfo) which exist only in Windows PE binaries.

4. **PE-Specific Headers** - Lines 96-117 parse PE optional header with Windows-specific data directories and structure. Mach-O binaries have completely different header format.

5. **Use Context** - In the MeshAgent ecosystem, PE_Parser is used by exe.js and MSH_Installer.js, both Windows-only tools for creating .exe files.

**Technical Note:** While the parser can technically run on non-Windows systems, the binaries it parses are Windows-exclusive, and its output is only meaningful in Windows build contexts.

## Functionality

### Core Purpose

Parses Windows PE executable structure and extracts binary metadata including format architecture, sections, Authenticode certificates, version information, and RVA (Relative Virtual Address) entries.

### Main Parse Function: parse(exePath) - Line 20

**Entry point that reads and analyzes PE binary at specified path.**

**Returns Object with:**
- format - 'x86' or 'x64'
- sections - Map of PE sections (.text, .data, .rsrc, etc.)
- CertificateTableAddress - File offset of certificate table
- CertificateTableSize - Total size of certificate table
- CertificateTableSizePos - Position of size field in PE header
- certificateDwLength - Authenticode dwLength field
- certificate - Base64-encoded certificate (if present)
- versionInfo - Parsed VERSIONINFO resource
- rva - Array of Relative Virtual Address entries

### DOS Header Parsing (Lines 23-35)

```javascript
var dosHeader = Buffer.alloc(64);
bytesRead = fs.readSync(fd, dosHeader, 0, 64, 0);

// Validate MZ signature (DOS stub)
if (dosHeader.readUInt16LE(0).toString(16).toUpperCase() != '5A4D') {
    throw ('unrecognized binary format');
}
```

**Validates:** Binary begins with "MZ" signature (0x5A4D)

**DOS Header Layout:**
- Offset 0x00-0x01: Magic number (0x5A4D = "MZ")
- Offset 0x3C: PE header offset (32-bit little-endian, line 38)

### NT Header Parsing (Lines 37-54)

```javascript
bytesRead = fs.readSync(fd, ntHeader, 0, ntHeader.length, dosHeader.readUInt32LE(60));

// Validate PE signature
if (ntHeader.slice(0, 4).toString('hex') != '50450000') {
    throw ('not a PE file');
}

// Determine architecture
switch (ntHeader.readUInt16LE(4).toString(16)) {
    case '14c': // 32 bit
        retVal.format = 'x86';
        break;
    case '8664': // 64 bit
        retVal.format = 'x64';
        break;
}
```

**NT Header Structure (24 bytes):**
- Offset 0x00-0x03: Signature "PE\0\0" (0x50450000)
- Offset 0x04-0x05: Machine type (architecture)
  - 0x014C = x86 (32-bit)
  - 0x8664 = x64 (64-bit)
- Offset 0x06-0x07: Number of sections
- Offset 0x14: Optional header size

### Optional Header Parsing (Lines 60-123)

```javascript
optHeader = Buffer.alloc(ntHeader.readUInt16LE(20));
bytesRead = fs.readSync(fd, optHeader, 0, optHeader.length, dosHeader.readUInt32LE(60) + 24);
```

**For 32-bit binaries (Lines 98-105):**
```javascript
case '10B': // 32 bit binary
    numRVA = optHeader.readUInt32LE(92);           // Number of RVA entries
    rvaStart = 96;                                  // Start of RVA array
    retVal.CertificateTableAddress = optHeader.readUInt32LE(128);
    retVal.CertificateTableSize = optHeader.readUInt32LE(132);
    retVal.CertificateTableSizePos = dosHeader.readUInt32LE(60) + 24 + 132;
    retVal.rvaStartAddress = dosHeader.readUInt32LE(60) + 24 + 96;
    break;
```

**For 64-bit binaries (Lines 106-112):**
```javascript
case '20B': // 64 bit binary
    numRVA = optHeader.readUInt32LE(108);
    rvaStart = 112;
    retVal.CertificateTableAddress = optHeader.readUInt32LE(144);
    retVal.CertificateTableSize = optHeader.readUInt32LE(148);
    retVal.CertificateTableSizePos = dosHeader.readUInt32LE(60) + 24 + 148;
    retVal.rvaStartAddress = dosHeader.readUInt32LE(60) + 24 + 112;
    break;
```

**Note:** 32-bit and 64-bit binaries have different optional header sizes and different offsets for certificate table fields.

### Section Header Parsing (Lines 71-94)

```javascript
var sect = Buffer.alloc(40);
for (z = 0; z < 16; ++z) {
    fs.readSync(fd, sect, 0, sect.length, retVal.sectionHeadersAddress + (z * 40));
    if (sect[0] != 46) { break; }  // 46 = ASCII '.'

    var s = {};
    s.sectionName = sect.slice(0, 8).toString().trim('\0');
    s.virtualSize = sect.readUInt32LE(8);
    s.virtualAddr = sect.readUInt32LE(12);
    s.rawSize = sect.readUInt32LE(16);
    s.rawAddr = sect.readUInt32LE(20);
    s.characteristics = sect.readUInt32LE(36);
    retVal.sections[s.sectionName] = s;
}
```

**Section Header Structure (40 bytes each):**
- Offset 0x00: Name (8 bytes, ASCII, null-terminated)
- Offset 0x08: Virtual size
- Offset 0x0C: Virtual address
- Offset 0x10: Raw size (in file)
- Offset 0x14: Raw address (in file)
- Offset 0x24: Characteristics (flags)

**Common Sections:**
- .text - Executable code
- .data - Initialized data
- .rsrc - Resources (including VERSIONINFO)
- .reloc - Relocation information

### Resource Section Parsing (Lines 91-94, 168-192)

```javascript
if (retVal.sections['.rsrc'] != null) {
    retVal.resources = readResourceTable(fd, retVal.sections['.rsrc'].rawAddr, 0);
}

function readResourceTable(fd, ptr, offset) {
    var buf = Buffer.alloc(16);
    fs.readSync(fd, buf, 0, buf.length, ptr + offset);
    var r = {};
    r.characteristics = buf.readUInt32LE(0);
    r.timeDateStamp = buf.readUInt32LE(4);
    r.majorVersion = buf.readUInt16LE(8);
    r.minorVersion = buf.readUInt16LE(10);
    var numberOfNamedEntries = buf.readUInt16LE(12);
    var numberofIdEntries = buf.readUInt16LE(14);
    r.entries = [];
    // ... recursively parse resource entries
}
```

**Recursively parses resource tree structure** to find VERSIONINFO resources.

### Authenticode Certificate Extraction (Lines 126-135)

```javascript
if (retVal.CertificateTableAddress) {
    var hdr = Buffer.alloc(8);
    fs.readSync(fd, hdr, 0, hdr.length, retVal.CertificateTableAddress);

    // Read certificate data
    retVal.certificate = Buffer.alloc(hdr.readUInt32LE(0));
    fs.readSync(fd, retVal.certificate, 0, retVal.certificate.length,
                retVal.CertificateTableAddress + hdr.length);

    // Convert to base64
    retVal.certificate = retVal.certificate.toString('base64');
    retVal.certificateDwLength = hdr.readUInt32LE(0);
}
```

**Extracts Authenticode certificate** and encodes as base64 string.

### RVA (Relative Virtual Address) Parsing (Lines 120-124)

```javascript
retVal.rva = [];
for (z = 0; z < retVal.rvaCount && z < 32; ++z) {
    retVal.rva.push({
        virtualAddress: optHeader.readUInt32LE(rvaStart + (z * 8)),
        size: optHeader.readUInt32LE(rvaStart + 4 + (z * 8))
    });
}
```

**RVA Directories (important indices):**
- 0: Export Table
- 1: Import Table
- 2: Resource Table
- 3: Exception Table
- 4: Certificate Table
- 5: Base Relocation Table
- etc.

### Version Information Parsing (Lines 136-343)

**Retrieves version info from resource section (Lines 194-211):**
```javascript
function getVersionInfoData(fd, header) {
    var ptr = header.sections['.rsrc'].rawAddr;
    for (var i = 0; i < header.resources.entries.length; i++) {
        if (header.resources.entries[i].name == 16) { // Resource type 16 = VERSIONINFO
            const verInfo = header.resources.entries[i].table.entries[0].table.entries[0].item;
            const actualPtr = (verInfo.offsetToData - header.sections['.rsrc'].virtualAddr) + ptr;
            var buffer = Buffer.alloc(verInfo.size);
            require('fs').readSync(fd, buffer, 0, buffer.length, actualPtr);
            return buffer;
        }
    }
    return null;
}
```

**VS_FIXEDFILEINFO Structure (Lines 213-233):**
```javascript
function readFixedFileInfoStruct(buf, ptr) {
    if (buf.length - ptr < 50) return null;
    var r = {};
    r.dwSignature = buf.readUInt32LE(ptr);
    if (r.dwSignature != 0xFEEF04BD) return null;
    r.dwFileVersionMS = buf.readUInt32LE(ptr + 8);      // Major.Minor
    r.dwFileVersionLS = buf.readUInt32LE(ptr + 12);     // Build.Patch
    r.dwProductVersionMS = buf.readUInt32LE(ptr + 16);
    r.dwProductVersionLS = buf.readUInt32LE(ptr + 20);
    r.dwFileOS = buf.readUInt32LE(ptr + 32);
    r.dwFileType = buf.readUInt32LE(ptr + 36);
    return r;
}
```

**Signature:** 0xFEEF04BD identifies valid FIXEDFILEINFO

**StringFileInfo Parsing (Lines 244-264):**
- Parses key-value pairs like ProductName, FileDescription, CompanyName
- Handles Unicode (UTF-16) encoding
- Supports nested table structures

**Final Integration (Lines 329-343):**
```javascript
function getVersionInfo(fd, header, resources) {
    var r = {};
    var b = getVersionInfoData(fd, header, resources);
    var info = readVersionInfo(b, 0);
    if ((info == null) || (info.stringFiles == null)) return null;
    var StringFileInfo = null;
    for (var i in info.stringFiles) {
        if (info.stringFiles[i].szKey == 'StringFileInfo') {
            StringFileInfo = info.stringFiles[i];
        }
    }
    // ... extract strings into result object
    for (var i in strings) { r[strings[i].key] = strings[i].value; }
    return r;
}
```

Returns dictionary of version strings accessible by key name.

### Version Info Encoding (Lines 345-442)

**encodeVersionInfo(info)** - Reverses the parsing process to re-encode modified version information back into binary format. Handles:
- Recalculating all length fields
- Proper Unicode encoding
- 4-byte alignment padding
- Nested structure offsets

## Dependencies

### Node.js Core Module Dependencies

#### fs (Lines 17, 23-24, 31, 38, 62, 75, 130-132, 147, 160, 171, 184, 205)

```javascript
var fs = require('fs');
```

**Methods Used:**
- `openSync(path, flags)` - Open file for binary reading
- `readSync(fd, buffer, offset, length, position)` - Read specific byte ranges
- `closeSync(fd)` - Close file descriptor

**Purpose:** Low-level binary file access to read PE structures

#### _GenericMarshal (Lines 152, 255, 273, 294, 296, 317, 407, 413, 422, 430, 432)

```javascript
require('_GenericMarshal').CreateVariable(buf).Wide2UTF8
```

**Purpose:** Convert Unicode (UTF-16) strings to UTF-8 JavaScript strings

**Usage in Context:**
- Extracting resource strings from VERSIONINFO
- Converting Windows Unicode format to readable text

### Platform Binary Dependencies

**None** - Pure JavaScript with only Node.js core and utility modules

## Technical Notes

### Endianness Handling

**Little-Endian (LE):** Used consistently throughout PE format
```javascript
buf.readUInt32LE(offset)
buf.readUInt16LE(offset)
```

**Why Little-Endian:** PE format is Windows x86-centric, which uses LE byte order.

### Architecture-Specific Offsets

**32-bit vs 64-bit Differences (Lines 98-112):**

The optional header size varies:
- 32-bit: 96 byte offset for RVA start
- 64-bit: 112 byte offset for RVA start

And certificate table position differs:
- 32-bit: Offset 128 and 132
- 64-bit: Offset 144 and 148

Parser automatically detects architecture and uses correct offsets.

### Resource Recursion

**Two-Level Navigation (Lines 188-192):**

Resource tables are hierarchical:
1. Top-level table (indexed by resource type)
2. Name/Language tables (indexed by resource name/language)
3. Data entry (points to actual resource data)

Parser recursively descends this tree to find VERSIONINFO (type 16).

### Pointer Arithmetic

**File Offset Calculations:**

```javascript
var actualPtr = (verInfo.offsetToData - header.sections['.rsrc'].virtualAddr) + ptr;
```

Converts from:
- Virtual address (used in headers)
- To file offset (used in fs.readSync)

By subtracting virtual address and adding section raw address.

### Version String Encoding

**UTF-16 LE Format:** Version strings are Unicode (UTF-16 LE)

Line 317 uses _GenericMarshal to decode:
```javascript
r.szKey = require('_GenericMarshal').CreateVariable(buf.slice(...)).Wide2UTF8;
```

### Certificate Table Modification Support

The parser extracts all necessary offsets (CertificateTableAddress, CertificateTableSizePos) to enable tools like MSH_Installer.js to modify and re-sign binaries.

**Information Extracted:**
- Where certificate table starts in file
- Where its size field is located
- How large it is
- The certificate content itself

This allows modifying the binary while preserving signature validity.

## Summary

PE_Parser.js provides comprehensive Windows PE binary analysis, extracting architecture information, sections, Authenticode certificates, version resources, and RVA entries. Supports both 32-bit and 64-bit binaries with proper offset handling.

**Placed in modules_macos_NEVER** because:
- Parses Windows PE binary format (not used on macOS)
- Extracts Windows-specific certificate information
- Analyzes Windows version resources
- Used by Windows-only tools (exe.js, MSH_Installer.js)

**Key Capabilities:**
- Full PE header parsing (DOS, NT, Optional)
- Section enumeration and analysis
- Authenticode certificate extraction
- Windows version resource parsing
- RVA directory extraction
- Version information re-encoding

**Dependencies in MeshAgent:**
- Used by exe.js for signing checks
- Used by MSH_Installer.js for certificate-aware embedding
