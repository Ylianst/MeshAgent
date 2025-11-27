# smbios.js

System Management BIOS (SMBIOS) table parsing and hardware information extraction. Provides cross-platform access to BIOS-level hardware information including processor details, memory configuration, system UUID, and Intel AMT/vPro capabilities through both Windows firmware tables and Linux dmidecode.

## Platform

**Supported Platforms:**
- Windows - Full support via Kernel32 firmware table API
- Linux - Full support via /usr/sbin/dmidecode
- macOS - Partial support (pure parsing only, no data retrieval)
- FreeBSD - Not supported

**Excluded Platforms:**
- macOS - Excluded from binary distribution (module is platform-agnostic)

**Placement in modules_macos_NEVER:**

Despite being partially platform-agnostic, this module is in `modules_macos_NEVER` because:

1. **Data Retrieval Dependency** - Active data gathering requires platform-specific mechanisms:
   - Line 37-42: Windows platform check for Kernel32 firmware table API
   - Line 44-72: Linux platform check for dmidecode execution
   - Line 154: Returns null on unsupported platforms
   - Module can parse SMBIOS data on any platform but cannot retrieve it on macOS

2. **Use Case Context** - SMBIOS information primarily used for:
   - Hardware identification on managed systems
   - Intel AMT/vPro capability detection (Lines 269-309)
   - System configuration assessment
   - Typically needed on Windows/Linux servers for management
   - Not relevant to macOS system management workflows

3. **AMT Detection** - Core functionality targets Intel platform detection:
   - Lines 272-308: amtInfo() parses Intel AMT capabilities
   - Checks for Intel vPro indicators (Line 282)
   - Returns Intel ME version information (Lines 287, 290)
   - macOS has no Intel AMT, making this feature moot

4. **Downstream Usage** - Used by modules excluded from macOS:
   - CSP.js (Line 283): Calls require('smbios')
   - amt.js and other management modules use SMBIOS data
   - Chain of dependencies justifies macOS exclusion

**Technical Note:** The module's parsing functions (parse, processorInfo, systemInfo, etc.) are purely computational and platform-agnostic. The platform exclusion is practical - on macOS, the module cannot retrieve data and the information would not be actionable.

## Functionality

### Core Purpose

Reads and parses SMBIOS (System Management BIOS) tables to extract hardware and management capabilities:
- Retrieves raw SMBIOS data from system firmware
- Parses structured binary SMBIOS tables
- Extracts processor, memory, system, and AMT information
- Supports Windows (firmware tables) and Linux (dmidecode) data sources
- Provides high-level parsing methods for common table types

### Constructor: SMBiosTables()

**Usage:**
```javascript
var smbios = require('smbios');
smbios.get(function(data) { ... });
```

**Instance Properties:**
- _ObjectID: 'SMBiosTable' (Line 36)
- Platform-specific members (Lines 37-42 Windows, 44-72 Linux)
- smTableTypes: Enumeration of SMBIOS table type names (Lines 311-356)

### get(callback) Method - Lines 113-154

**Syntax:**
```javascript
smbios.get(callback);
// or synchronous:
var data = smbios.get();
```

**Callback:**
```javascript
callback(parsedData)  // parsedData is object returned by _parse()
```

**Windows Implementation (Lines 114-129):**

1. **Retrieve Raw Table (Lines 115-120):**
   ```javascript
   var size = this._native.GetSystemFirmwareTable(RSMB, 0, 0, 0).Val;
   var buffer = this._marshal.CreateVariable(size);
   var written = this._native.GetSystemFirmwareTable(RSMB, 0, buffer, size).Val;
   ```
   - RSMB = 0x52534D42 (magic constant for SMBIOS, Line 20)
   - GetSystemFirmwareTable queries Windows firmware table provider
   - Returns raw SMBIOS binary data

2. **Parse Structure (Lines 123-127):**
   - Reads length from buffer offset 4
   - Extracts SMBIOS data starting at offset 8
   - Calls _parse() to structure binary data
   - Invokes callback (Line 129) or returns directly

**Linux Implementation (Lines 131-152):**

1. **Execute dmidecode (Line 133):**
   ```javascript
   this.child = require('child_process').execFile('/usr/sbin/dmidecode', ['dmidecode', '-u']);
   ```
   - Executes system dmidecode command with -u (raw output) flag
   - Captures stdout to MemoryStream

2. **Process Output (Lines 138-151):**
   - Collects dmidecode output (Line 138)
   - Waits for process exit (Line 139)
   - Canonicalizes data format (Line 147)
   - Parses canonicalized output (Line 148)
   - Invokes callback with result (Line 149)

3. **Canonicalization (Lines 45-71):**
   Converts dmidecode human-readable format to binary:
   ```javascript
   var lines = data.toString().split('Header and Data:\x0A');
   ```
   - Splits output by "Header and Data:" lines (Line 46)
   - Extracts header hex string (Line 52)
   - Extracts string values (Lines 54-62)
   - Reconstructs binary format (Lines 53, 61-62)
   - Appends null terminator (Line 62)

**Unsupported Platforms (Line 154):**
Returns null or empty data for non-Windows/Linux

### _parse(SMData) Method - Lines 73-111

**Purpose:** Structures raw binary SMBIOS data into JavaScript objects

**Process:**
1. Iterates through SMBIOS structures (Line 80)
2. For each structure:
   - Reads type and length (Lines 82-83)
   - Extracts data portion (Line 86)
   - Stores in ret[type] array (Lines 85-86)
   - Extracts string table (Lines 90-105)
   - Associates with structure via _strings property (Line 100)

**Structure Format:**
- Byte 0: Type (table type ID)
- Byte 1: Length (structure size)
- Bytes 2-3: Handle (unused)
- Bytes 4+: Data
- After data: null-terminated string table

**Result:**
```javascript
{
    1: [               // Type 1 = System Information
        <Buffer>,      // Structure data
        <Buffer>,      // Another structure of same type
        ...
    ],
    4: [               // Type 4 = Processor
        <Buffer>,
        ...
    ],
    ...
}
```

Each buffer has _strings property containing parsed strings.

### parse(data) Method - Lines 156-199

**Purpose:** High-level wrapper that calls multiple parsing methods

**Syntax:**
```javascript
var result = smbios.parse(rawData);
```

**Result Object:**
```javascript
{
    processorInfo: [...],      // Line 160
    memoryInfo: {...},         // Line 167
    systemInfo: {...},         // Line 174
    systemSlots: [...],        // Line 181
    amtInfo: {...}             // Line 188
}
```

Silently catches exceptions if individual parsers fail (Lines 158-177)

### processorInfo(data) Method - Lines 201-226

**Syntax:**
```javascript
var procs = smbios.processorInfo(data);
```

**Result Array:**
```javascript
[
    {
        _ObjectID: 'SMBiosTables.processorInfo',
        Processor: 'CPU',           // Processor type string
        MaxSpeed: '2400 Mhz',       // From offset 16-17 LE
        Cores: 4,                   // From offset 31 (if present)
        Threads: 8,                 // From offset 33 (if present)
        Populated: 1,               // 1 if populated, 0 otherwise
        Status: 'Enabled',          // From status string enum
        Socket: 'Socket H',         // _strings[offset 0 - 1]
        Manufacturer: 'Intel',      // _strings[offset 3 - 1]
        Version: 'Intel(R) Xeon...' // _strings[offset 12 - 1]
    },
    ...
]
```

**SMBIOS Table Type:** Type 4 (Processor Information)

**Data Extraction (Lines 207-223):**
- Type 4 structure (Line 207)
- Populated bit check: p[20] & 0x40 (Line 209)
- Status bits: p[20] & 0x07 (Line 210)
- Max speed: p.readUInt16LE(16) (Line 214)
- Cores: p[31] (Line 215)
- Threads: p[33] (Line 216)
- Strings indexed from _strings array

### memoryInfo(data) Method - Lines 227-238

**Syntax:**
```javascript
var mem = smbios.memoryInfo(data);
```

**Result Object:**
```javascript
{
    _ObjectID: 'SMBiosTables.memoryInfo',
    location: 'System Board',      // From memoryLocation map
    maxCapacityKb: 262144          // From offset 3-6 LE
}
```

**SMBIOS Table Type:** Type 16 (Physical Memory Array)

**Data Extraction (Lines 230-235):**
- Location map lookup: m[0] (Line 232)
- Capacity: m.readUInt32LE(3) (Line 233)
- Special case: 0x80000000 → 'A really big number' (Lines 234-235)

### systemInfo(data) Method - Lines 239-257

**Syntax:**
```javascript
var sysInfo = smbios.systemInfo(data);
```

**Result Object:**
```javascript
{
    _ObjectID: 'SMBiosTables.systemInfo',
    uuid: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
    wakeReason: 'Power Switch'
}
```

**SMBIOS Table Type:** Type 1 (System Information)

**Data Extraction (Lines 243-255):**
- UUID from 16-byte structure at offset 4-19 (Line 246)
- UUID formatting: 4-2-2-2-6 byte fields in specified endianness (Lines 248-252)
- Wake reason lookup: si[20] → wakeReason enum (Line 254)

**UUID Endianness:**
- First 4 bytes: little-endian
- Next 2 bytes: little-endian
- Next 2 bytes: little-endian
- Next 2 bytes: big-endian
- Last 6 bytes: as-is

### systemSlots(data) Method - Lines 258-268

**Syntax:**
```javascript
var slots = smbios.systemSlots(data);
```

**Result Array:**
```javascript
[
    { name: 'PCI Express x16' },
    { name: 'PCI Express x1' },
    ...
]
```

**SMBIOS Table Type:** Type 9 (System Slots)

**Data Extraction (Lines 261-265):**
- Iterates through Type 9 structures
- Retrieves slot name from _strings[ss[0] - 1] (Line 264)

### amtInfo(data) Method - Lines 269-309

**Syntax:**
```javascript
var amt = smbios.amtInfo(data);
```

**Result Object (Without Intel AMT):**
```javascript
{ AMT: false }
```

**Result Object (With Intel AMT):**
```javascript
{
    AMT: true,
    enabled: true,                  // Bit 4 of data[5]
    storageRedirection: false,      // Bit 5 of data[6]
    serialOverLan: true,            // Bit 6 of data[7]
    kvm: true,                       // Bit 13 of data[14]
    TXT: true,                       // Intel TXT capable
    VMX: true,                       // Intel VT capable
    MEBX: '11.8.92.2324',           // ME BIOS Extension version
    ManagementEngine: '12.0.38.1234' // ME firmware version
}
```

**SMBIOS Detection (Lines 272-275):**

Table Type 130 (OEM data) checked for '$AMT' signature:
```javascript
if (data[130] && data[130].peek().slice(0, 4).toString() == '$AMT')
```

**Capabilities (Lines 275-280):**
- data[4]: AMT present indicator
- data[5]: Enabled flag
- data[6]: Storage redirection
- data[7]: Serial over LAN (SOL)
- data[14]: KVM support

**vPro Detection (Lines 282-287):**

Table Type 131 (OEM data) checked for 'vPro' signature:
```javascript
if (data[131].peek().slice(52, 56).toString() == 'vPro')
```

**vPro Capabilities (Lines 285-287):**
- Bit 2: TXT capable (Bit 3: enabled)
- Bit 4: VMX capable (Bit 5: enabled)
- MEBX version: readUInt16LE at offsets 4, 6, 8, 10
- ME version: readUInt16LE at offsets 20, 22, 28, 30 (different order)

### SMBIOS Table Type Map - Lines 311-356

Enumeration of standard SMBIOS table types:
```javascript
smTableTypes = {
    0: 'BIOS information',
    1: 'System information',
    4: 'Processor information',
    16: 'Physical memory array',
    130: 'Intel AMT OEM data',
    131: 'Intel vPro settings',
    ...
}
```

Total 40+ table types defined (Lines 311-356)

## Dependencies

### Node.js Core Modules

#### child_process (Line 133)

```javascript
require('child_process').execFile('/usr/sbin/dmidecode', ['dmidecode', '-u'])
```

**Platform:** Linux only

**Purpose:** Execute system dmidecode command

**Methods:**
- execFile(command, args, callback) - Run executable
- on('exit', callback) - Process completion
- on('data', callback) on stdout - Capture output
- Properties: stdout, stderr, etc.

### MeshAgent Module Dependencies

#### _GenericMarshal (Line 38-42)

```javascript
this._marshal = require('_GenericMarshal');
this._native = this._marshal.CreateNativeProxy("Kernel32.dll");
this._native.CreateMethod('EnumSystemFirmwareTables');
this._native.CreateMethod('GetSystemFirmwareTable');
```

**Platform:** Windows only

**Purpose:** Native API access to firmware tables

**Methods:**
- CreateNativeProxy(dllName) - Load DLL
- CreateMethod(name) - Define native method
- CreateVariable(size) - Allocate memory
- PointerSize - Architecture (4 or 8)

**Kernel32 Methods:**
- GetSystemFirmwareTable(provider, table, buffer, size) - Get firmware data

#### MemoryStream (Line 47, 132)

```javascript
var MemoryStream = require('MemoryStream');
var ms = new MemoryStream();
ms.write(buffer);
ms.buffer  // Get accumulated bytes
```

**Purpose:** Accumulate binary/text data

**Methods:**
- write(buffer/string) - Add data
- buffer property - Get accumulated bytes
- on('end', callback) - Stream end event

### Dependency Chain

```
smbios.js
├─── _GenericMarshal (Windows only, Line 38)
│    ├─── Kernel32.dll
│    └─── GetSystemFirmwareTable
├─── child_process (Linux only, Line 133)
│    └─── /usr/sbin/dmidecode
├─── MemoryStream (Line 47, 132)
│    └─── Data accumulation
└─── fs (implicit, via child_process)
     └─── /usr/sbin/dmidecode access
```

### Platform Binary Dependencies

**Windows:**
- Kernel32.dll firmware table provider interface
- System firmware with SMBIOS tables

**Linux:**
- /usr/sbin/dmidecode executable
- Linux kernel DMI (Desktop Management Interface) support
- /sys/firmware/dmi or /dev/mem access for dmidecode

## Technical Notes

### RSMB Constant

**Value (Line 20):** 0x52534D42 = 'RSMB' in ASCII

RSMB (Raw System Management BIOS) is the standard Windows firmware table provider identifier for SMBIOS data.

### Windows Firmware Tables API

**Kernel32.GetSystemFirmwareTable(provider, table, buffer, size)**

Two-call pattern:
1. First call with buffer=0 to get size
2. Second call with allocated buffer to get data

### Buffer Structure (Windows)

**Offset 0-3:** Magic number (RSMB)
**Offset 4-7:** Table length (DWORD, little-endian)
**Offset 8+:** SMBIOS structures

### Linux dmidecode Processing

**Raw Output Format:**
```
Handle 0xXXXX
  DMI type XX, YY bytes
  Header and Data:
    <hex dump of structure>
  Strings:
    <string1>
    <string2>
```

**Canonicalization:** Extracts hex header and hex-encoded strings, reconstructs binary format

### String Indexing Convention

SMBIOS strings are 1-indexed:
```javascript
var name = p._strings[p[offset] - 1];  // Subtract 1 from string index
```

Index 0 = no string, 1 = first string, 2 = second string, etc.

### Intel AMT Detection Strategy

**Table Type 130 (OEM):**
- Manufacturer-specific data
- Intel uses for AMT capability flags
- '$AMT' signature at offset 0-3

**Table Type 131 (OEM):**
- Additional Intel management data
- 'vPro' signature at offset 52-55
- Contains version information for ME and vPro

### Error Handling

**Windows Errors (Lines 158-177):**
- Individual parse methods wrapped in try-catch
- Silently returns empty/false on parse failure
- Prevents single malformed table from failing entire parse

**Linux Errors (Lines 142-144):**
- Checks minimum output size (300 bytes threshold)
- Calls callback with empty array if insufficient data

## Summary

The smbios.js module provides SMBIOS table access and parsing for Windows and Linux systems. It abstracts the platform differences (GetSystemFirmwareTable on Windows, dmidecode on Linux) and provides high-level parsing methods for processor, memory, system, and Intel management information.

**Placed in modules_macos_NEVER** because:
- Practical: Cannot retrieve SMBIOS data on macOS (no system API)
- Contextual: SMBIOS info primarily used for Intel platform management
- Downstream: Used by modules excluded from macOS (CSP.js, AMT stack)
- Actionability: Intel AMT/vPro detection not relevant on macOS

**Core functionality:**
- SMBIOS table retrieval from firmware (Windows) or system tools (Linux)
- Binary SMBIOS structure parsing
- High-level information extraction (processor, memory, system, AMT)
- Intel vPro and AMT capability detection
- Cross-platform abstraction for hardware queries

Used for system identification, inventory, and Intel management capability assessment on managed systems.
