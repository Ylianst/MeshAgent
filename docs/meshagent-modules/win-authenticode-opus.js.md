# win-authenticode-opus.js

Windows Authenticode digital signature metadata reader that extracts program description and URL information from signed executable files. Provides validation functionality to ensure MeshAgent binaries are locked to specific server configurations.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support (implicit)

**Excluded Platforms:**
- **macOS** - Implicitly excluded (no platform check, module will fail on instantiation)
- **Linux** - Implicitly excluded (no platform check, module will fail on instantiation)
- **FreeBSD** - Implicitly excluded (no platform check, module will fail on instantiation)
- **All non-Windows platforms** - Implicitly excluded

**Exclusion Reasoning:**

The module has **no explicit platform check** but is fundamentally Windows-only. It will fail immediately when attempting to load Windows-specific DLLs:

**Lines 31-35:** Module reads Authenticode signatures using Windows-exclusive cryptography DLL:
```javascript
var GM = require('_GenericMarshal');
var crypt = GM.CreateNativeProxy('Crypt32.dll');
crypt.CreateMethod('CryptQueryObject');
crypt.CreateMethod('CryptMsgGetParam');
crypt.CreateMethod('CryptDecodeObject');
```

**Why macOS/Linux are excluded:**

1. **Authenticode is Windows-Specific Digital Signature Format**
   - Authenticode: Microsoft's code signing technology for Windows PE (Portable Executable) files
   - macOS: Uses code signing with `codesign` utility and Mach-O format
   - Linux: No standardized code signing (GPG signatures, AppImage signatures, or distro-specific)
   - Completely different signature formats and verification methods

2. **PE File Format is Windows-Specific**
   - Authenticode embedded in PE (Portable Executable) format (.exe, .dll, .sys)
   - macOS uses Mach-O format
   - Linux uses ELF format
   - Different binary structures, no cross-platform compatibility

3. **Windows Cryptography API Dependencies**
   - **Crypt32.dll** - Windows Cryptography API for certificate and signature handling
   - Contains all Authenticode verification and parsing functions
   - Only exists on Windows systems
   - No equivalent on other platforms

4. **PKCS#7 Structure Parsing**
   - Authenticode uses PKCS#7 embedded signatures
   - Windows CryptoAPI provides structure parsing
   - SPC_SP_OPUS_INFO_OBJID (1.3.6.1.4.1.311.2.1.12) - Microsoft-specific OID
   - Proprietary Microsoft extension to PKCS#7

5. **Use Case is Windows Agent Verification**
   - Lines 117-153: `checkMSH()` validates MeshAgent.exe is locked to specific server
   - Reads signature from `process.execPath` (Windows executable)
   - Ensures agent can't be redirected to rogue servers
   - Security feature specific to Windows MeshAgent deployment

**macOS Alternative:**
- Code signature verification: `codesign -dv --verbose=4 /path/to/app`
- Programmatic: Security framework APIs (SecCodeCopySelf, SecCodeCheckValidity)

**Linux Alternative:**
- GPG signature verification: `gpg --verify signature.asc binary`
- AppImage: Embedded GPG signatures
- No standardized equivalent to Authenticode

## Functionality

### Core Export: read(path)

**Lines 29-99:** Main function that reads Authenticode signature metadata from a file.

**Parameters:**
- `path` - Full path to signed executable file (.exe, .dll, .sys, etc.)

**Returns:**
- Object with properties:
  - `description` - Program description string (or null if not set)
  - `url` - URL embedded in signature (or null if not set)
- `null` if:
  - File has no signature
  - Signature doesn't contain SPC_SP_OPUS_INFO
  - Decoding fails

**Algorithm:**

**Step 1: Query Signature (Lines 45-54):**
```javascript
crypt.CryptQueryObject(
    CERT_QUERY_OBJECT_FILE,              // 0x00000001 - Query file
    GM.CreateVariable(path, { wide: true }),  // File path (UTF-16)
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,  // Look for embedded PKCS#7
    CERT_QUERY_FORMAT_FLAG_BINARY,       // Binary format
    0,                                    // Reserved
    dwEncoding,                           // Output: Encoding type
    dwContentType,                        // Output: Content type
    dwFormatType,                         // Output: Format type
    hStore,                               // Output: Certificate store
    hMsg,                                 // Output: Cryptographic message
    0                                     // Not used
)
```

**Returns:**
- Non-zero: Signature found
- Zero: No signature or error

**Step 2: Get Signer Info Size (Lines 55-59):**
```javascript
crypt.CryptMsgGetParam(
    hMsg.Deref(),              // Message handle
    CMSG_SIGNER_INFO_PARAM,    // 6 - Signer info parameter
    0,                         // Index 0 (first signer)
    0,                         // NULL buffer (query size)
    dwSignerInfo               // Output: Required buffer size
)
```

**Purpose:** Determine size of CMSG_SIGNER_INFO structure

**Step 3: Retrieve Signer Info (Lines 61-67):**
```javascript
var pSignerInfo = GM.CreateVariable(dwSignerInfo.toBuffer().readUInt32LE());
crypt.CryptMsgGetParam(
    hMsg.Deref(),
    CMSG_SIGNER_INFO_PARAM,
    0,
    pSignerInfo,               // Buffer to receive data
    dwSignerInfo               // Buffer size
)
```

**Retrieves:** CMSG_SIGNER_INFO structure containing authenticated attributes

**Step 4: Enumerate Authenticated Attributes (Lines 69-95):**
```javascript
var attributes = pSignerInfo.Deref(
    GM.PointerSize == 8 ? 104 : 52,  // Offset to UnauthAttrs
    GM.PointerSize * 2               // Read count + pointer
);
var attrCount = attributes.toBuffer().readUInt32LE();

for (n = 0; n < attrCount; n++) {
    attr = attributes.Deref(GM.PointerSize, GM.PointerSize).Deref();
    attr = attr.increment(n * (GM.PointerSize == 8 ? 24 : 12));

    if (SPC_SP_OPUS_INFO_OBJID == attr.Deref().String) {
        // Found SPC_SP_OPUS_INFO attribute
    }
}
```

**Structure Offsets:**
- **32-bit:** UnauthAttrs at offset 52, each attribute 12 bytes
- **64-bit:** UnauthAttrs at offset 104, each attribute 24 bytes

**Step 5: Decode SPC_SP_OPUS_INFO (Lines 79-93):**
```javascript
var blob = attr.Deref(GM.PointerSize * 2, GM.PointerSize).Deref();
var cb = blob.Deref(0, 4).toBuffer().readUInt32LE();       // Size
var pb = blob.Deref(GM.PointerSize, GM.PointerSize).Deref();  // Data

// Get decoded structure size
crypt.CryptDecodeObject(
    ENCODING,
    GM.CreateVariable(SPC_SP_OPUS_INFO_OBJID),
    pb, cb, 0, 0, dwData
);

// Decode structure
var opus = GM.CreateVariable(dwData.toBuffer().readUInt32LE());
crypt.CryptDecodeObject(
    ENCODING,
    GM.CreateVariable(SPC_SP_OPUS_INFO_OBJID),
    pb, cb, 0, opus, dwData
);
```

**Decoding:** ASN.1 DER-encoded structure to C structure

**Step 6: Extract Fields (Line 91):**
```javascript
return ({
    description: opus.Deref().Val != 0 ?
        opus.Deref().Wide2UTF8 : null,
    url: opus.Deref(GM.PointerSize, GM.PointerSize).Deref().Val != 0 ?
        opus.Deref(GM.PointerSize, GM.PointerSize).Deref()
            .Deref(GM.PointerSize, GM.PointerSize).Deref().Wide2UTF8.trim()
        : null
});
```

**SPC_SP_OPUS_INFO Structure:**
```c
typedef struct _SPC_SP_OPUS_INFO {
    LPCWSTR pwszProgramName;    // Offset 0
    PSPC_LINK pMoreInfo;        // Offset +PointerSize
    PSPC_LINK pPublisherInfo;   // Offset +(PointerSize*2)
} SPC_SP_OPUS_INFO;
```

**Field Extraction:**
- `description`: First pointer (pwszProgramName)
- `url`: Second pointer → SPC_LINK → nested pointer → wide string

**Example Usage:**
```javascript
var opus = require('win-authenticode-opus');

// Read signature from executable
var sigInfo = opus('C:\\Program Files\\MeshAgent\\MeshAgent.exe');

if (sigInfo) {
    console.log('Description:', sigInfo.description);
    // "Mesh Agent Background Service"

    console.log('URL:', sigInfo.url);
    // "https://meshcentral.example.com/agent.ashx?id=ABC123"
} else {
    console.log('No signature or no OPUS info');
}
```

---

### Secondary Export: locked(uri)

**Lines 100-116:** Parses URL from signature to extract server lock configuration.

**Parameters:**
- `uri` - URL string from Authenticode signature

**Returns:**
- Object with properties:
  - `dns` - Server hostname
  - `id` - Server ID
- `null` if:
  - URL doesn't contain `serverid` parameter
  - Hostname is empty
  - Server ID is empty

**Algorithm:**

**Step 1: Parse URI (Line 102):**
```javascript
var f = require('http').parseUri(uri);
```

**Extracts:** Protocol, host, path, query string

**Step 2: Parse Query Parameters (Lines 103-106):**
```javascript
var q = f.path.split('?').pop().split(',');
while (q.length > 0) {
    var tokens = q.pop().split('=');
    if (tokens[0].trim().toLowerCase() == 'serverid') {
        // Found serverid parameter
    }
}
```

**Query Format:**
- Expected: `?param1=value1,serverid=ABC123`
- Delimiter: Comma (not standard `&`)
- Case-insensitive parameter name matching

**Step 3: Validate and Return (Lines 109-112):**
```javascript
if (f.host != null && f.host != '' && tokens[1] != null && tokens[1] != '') {
    return ({ dns: f.host, id: tokens[1] });
}
```

**Example Usage:**
```javascript
var opus = require('win-authenticode-opus');

var uri = 'https://mesh.example.com/agent.ashx?id=agent1,serverid=ABC123DEF456';
var lock = opus.locked(uri);

console.log(lock.dns);  // "mesh.example.com"
console.log(lock.id);   // "ABC123DEF456"
```

**Use Case:**
- Validate agent is locked to specific MeshCentral server
- Prevent agent redirection attacks
- Ensure configuration integrity

---

### Secondary Export: checkMSH()

**Lines 117-153:** Validates current MeshAgent executable is locked to correct server configuration.

**Parameters:** None (reads from current process and configuration)

**Returns:** Nothing (throws exception on mismatch)

**Throws:**
- `'DNS MISMATCH in Configuration, LOCKED to: <dns>'` - Server hostname doesn't match signature
- `'ServerID MISMATCH in Configuration, LOCKED to: <id>'` - Server ID doesn't match signature

**Algorithm:**

**Step 1: Read Signature from Current Executable (Line 119):**
```javascript
var value = module.exports(process.execPath);
```

**`process.execPath`:** Path to MeshAgent.exe

**Step 2: Extract URL and Parse Lock Info (Lines 120-130):**
```javascript
if (value != null) {
    if (value.url != null) {
        value = module.exports.locked(value.url);
    } else {
        value = null;
    }
}
```

**`value` now contains:** `{ dns: '...', id: '...' }` or `null`

**Step 3: Read Current Configuration (Line 133):**
```javascript
var msh = _MSH();
```

**`_MSH()`:** Reads MeshAgent configuration (presumably from .msh file or registry)

**Step 4: Validate DNS Match (Lines 136-144):**
```javascript
var res1 = require('http').parseUri(msh.MeshServer);
if(res1!=null) {
    if(res1.host.toLowerCase() != value.dns.toLowerCase()) {
        throw ('DNS MISMATCH in Configuration, LOCKED to: ' + value.dns);
    }
}
```

**Comparison:** Case-insensitive hostname match

**Step 5: Validate Server ID Match (Lines 145-148):**
```javascript
if(msh.ServerID.toLowerCase() != value.id.toLowerCase()) {
    throw ('ServerID MISMATCH in Configuration, LOCKED to: ' + value.id);
}
```

**Comparison:** Case-insensitive server ID match

**Example Usage:**
```javascript
// Called during MeshAgent startup
try {
    require('win-authenticode-opus').checkMSH();
    console.log('Agent signature validation passed');
} catch(e) {
    console.error('SECURITY ERROR:', e);
    process.exit(1);  // Refuse to start with mismatched configuration
}
```

**Security Benefit:**
- Prevents compromised configuration files from redirecting agent
- Signature can't be modified without breaking signature
- Ensures agent only connects to intended MeshCentral server
- Mitigates man-in-the-middle configuration attacks

**Deployment Workflow:**
1. Sign MeshAgent.exe with Authenticode
2. Embed URL with serverid: `https://mesh.company.com/agent.ashx?id=COMPANY,serverid=ABC123`
3. Distribute signed executable
4. Agent validates signature matches .msh file on every startup
5. Prevents malicious .msh file substitution

---

### Module Exports

**Line 156-158:**
```javascript
module.exports = read;
module.exports.locked = locked;
module.exports.checkMSH = checkMSH;
```

**Export Structure:**
- Default export: `read()` function
- Named export: `locked()` function
- Named export: `checkMSH()` function

**Usage Patterns:**
```javascript
// Default export
var opus = require('win-authenticode-opus');
var sig = opus('path.exe');

// Named exports
var lock = opus.locked('https://...');
opus.checkMSH();
```

## Dependencies

### Native Module Dependencies

#### _GenericMarshal (Line 31)

```javascript
var GM = require('_GenericMarshal');
```

**Purpose:** FFI (Foreign Function Interface) library for calling Windows DLLs

**Capabilities:**
- JavaScript to native DLL function calls
- Memory marshaling and buffer management
- Pointer arithmetic and structure traversal
- Wide character string handling
- Type conversion between JavaScript and C types

**Source:** `/microscript/ILibDuktape_GenericMarshal.c`

---

### Windows System DLL Dependencies

#### Crypt32.dll (Lines 32-35)

```javascript
var crypt = GM.CreateNativeProxy('Crypt32.dll');
```

**Methods Used:**

- **CryptQueryObject()** - Line 33, 45
  - **Purpose:** Retrieves information about cryptographic object (certificate, signature, etc.)
  - **Parameters:** `CryptQueryObject(DWORD dwObjectType, const void *pvObject, DWORD dwExpectedContentTypeFlags, DWORD dwExpectedFormatTypeFlags, DWORD dwFlags, DWORD *pdwMsgAndCertEncodingType, DWORD *pdwContentType, DWORD *pdwFormatType, HCERTSTORE *phCertStore, HCRYPTMSG *phMsg, const void **ppvContext)`
  - **Used:** Query file for embedded Authenticode signature
  - **Returns:** Non-zero on success
  - **Documentation:** Not directly available (legacy CryptoAPI)

- **CryptMsgGetParam()** - Line 34, 55, 63
  - **Purpose:** Retrieves parameter from cryptographic message
  - **Parameters:** `CryptMsgGetParam(HCRYPTMSG hCryptMsg, DWORD dwParamType, DWORD dwIndex, void *pvData, DWORD *pcbData)`
  - **Used:** Get signer information from PKCS#7 message
  - **Called twice:** First to get size, second to retrieve data
  - **Documentation:** Not directly available (legacy CryptoAPI)

- **CryptDecodeObject()** - Line 35, 85, 88
  - **Purpose:** Decodes ASN.1 encoded structure
  - **Parameters:** `CryptDecodeObject(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE *pbEncoded, DWORD cbEncoded, DWORD dwFlags, void *pvStructInfo, DWORD *pcbStructInfo)`
  - **Used:** Decode SPC_SP_OPUS_INFO from ASN.1 DER encoding
  - **Called twice:** First to get size, second to decode
  - **Documentation:** Not directly available (legacy CryptoAPI)

**Crypt32.dll Overview:**
- Windows Cryptography API (CryptoAPI)
- Certificate store management
- Cryptographic message encoding/decoding
- Digital signature verification
- Part of Windows core system libraries

---

### Module Dependencies

#### http (Lines 102, 138)

```javascript
var f = require('http').parseUri(uri);
var res1 = require('http').parseUri(msh.MeshServer);
```

**Purpose:** URL parsing utility

**Method Used:**
- `parseUri(url)` - Parses URL into components

**Returns:**
- Object with properties:
  - `protocol` - 'http', 'https', etc.
  - `host` - Hostname with port
  - `hostname` - Hostname without port
  - `port` - Port number
  - `path` - Path and query string
  - Other standard URL components

**Usage:**
- Extract hostname from signature URL
- Parse MeshServer URL from configuration
- Compare hostnames for security validation

---

### Windows API Constants

**Lines 18-27:** Cryptography API constants

**Encoding Types (Lines 18-20):**
```javascript
const X509_ASN_ENCODING = 0x00000001;      // X.509 ASN.1 encoding
const PKCS_7_ASN_ENCODING = 0x00010000;    // PKCS#7 ASN.1 encoding
const ENCODING = (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);  // Both
```

**Combined:** `0x00010001` - Indicates X.509 certificates in PKCS#7 container

**Query Object Type (Line 21):**
```javascript
const CERT_QUERY_OBJECT_FILE = 0x00000001;
```
- Indicates query target is a file (not memory blob)

**Content Type (Lines 22-23):**
```javascript
const CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10;
const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = (1 << CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED);
```
- `CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10`
- Flag value: `1 << 10 = 0x00000400`
- Indicates embedded PKCS#7 signature (Authenticode)

**Format Type (Lines 24-25):**
```javascript
const CERT_QUERY_FORMAT_BINARY = 1;
const CERT_QUERY_FORMAT_FLAG_BINARY = (1 << CERT_QUERY_FORMAT_BINARY);
```
- Flag value: `1 << 1 = 0x00000002`
- Indicates binary format (PE file)

**Message Parameter Type (Line 26):**
```javascript
const CMSG_SIGNER_INFO_PARAM = 6;
```
- Parameter ID for retrieving signer information from cryptographic message

**OID (Object Identifier) - Line 27:**
```javascript
const SPC_SP_OPUS_INFO_OBJID = "1.3.6.1.4.1.311.2.1.12";
```
- **1.3.6.1.4.1** - ISO member-body, US, identified-organization
- **311** - Microsoft
- **2.1.12** - Software Publishing Credential, SP Opus Info
- Microsoft-specific authenticated attribute containing program description and URL

---

### Dependency Chain Summary

```
win-authenticode-opus.js
├─── _GenericMarshal (Line 31) - FFI library
│    └─── Native marshaling layer
├─── Crypt32.dll (Lines 32-35) - Cryptography API
│    ├─── CryptQueryObject() - Query file signature
│    ├─── CryptMsgGetParam() - Get signer info
│    └─── CryptDecodeObject() - Decode ASN.1 structures
├─── http (Lines 102, 138) - URL parsing
│    └─── parseUri() - Parse URLs
└─── Internal Dependencies (Line 133)
     └─── _MSH() - Read MeshAgent configuration
```

## Technical Implementation Details

### Authenticode Signature Structure

**PE File with Authenticode:**
```
PE File Header
├─── Code sections (.text, .data, etc.)
├─── Resource sections
└─── Certificate Table (IMAGE_DIRECTORY_ENTRY_SECURITY)
     └─── WIN_CERTIFICATE structure
          └─── PKCS#7 SignedData
               ├─── Certificates (chain)
               ├─── Signer Info
               │    ├─── Issuer
               │    ├─── Serial Number
               │    ├─── Authenticated Attributes ←─── SPC_SP_OPUS_INFO here
               │    └─── Signature
               └─── Content (PE file hash)
```

**CMSG_SIGNER_INFO Structure:**
```c
typedef struct _CMSG_SIGNER_INFO {
    DWORD dwVersion;
    CERT_NAME_BLOB Issuer;
    CERT_NAME_BLOB SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
    CRYPT_DATA_BLOB EncryptedHash;
    CRYPT_ATTRIBUTES AuthAttrs;
    CRYPT_ATTRIBUTES UnauthAttrs;  // ← SPC_SP_OPUS_INFO is here
} CMSG_SIGNER_INFO;
```

**Structure Offsets:**
- **32-bit:** UnauthAttrs at byte offset 52
- **64-bit:** UnauthAttrs at byte offset 104

**CRYPT_ATTRIBUTES Structure:**
```c
typedef struct _CRYPT_ATTRIBUTES {
    DWORD cAttr;           // Attribute count
    PCRYPT_ATTRIBUTE rgAttr;  // Pointer to array of attributes
} CRYPT_ATTRIBUTES;
```

**CRYPT_ATTRIBUTE Structure:**
```c
typedef struct _CRYPT_ATTRIBUTE {
    LPSTR pszObjId;        // OID string
    DWORD cValue;          // Value count
    PCRYPT_ATTR_BLOB rgValue;  // Pointer to array of values
} CRYPT_ATTRIBUTE;
```

**Size per architecture:**
- **32-bit:** 12 bytes (4 + 4 + 4)
- **64-bit:** 24 bytes (8 + 4 + 4 + 8 padding)

**SPC_SP_OPUS_INFO Structure (decoded):**
```c
typedef struct _SPC_SP_OPUS_INFO {
    LPCWSTR pwszProgramName;   // Program description
    PSPC_LINK pMoreInfo;       // URL link
    PSPC_LINK pPublisherInfo;  // Publisher link (rarely used)
} SPC_SP_OPUS_INFO;
```

**SPC_LINK Structure:**
```c
typedef struct _SPC_LINK {
    DWORD dwLinkChoice;
    union {
        LPWSTR pwszUrl;
        SPC_SERIALIZED_OBJECT Moniker;
        LPWSTR pwszFile;
    };
} SPC_LINK;
```

---

### Memory Management and Pointer Traversal

**Attribute Enumeration (Lines 70-76):**

**Step 1: Read UnauthAttrs (Line 70):**
```javascript
var attributes = pSignerInfo.Deref(
    GM.PointerSize == 8 ? 104 : 52,  // Offset to UnauthAttrs
    GM.PointerSize * 2               // Read 2 pointers worth (count + array ptr)
);
```

**Read:** `CRYPT_ATTRIBUTES` structure (count + pointer)

**Step 2: Get Attribute Count (Line 71):**
```javascript
var attrCount = attributes.toBuffer().readUInt32LE();
```

**Step 3: Get Attribute Array Pointer (Line 75):**
```javascript
attr = attributes.Deref(GM.PointerSize, GM.PointerSize).Deref();
```
- Skip pointer size (past count)
- Dereference pointer to array
- Get first CRYPT_ATTRIBUTE

**Step 4: Iterate Array (Line 76):**
```javascript
attr = attr.increment(n * (GM.PointerSize == 8 ? 24 : 12));
```
- 32-bit: 12 bytes per attribute
- 64-bit: 24 bytes per attribute

**Pointer Dereferences (Line 91):**

**Description:**
```javascript
opus.Deref().Val != 0 ? opus.Deref().Wide2UTF8 : null
```
- `opus` points to SPC_SP_OPUS_INFO
- `opus.Deref()` = pwszProgramName pointer
- `.Val != 0` checks if not NULL
- `.Wide2UTF8` converts UTF-16 to UTF-8

**URL:**
```javascript
opus.Deref(GM.PointerSize, GM.PointerSize).Deref().Val != 0 ?
    opus.Deref(GM.PointerSize, GM.PointerSize).Deref()
        .Deref(GM.PointerSize, GM.PointerSize).Deref().Wide2UTF8.trim()
    : null
```

**Traversal:**
1. `opus.Deref(GM.PointerSize, ...)` - Skip to pMoreInfo
2. `.Deref()` - Dereference to SPC_LINK structure
3. `.Deref(GM.PointerSize, ...)` - Skip to union (pwszUrl)
4. `.Deref()` - Dereference to actual wide string
5. `.Wide2UTF8.trim()` - Convert and trim whitespace

---

### ASN.1 Decoding

**Two-Phase Decoding Pattern:**

**Phase 1: Get Size (Line 85):**
```javascript
crypt.CryptDecodeObject(
    ENCODING,
    GM.CreateVariable(SPC_SP_OPUS_INFO_OBJID),
    pb,      // Encoded data pointer
    cb,      // Encoded data size
    0,       // Flags
    0,       // NULL buffer (query size)
    dwData   // Output: Required buffer size
)
```

**Phase 2: Decode (Line 88):**
```javascript
var opus = GM.CreateVariable(dwData.toBuffer().readUInt32LE());
crypt.CryptDecodeObject(
    ENCODING,
    GM.CreateVariable(SPC_SP_OPUS_INFO_OBJID),
    pb, cb, 0,
    opus,    // Buffer to receive decoded structure
    dwData   // Buffer size
)
```

**Why Two Calls:**
- First call determines required buffer size
- Allocate exact amount needed
- Second call performs actual decoding
- Standard Windows API pattern for variable-size outputs

---

### Error Handling

**No Explicit Error Handling:**
- Module relies on Windows API returning error codes
- If signature missing: `CryptQueryObject()` returns 0
- If attribute missing: Loop doesn't find matching OID
- If decoding fails: `CryptDecodeObject()` returns 0
- All failure paths return `null` (implicit)

**Exception Throwing:**
- Only `checkMSH()` throws exceptions (Lines 143, 147)
- Intentional: Security validation should fail loudly

**Best Practice:**
```javascript
try {
    var sig = opus('path.exe');
    if (sig) {
        console.log('Signature found:', sig.description);
    } else {
        console.log('No signature or no OPUS info');
    }
} catch(e) {
    console.error('Error reading signature:', e);
}
```

---

### Security Considerations

**Signature Validation:**
- Module **only reads metadata**, does **not verify signature validity**
- Does not check if signature is trusted
- Does not validate certificate chain
- Does not check for revocation

**Trust Assumptions:**
- Assumes Windows verified signature during execution
- Assumes file hasn't been modified since signing
- Assumes attacker can't replace executable

**Proper Security Flow:**
1. Windows verifies Authenticode signature on load
2. If verification fails, Windows blocks execution (SmartScreen)
3. If verification succeeds, this module reads metadata
4. `checkMSH()` validates configuration matches signature

**Attack Mitigations:**
- Configuration file modification → Detected by `checkMSH()`
- Executable replacement → Signature won't match certificate
- Man-in-the-middle → DNS/ServerID mismatch detected

**Limitations:**
- If attacker has code signing certificate, can create new signed binary
- Doesn't prevent valid but malicious signatures
- Relies on OS-level signature verification

## Known Usage Patterns

### MeshAgent Security Validation

**Typical Integration:**
```javascript
// Early in MeshAgent startup
if (process.platform == 'win32') {
    try {
        var opus = require('win-authenticode-opus');

        // Verify agent is locked to correct server
        opus.checkMSH();

        console.log('Agent signature validation: PASSED');
    } catch(e) {
        console.error('Agent signature validation: FAILED');
        console.error(e);

        // Log security event
        require('MeshAgent').SendCommand({
            action: 'msg',
            type: 'console',
            value: 'SECURITY ERROR: ' + e
        });

        // Refuse to start
        process.exit(1);
    }
}
```

### Signature Information Display

```javascript
var opus = require('win-authenticode-opus');

// Show signature info for executable
var sig = opus('C:\\Program Files\\MyApp\\MyApp.exe');

if (sig) {
    console.log('Signed Application');
    console.log('  Description:', sig.description || '(none)');
    console.log('  URL:', sig.url || '(none)');

    if (sig.url) {
        var lock = opus.locked(sig.url);
        if (lock) {
            console.log('  Server Lock:');
            console.log('    DNS:', lock.dns);
            console.log('    ID:', lock.id);
        }
    }
} else {
    console.log('No signature or no OPUS information');
}
```

### Build Process Integration

```powershell
# Sign MeshAgent.exe with server lock
$description = "Mesh Agent Background Service"
$url = "https://mesh.company.com/agent.ashx?id=COMPANY,serverid=$ServerID"

signtool sign `
    /f codesigning.pfx `
    /p $password `
    /d $description `
    /du $url `
    /tr http://timestamp.digicert.com `
    /td SHA256 `
    MeshAgent.exe
```

**Parameters:**
- `/d` - Sets `SPC_SP_OPUS_INFO.pwszProgramName`
- `/du` - Sets `SPC_SP_OPUS_INFO.pMoreInfo.pwszUrl`
- `/tr` - Timestamp server (for signature expiration)
- `/td` - Timestamp digest algorithm

**Verification:**
```javascript
// In JavaScript
var sig = opus('MeshAgent.exe');
console.log(sig.description);  // "Mesh Agent Background Service"
console.log(sig.url);           // "https://mesh.company.com/agent.ashx?..."
```

## Limitations

### API Limitations

1. **Read-Only:** Cannot create or modify signatures
2. **No Validation:** Doesn't verify signature cryptographically
3. **OPUS Only:** Only reads SPC_SP_OPUS_INFO, not other attributes
4. **Single Signer:** Only processes first signer (index 0)
5. **Windows Only:** Authenticode is Windows-specific

### Data Limitations

1. **Optional Fields:** Description and URL are optional in signatures
2. **String Encoding:** Only handles wide character (UTF-16) strings
3. **URL Format:** Assumes specific query parameter format (`serverid=`)
4. **No Timestamp:** Doesn't read or validate timestamp information

### Security Limitations

1. **No Certificate Chain Validation**
2. **No Revocation Checking**
3. **No Trust Store Verification**
4. **Assumes OS Validated Signature**

### Platform Limitations

1. **Windows Only:** Will fail on non-Windows
2. **PE Files Only:** Only works with .exe, .dll, .sys, etc.
3. **Crypt32.dll Required:** Older/minimal Windows may not have full CryptoAPI

## Best Practices

### 1. Always Check for Null Return

```javascript
var sig = opus('path.exe');
if (sig) {
    // Process signature
} else {
    // Handle unsigned or no OPUS info
}
```

### 2. Use Try-Catch for Security Checks

```javascript
try {
    opus.checkMSH();
} catch(e) {
    console.error('Security validation failed:', e);
    // Take appropriate action (exit, alert, etc.)
}
```

### 3. Validate URL Format

```javascript
if (sig && sig.url) {
    var lock = opus.locked(sig.url);
    if (lock && lock.dns && lock.id) {
        // Valid lock configuration
    } else {
        console.warn('URL does not contain server lock info');
    }
}
```

### 4. Combine with OS-Level Validation

```javascript
// Let Windows validate signature first
if (process.platform == 'win32') {
    // Windows already validated signature for this executable
    // Now check configuration matches
    opus.checkMSH();
}
```

### 5. Log Security Events

```javascript
try {
    opus.checkMSH();
} catch(e) {
    // Log to security event log
    require('windows-eventlog').log('Security', {
        type: 'Error',
        eventID: 1000,
        message: 'MeshAgent signature validation failed: ' + e
    });

    process.exit(1);
}
```

## License

**Apache License 2.0**
Copyright 2022 Intel Corporation
Author: Bryan Roe

## Summary

win-authenticode-opus.js is a Windows-specific module that reads digital signature metadata from Authenticode-signed executables. It extracts program description and URL information from the SPC_SP_OPUS_INFO authenticated attribute and provides security validation to ensure MeshAgent binaries are locked to specific server configurations.

**Implicitly excludes all non-Windows platforms** because:
- Relies entirely on Windows-specific Crypt32.dll (Windows Cryptography API)
- Authenticode is a Windows-exclusive code signing technology for PE (Portable Executable) files
- macOS uses different code signing (codesign utility, Mach-O format)
- Linux has no standardized equivalent (GPG signatures, distro-specific approaches)
- SPC_SP_OPUS_INFO is a Microsoft-specific extension to PKCS#7 (OID 1.3.6.1.4.1.311.2.1.12)
- No platform check - will fail immediately when trying to load Crypt32.dll on macOS/Linux
- Intentionally designed for Windows MeshAgent security validation

The module provides critical security functionality for Windows MeshAgent deployments by ensuring the agent executable's embedded signature matches the runtime configuration, preventing redirection attacks and configuration tampering. Alternative approaches using platform-specific code signing verification would be required for macOS (Security framework) or Linux (GPG verification).
