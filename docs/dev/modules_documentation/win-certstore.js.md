# win-certstore.js

Provides access to Windows certificate store for certificate management and retrieval. Implements X.509 certificate operations using Windows Cryptography API through Crypt32.dll and NCrypt.dll for low-level certificate store access and searching.

## Platform

**Supported Platforms:**
- Windows (all versions) - Full support

**Excluded Platforms:**
- **macOS** - Not supported (Windows-only)
- **Linux** - Not supported (Windows-only)
- **FreeBSD** - Not supported (Windows-only)

**Exclusion Reasoning:**

Windows-specific module requiring Windows APIs/DLLs unavailable on other platforms.

**Platform Notes:**

**win-certstore.js is Windows-only** because:

1. **Windows Certificate Store** - Uses Windows-specific certificate storage system (MY store)
2. **Crypt32.dll Dependency** - Microsoft cryptography library available only on Windows
3. **NCrypt.dll Dependency** - Windows cryptographic provider interface not available on other platforms
4. **Direct DLL Access** - Requires _GenericMarshal to load native Windows DLLs

---

## Functionality

### Core Purpose

win-certstore.js manages Windows certificate store operations:

1. **Certificate Storage Access** - Open and manage Windows certificate stores
2. **Cryptographic Provider Initialization** - Initialize hardware/software key providers
3. **Certificate Search** - Find certificates by Common Name (CN)
4. **Certificate Retrieval** - Extract certificate data from store in TLS-compatible format

### Main Operations

1. **Crypto Provider Management** - OpenCryptoProvider(), initialize platform and software key storage
2. **Certificate Store Access** - OpenStore(), access LOCAL_MACHINE or CURRENT_USER stores
3. **Certificate Search** - GetCertificate(CN, location), find certificate by subject name
4. **Certificate Loading** - Load certificate context into JavaScript-compatible format

---

## Constructor

### certstore() - Lines 25-114

**Purpose:** Initialize certificate store manager with DLL interfaces

**Initialization:**
1. Creates instance ID 'win-certstore'
2. Loads Crypt32.dll native proxy (line 29)
3. Loads NCrypt.dll native proxy (line 36)
4. Creates method references for certificate operations
5. Initializes provider constants and store locations

**Stored Properties:**
- `_marshal` - Generic marshal interface for native calls
- `_Crypt32` - Windows cryptography DLL proxy
- `_Ncrpyt` - Windows NCrypt DLL proxy
- `STORE_LOCATION` - Constants: LOCAL_MACHINE (2 << 16), CURRENT_USER (1 << 16)
- `PROVIDERS` - Array of provider strings: Platform Crypto Provider, Software Key Storage Provider

---

## Core Methods

### OpenCryptoProvider() - Lines 42-67

**Purpose:** Initialize cryptographic provider for certificate operations

**Returns:** Pointer to initialized crypto provider

**Process:**
1. Creates pointer for provider handle (line 45)
2. Iterates through PROVIDERS array (Platform, then Software) (line 46)
3. Calls NCryptOpenStorageProvider() for each provider (line 48)
4. Returns first successful provider handle (line 49)
5. Throws error if no providers available (line 51)

**Returned Provider Properties:**
- `_b` - Original pointer buffer reference
- `_crypt` - Back-reference to certstore instance
- `_finalized` - Flag tracking cleanup status
- `close()` - Manual cleanup method calling NCryptFreeObject()
- Finalizer listener on '~' event for automatic cleanup

**Error Handling:**
- Throws: 'Unable to open CryptoProvider' if all providers fail

---

### OpenStore(provider, location) - Lines 68-77

**Purpose:** Open Windows certificate store at specified location

**Parameters:**
- `provider` - Crypto provider handle from OpenCryptoProvider()
- `location` - STORE_LOCATION (LOCAL_MACHINE or CURRENT_USER)

**Returns:** Certificate store handle

**Process:**
1. Calls CertOpenStore() with:
   - CERT_STORE_PROV_SYSTEM (system provider type)
   - X509_ASN_ENCODING | PKCS_7_ASN_ENCODING (encoding types)
   - provider handle
   - location | CERT_STORE_OPEN_EXISTING_FLAG (flags)
   - 'MY' store name (line 70)
2. Attaches cleanup methods to handle
3. Registers finalizer listener

**Returned Store Properties:**
- `_crypt` - Back-reference to certstore instance
- `_finalized` - Cleanup flag
- `close()` - Explicit cleanup calling CertCloseStore()
- Finalizer listener for automatic cleanup

**Error Handling:**
- Throws: 'Error opening CertStore' if store handle is null

---

### GetCertificate(CN, location) - Lines 78-111

**Purpose:** Search for and retrieve certificate by Common Name (CN)

**Parameters:**
- `CN` - Certificate Common Name to search for (e.g., "*.example.com")
- `location` - STORE_LOCATION (LOCAL_MACHINE or CURRENT_USER)

**Returns:** Certificate object loaded via tls.loadCertificate()

**Process:**
1. Creates variable for CN string (line 80)
2. Encodes subject name to X.500 format:
   - First call to CertStrToNameA to get required size (lines 82-85)
   - Second call to actually encode the name (lines 87-90)
3. Opens crypto provider (line 91)
4. Opens certificate store (line 92)
5. Creates search structure with encoded subject name (lines 93-95)
6. Calls CertFindCertificateInStore() to locate cert (line 98)
7. If found, extracts certificate blob:
   - Dereferences pointer to certificate data (line 102)
   - Extracts ASN.1 encoded certificate binary
   - Loads via tls.loadCertificate() (line 103)
8. Returns loaded certificate object (line 104)

**Search Flags:**
- CERT_FIND_SUBJECT_NAME (2 << 16 | 7) - Search by subject name
- X509_ASN_ENCODING | PKCS_7_ASN_ENCODING - Encoding types

**Error Handling:**
- Throws: 'Error calculating CERT_X500_NAME_STR for (CN)' - Subject name encoding failed
- Throws: 'Error encoding CERT_X500_NAME_STR for (CN)' - Subject name encoding failed
- Throws: 'Not Found' - Certificate not found in store

**Example:**
```javascript
var certstore = require('win-certstore');
var cert = certstore.GetCertificate('*.example.com', certstore.STORE_LOCATION.LOCAL_MACHINE);
```

---

## Constants and Encoding Flags - Lines 16-23

```javascript
const CERT_FIND_SUBJECT_NAME = (2 << 16 | 7);              // Search criteria
const CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;          // Open existing store
const CERT_STORE_PROV_SYSTEM = 10;                         // System provider
const CERT_X500_NAME_STR = 3;                              // X.500 name string format
const PKCS_7_ASN_ENCODING = 0x00010000;                    // PKCS#7 ASN.1 encoding
const X509_ASN_ENCODING = 0x00000001;                      // X.509 ASN.1 encoding
const CERT_CLOSE_STORE_FORCE_FLAG = 0x00000001;           // Force close flag
const CERT_CLOSE_STORE_CHECK_FLAG = 0x00000002;           // Check close flag
```

---

## Dependencies

### Native DLL Interfaces - Lines 28-34

**Crypt32.dll** - Windows Cryptography API (Lines 29-34)
- CertCloseStore() - Close certificate store handle
- CertDeleteCertificateFromStore() - Delete certificate from store
- CertFindCertificateInStore() - Search certificate store
- CertOpenStore() - Open certificate store
- CertStrToNameA() - Encode subject name to X.500 format

**NCrypt.dll** - Windows Cryptographic Provider API (Lines 36-38)
- NCryptFreeObject() - Release cryptographic object handle
- NCryptOpenStorageProvider() - Open crypto provider

### Module Dependencies - Lines 28, 36, 103

**require('_GenericMarshal')** - Line 28, 36
- CreateNativeProxy() to load DLL interfaces
- CreateMethod() to define DLL functions
- CreateVariable() for memory buffers
- Pointer management for C structures

**require('tls')** - Line 103
- loadCertificate() to load X.509 certificate from binary
- Converts DER-encoded certificate to JavaScript certificate object

---

## Technical Details

### Certificate Store Locations

1. **LOCAL_MACHINE (2 << 16)**
   - System-wide certificates
   - Requires administrator access
   - Shared across all user accounts

2. **CURRENT_USER (1 << 16)**
   - User-specific certificates
   - Accessible by current user
   - Private to logged-in user

### Cryptographic Providers

The module supports two provider types (lines 40):

1. **Microsoft Platform Crypto Provider**
   - Hardware TPM support if available
   - Provides stronger security via hardware
   - Falls back to software if unavailable

2. **Microsoft Software Key Storage Provider**
   - Pure software implementation
   - Always available
   - Used as fallback if hardware unavailable

### Subject Name Encoding

X.500 format example: "CN=example.com, O=Company, C=US"
- First CertStrToNameA call determines encoding size
- Second call performs actual encoding
- Buffer passed to CertFindCertificateInStore()

---

## Error Conditions

1. **Provider Initialization Failure**
   - Both crypto providers unavailable
   - Throws: 'Unable to open CryptoProvider'

2. **Store Access Failure**
   - Cannot open MY certificate store
   - Throws: 'Error opening CertStore'

3. **Subject Name Encoding**
   - Invalid CN format or encoding error
   - Throws: 'Error calculating/encoding CERT_X500_NAME_STR'

4. **Certificate Not Found**
   - No certificate matches CN in store at location
   - Throws: 'Not Found'

---

## Security Considerations

1. **Access Control** - Certificate store access controlled by Windows permissions
2. **Private Key Protection** - Private keys secured by Windows DPAPI (Data Protection API)
3. **Hardware Security Module** - TPM/HSM support when Platform Crypto Provider available
4. **Cleanup** - Automatic cleanup of handles via finalizers prevents resource leaks

---

## Summary

win-certstore.js provides Windows certificate store management through direct DLL interfaces. The module initializes cryptographic providers, opens certificate stores at system or user scope, and retrieves certificates by Common Name. Comprehensive error handling and automatic resource cleanup ensure robust certificate operations on Windows systems.
