# win-crypto.js

Provides comprehensive Windows cryptography operations including certificate creation, signing, and verification. Implements X.509 certificate generation, message signing/verification, and cryptographic key management through Windows CNG (Cryptography Next Generation) and Crypt32 APIs.

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

**win-crypto.js is Windows-only** because:

1. **Windows CNG/Crypt32 APIs** - Direct dependencies on Windows cryptographic libraries
2. **RSA Key Generation** - Uses Windows cryptographic providers
3. **X.509 Certificate Generation** - Windows CERT_CONTEXT and ASN.1 encoding
4. **PKCS#7 Signing** - Windows implementation of cryptographic message signing
5. **Direct DLL Access** - Requires _GenericMarshal for Kernel32.dll, Bcrypt.dll, Crypt32.dll

---

## Functionality

### Core Purpose

win-crypto.js provides Windows-native cryptographic operations:

1. **Certificate Generation** - Create self-signed X.509 certificates
2. **Message Signing** - Sign data with private keys (PKCS#7 format)
3. **Message Verification** - Verify PKCS#7 signed messages
4. **Certificate Manipulation** - Load, manipulate, and export certificates
5. **Key Management** - Access private/public keys, key algorithms

### Main Operations

1. **Certificate Creation** - makeCert(options), MakeCertFromPublicKey(options)
2. **Message Operations** - signMessage(), verifyMessage()
3. **Encoding** - CryptEncodeObject(), EncodeString()
4. **Certificate Loading** - loadCert(encodedCert, options)

---

## Constructor - Lines 113-155

**Purpose:** Initialize cryptographic engine with DLL interfaces

**Initialization:**
1. Creates instance ID 'win-crypto'
2. Loads Kernel32.dll (line 117)
3. Loads Bcrypt.dll for random number generation (line 123)
4. Loads Crypt32.dll for cryptographic operations (line 128)
5. Creates method references for all cryptographic functions

**Kernel32 Methods:**
- FileTimeToSystemTime(), SystemTimeToFileTime() - Time conversions
- GetLastError() - Get Windows error codes
- GetSystemTime() - Get current system time

**Bcrypt Methods:**
- BCryptGenRandom() - Generate random numbers
- BCryptCloseAlgorithmProvider() - Release algorithm provider
- BCryptOpenAlgorithmProvider() - Open RNG algorithm

**Crypt32 Methods:**
- CertStrToNameA() - Encode subject name
- CertCreateCertificateContext() - Create certificate context
- CertCreateSelfSignCertificate() - Create self-signed cert
- CryptAcquireCertificatePrivateKey() - Get private key from cert
- CryptDecodeObject()/CryptEncodeObject() - Encode/decode ASN.1 objects
- CryptHashCertificate() - Hash certificate data
- CryptSignMessage() - Sign message with certificate
- CryptVerifyMessageSignature() - Verify signed message

---

## Core Methods

### makeCert(options) - Lines 171-374

**Purpose:** Generate self-signed X.509 certificate

**Parameters - options object:**
- `CN` - Common Name (required)
- `T` - Title (optional)
- `L` - Locality Name (optional)
- `O` - Organization Name (optional)
- `C` - Country (optional)
- `S` - State or Province (optional)
- `STREET` - Street Address (optional)
- `_algorithm` - Hash algorithm: 'SHA1', 'SHA256', 'SHA384', 'SHA512' (required)
- `_years` - Certificate validity in years (required)
- `_keyRestrictions` - Key usage restrictions object (optional)

**Returns:** Certificate context with methods and properties

**Certificate Object Properties:**
- `privateKey` - Private key object
  - `keySpec` - Key specification
  - `needFree` - Cleanup flag
- `publicKey` - Buffer containing public key
- `publicKey.oid` - Algorithm OID
- `SubjectPublicKeyInfo` - Public key info structure
- `Subject` - Subject name structure
- `signMessage()` - Method to sign data

**Key Usage Restrictions (lines 156-169):**
- CERT_DIGITAL_SIGNATURE_KEY_USAGE
- CERT_NON_REPUDIATION_KEY_USAGE
- CERT_KEY_ENCIPHERMENT_KEY_USAGE
- CERT_DATA_ENCIPHERMENT_KEY_USAGE
- CERT_KEY_AGREEMENT_KEY_USAGE
- CERT_KEY_CERT_SIGN_KEY_USAGE
- CERT_OFFLINE_CRL_SIGN_KEY_USAGE

**Process:**
1. Validates algorithm (line 173)
2. Builds X.500 subject string from options (lines 185-195)
3. Encodes subject name in ASN.1 format (lines 252-261)
4. Processes key restrictions if specified (lines 199-244)
5. Calls CertCreateSelfSignCertificate() (line 287)
6. Extracts private key using CryptAcquireCertificatePrivateKey() (lines 299-305)
7. Extracts public key info (lines 308-320)

**Certificate Validity (lines 278-285):**
- Current time minus 1 hour (not before)
- Current time plus specified years (not after)
- Leap-year exception for Feb 29 (line 282)

---

### signMessage(message, options) - Lines 323-372

**Purpose:** Sign message with certificate's private key

**Parameters:**
- `message` - Buffer to sign
- `options` - Object with:
  - `hashAlgorithm` - 'SHA1', 'SHA256', 'SHA384', 'SHA512'
  - `encodingType` - PKCS_7_ASN_ENCODING (0x00010000)

**Returns:** Signed message buffer in PKCS#7 format

**Process:**
1. Creates CRYPT_SIGN_MESSAGE_PARA structure
2. Sets message encoding type and hash algorithm
3. Calls CryptSignMessage() twice:
   - First to get size (line 353)
   - Second to perform signing (line 357)
4. Returns signed message buffer

---

### verifyMessage(message, options) - Lines 375-410

**Purpose:** Verify PKCS#7 signed message

**Parameters:**
- `message` - Signed message buffer
- `options` - Object with:
  - `encodingType` - PKCS_7_ASN_ENCODING

**Returns:** Original unsigned message buffer

**Process:**
1. Creates CRYPT_VERIFY_MESSAGE_PARA structure
2. Calls CryptVerifyMessageSignature() twice:
   - First to get decoded size (line 388)
   - Second to decode and verify (line 395)
3. Returns decoded message buffer

---

### loadCert(encodedCert, options) - Lines 411-431

**Purpose:** Load X.509 certificate from encoded bytes

**Parameters:**
- `encodedCert` - DER-encoded certificate bytes
- `options` - Object with:
  - `encodingType` - X509_ASN_ENCODING | PKCS_7_ASN_ENCODING

**Returns:** Certificate context with getInfo() method

**Process:**
1. Creates variable from encoded cert bytes
2. Calls CertCreateCertificateContext()
3. Attaches _marshal, _Crypt32, _Kernel32 references
4. Attaches getInfo() method for introspection

---

### EncodeString(inStr) - Lines 432-449

**Purpose:** Encode X.500 name string to ASN.1

**Parameters:**
- `inStr` - X.500 name string (e.g., "CN=example, O=Company")

**Returns:** Encoded binary structure

---

### CryptEncodeObject(encodingType, structType, data) - Lines 450-467

**Purpose:** Encode ASN.1 structure

**Parameters:**
- `encodingType` - Encoding type (X509_ASN_ENCODING)
- `structType` - Structure type or OID string
- `data` - Structure to encode

**Returns:** Encoded buffer with _size property

---

### MakeCertFromPublicKey(options) - Lines 468-625

**Purpose:** Create certificate from existing public key (for CA operations)

**Parameters:**
- `Issuer` - X.500 issuer string
- `Subject` - Object with subject name properties
- `PublicKey` - Binary public key buffer
- `SigningCert` - CA certificate for signing
- `SignatureAlgorithm` - Algorithm OID

**Optional:**
- `KeyUsage` - Array of key usage names
- `EnhancedKeyUsages` - Array of EKU OIDs

**Returns:** Certificate info structure (not yet signed)

---

### SignCertificate(signingCert, certinfo) - Lines 627-647

**Purpose:** Sign certificate using CA certificate

**Parameters:**
- `signingCert` - CA certificate with private key
- `certinfo` - Certificate info to sign

**Returns:** Signed certificate buffer

---

### dateToFileTime(dt) - Lines 678-696

**Purpose:** Convert JavaScript Date to Windows FILETIME

**Parameters:**
- `dt` - JavaScript Date object

**Returns:** 8-byte FILETIME structure

---

### fileTimeToDate(ft) - Lines 697-717

**Purpose:** Convert Windows FILETIME to JavaScript Date

**Parameters:**
- `ft` - FILETIME structure

**Returns:** JavaScript Date object

---

## Constants and Algorithm Support - Lines 17-111

### Hashing Algorithms:
- SHA1: 1.2.840.113549.1.1.5
- SHA256: 1.2.840.113549.1.1.11
- SHA384: 1.2.840.113549.1.1.12
- SHA512: 1.2.840.113549.1.1.13

### Key Algorithms (full OID mappings):
- RSA: 1.2.840.113549
- PKCS variants: 1.2.840.113549.1.x
- RSA-specific: RSA_RSA, RSA_SHA1RSA, RSA_SHA256RSA, etc.

### Extension OIDs:
- Key Usage: 2.5.29.15
- Subject Alt Name: 2.5.29.7
- Basic Constraints: 2.5.29.19
- Extended Key Usage: 2.5.29.37

---

## Dependencies

### Native DLLs - Lines 117, 123, 128

**Kernel32.dll** (Line 117)
- FileTimeToSystemTime() - Convert FILETIME to SYSTEMTIME
- SystemTimeToFileTime() - Convert SYSTEMTIME to FILETIME
- GetLastError() - Get Windows error code
- GetSystemTime() - Get current time

**Bcrypt.dll** (Line 123)
- BCryptGenRandom() - Generate cryptographic random
- BCryptCloseAlgorithmProvider() - Release provider
- BCryptOpenAlgorithmProvider() - Open RNG provider

**Crypt32.dll** (Line 128)
- CertStrToNameA() - Encode X.500 name
- CertCreateCertificateContext() - Create cert context
- CertCreateSelfSignCertificate() - Create self-signed cert
- CryptAcquireCertificatePrivateKey() - Get private key
- CryptDecodeObject()/CryptEncodeObject() - Encode/decode ASN.1
- CryptHashCertificate() - Hash certificate
- CryptSignMessage() - Sign PKCS#7 message
- CryptVerifyMessageSignature() - Verify PKCS#7

### Module Dependencies - Line 116

**require('_GenericMarshal')**
- CreateNativeProxy() - Load DLL
- CreateMethod() - Define function
- CreateVariable() - Memory buffers
- PointerSize - Architecture detection

---

## Technical Notes

### Certificate Structure

Certificates contain multiple nested structures:
- CERT_CONTEXT - Top-level certificate container
- CERT_INFO - Certificate data (version, serial, validity, etc.)
- SubjectPublicKeyInfo - Public key encoding
- X.500 Name - Subject/Issuer distinguished names

### Key Acquisition

Private keys acquired via CryptAcquireCertificatePrivateKey() with:
- keySpec - Key specification (AT_SIGNATURE, AT_KEYEXCHANGE)
- needFree - Flag indicating if key provider should be released

### Encoding Formats

- X509_ASN_ENCODING (0x00000001) - Pure X.509
- PKCS_7_ASN_ENCODING (0x00010000) - PKCS#7 container
- Usually both combined: 0x00010001

---

## Security Considerations

1. **Private Key Protection** - Private keys stored securely by Windows CryptoAPI
2. **Algorithm Selection** - Use SHA256 or higher (SHA1 deprecated)
3. **Key Length** - RSA keys typically 2048-bit minimum
4. **Certificate Validity** - Set appropriate expiration dates
5. **Key Usage Constraints** - Restrict certificate usage via constraints

---

## Error Handling

1. **Algorithm Error** - Invalid algorithm throws error (line 173)
2. **Certificate Creation** - Check pCert.Val == 0 for failure
3. **Key Acquisition** - Verify needFree flag for cleanup
4. **Encoding Errors** - GetLastError() returns Windows error code

---

## Summary

win-crypto.js provides complete Windows cryptographic capabilities including X.509 certificate generation, PKCS#7 signing/verification, key management, and ASN.1 encoding. The module leverages Windows CNG and Crypt32 APIs to deliver enterprise-grade cryptographic operations with proper error handling and resource management.
