# http-digest.js

HTTP Digest Authentication client implementation conforming to RFC 2617. Handles authentication challenges from HTTP servers and automatically retries requests with proper digest credentials, supporting both 'auth' and 'auth-int' quality of protection modes.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support
- macOS (darwin) - Full support
- FreeBSD - Full support

**Excluded Platforms:**
- None - This module is cross-platform

**Exclusion Reasoning:**

This module has no platform exclusions. It implements the HTTP Digest Authentication protocol (RFC 2617), which is a standard HTTP protocol independent of the underlying operating system. The module operates entirely at the HTTP protocol level using Node.js's standard `http` module and cryptographic functions (`MD5Stream`), making it universally compatible across all platforms where Node.js runs.

## Functionality

### Purpose

The http-digest module provides HTTP Digest Authentication capabilities for secure communication with web servers that require digest-based credentials. It serves as a drop-in replacement for standard HTTP client requests, transparently handling authentication challenges:

- **Automatic Authentication:** Detects 401 challenges and retries with digest credentials
- **Quality of Protection (QoP) Support:** Handles 'auth' and 'auth-int' modes
- **Nonce Management:** Tracks nonce counter (NC) for replay attack prevention
- **Opaque Value Handling:** Preserves server-provided opaque values
- **Request Buffering:** Buffers request body for authentication retries
- **Event Forwarding:** Forwards HTTP events (upgrade, error, continue, timeout, drain) to caller

This module is typically used:
- To communicate with Intel AMT (Active Management Technology) interfaces
- For secure API access requiring digest authentication
- When interacting with legacy systems that use digest instead of modern auth
- In environments where TLS client certificates are unavailable

### HTTP Digest Authentication Protocol

HTTP Digest Authentication (RFC 2617) provides password-based authentication without transmitting passwords in plaintext. It uses challenge-response mechanism with MD5 hashing:

**Authentication Flow:**
```
1. Client sends request without credentials
2. Server responds with 401 + WWW-Authenticate header containing:
   - realm: Protection space identifier
   - nonce: Server-generated random value
   - qop: Quality of protection options
   - opaque: Optional server-specific value
3. Client calculates digest response:
   - hash1 = MD5(username:realm:password)
   - hash2 = MD5(method:uri[:entity-body-hash])
   - response = MD5(hash1:nonce[:nc:cnonce:qop]:hash2)
4. Client retries request with Authorization header
5. Server validates digest and grants access (200 OK) or denies (401)
```

**Quality of Protection (QoP) Modes:**

| Mode | Description | Hash Input |
|------|-------------|------------|
| `auth` | Authentication only | Method + URI |
| `auth-int` | Authentication with integrity protection | Method + URI + MD5(entity-body) |
| (none) | Legacy mode without qop | Simplified hash calculation |

### Key Classes and Functions

#### http_digest() - Line 120

**Purpose:** Factory object providing the module's public API.

**Methods:**
- `create(options)` - Creates digest authentication instance
- `create(username, password)` - Convenience overload for basic credentials

**Export:**
```javascript
module.exports = new http_digest();
```

---

#### http_digest.create(options) - Lines 123-134

**Purpose:** Creates a new digest authentication instance with specified credentials.

**Parameters:**

**Variant 1 - Object parameter:**
```javascript
{
    username: '<username>',
    password: '<password>',
    qop: 'auth' | 'auth-int'  // Optional: preferred QoP mode
}
```

**Variant 2 - Two string parameters:**
```javascript
create(username, password)
```

**Return Value:**
Instance of `http_digest_instance` with configured credentials.

**Usage:**
```javascript
var httpDigest = require('http-digest');

// Option 1: Object parameter
var digest = httpDigest.create({
    username: 'admin',
    password: 'password123',
    qop: 'auth'
});

// Option 2: String parameters
var digest = httpDigest.create('admin', 'password123');
```

---

#### http_digest_instance(options) - Line 137

**Purpose:** Digest authentication instance that manages authentication state and performs requests.

**Constructor Initialization:**
- Stores credentials (username, password)
- Initializes nonce counter (NC) to 0
- Generates client nonce (CNONCE) - 16-byte random hex string
- Prepares for stateful authentication across multiple requests

**Properties:**
```javascript
{
    _ObjectID: 'http-digest.instance',
    _options: { username, password, qop },  // User credentials
    http: null,                              // HTTP client reference
    _NC: 0,                                  // Nonce counter for replay prevention
    _CNONCE: '<random_hex>',                 // Client nonce (16 bytes)
    _auth: {                                 // Authentication state
        realm: '<realm>',
        nonce: '<server_nonce>',
        opaque: '<opaque_value>',
        qop: 'auth' | 'auth-int',
        step1: '<hash1>',
        step2: '<hash2>',
        step3: '<response>'
    }
}
```

**Methods:**
- `request(uri | options [, callback])` - Makes HTTP request with digest auth
- `get(uri)` - Convenience method for GET requests

---

#### http_digest_instance.request(uri | options [, callback]) - Lines 149-313

**Purpose:** Makes HTTP request with automatic digest authentication handling.

**Parameters:**
- `uri` - String: Full URI (e.g., "http://server:16992/api")
- `options` - Object: HTTP request options (see http.request)
- `callback` - Function: Optional response callback

**Return Value:**
Writable stream that extends Node.js WritableStream with events:
```javascript
{
    // WritableStream methods
    write(chunk),
    end([chunk]),

    // Events
    on('response', callback),  // HTTP response received
    on('error', callback),     // Request error occurred
    on('upgrade', callback),   // HTTP upgrade (WebSocket)
    on('continue', callback),  // 100-Continue response
    on('timeout', callback),   // Request timeout
    on('drain', callback),     // Write buffer drained

    // Properties
    _request,                  // Underlying http.ClientRequest
    _buffered,                 // Buffered request body
    _ended,                    // Stream ended flag
    options                    // Request options
}
```

**Process Flow:**

1. **Initial Request:**
   - Parses URI or accepts options object
   - Checks if existing authentication headers can be added (from previous challenge)
   - Creates underlying http.request()
   - Sends request to server

2. **Challenge Handling (401 response):**
   - Parses `WWW-Authenticate` header
   - Extracts realm, nonce, opaque, qop
   - Selects appropriate QoP mode (prefers auth-int, falls back to auth)

3. **Digest Calculation:**
   - Computes hash1 = MD5(username:realm:password)
   - Computes hash2 = MD5(method:uri[:entity-body-hash])
   - Computes response = MD5(hash1:nonce:nc:cnonce:qop:hash2)
   - Increments nonce counter (NC)

4. **Retry Request:**
   - Adds `Authorization` header with digest response
   - Replays buffered request body
   - Forwards all events to caller

5. **Success or Failure:**
   - 200-299: Emits 'response' event with successful response
   - 401 (second time): Emits 'error' - authentication failed
   - Other codes: Emits 'response' as normal

**Platform Behavior:**
- All platforms supported
- Standard HTTP protocol

---

#### http_digest_instance.get(uri) - Lines 145-148

**Purpose:** Convenience method for making GET requests with digest authentication.

**Parameters:**
- `uri` - String: Full URI to fetch

**Return Value:**
Same as `request()` - Writable stream with events

**Usage:**
```javascript
digest.get('http://server/api/data')
    .on('response', function(response) {
        console.log('Status:', response.statusCode);
    });
```

---

#### generateAuthHeaders(imsg, options, digest) - Lines 37-118

**Purpose:** Generates HTTP Digest Authentication header value.

**Parameters:**
- `imsg` - HTTP response message with WWW-Authenticate header (null for cached auth)
- `options` - Request options containing method, path, headers
- `digest` - Digest instance with credentials and state

**Process:**

1. **Parse Challenge (if imsg provided):**
   - Extract realm, nonce, opaque from WWW-Authenticate header
   - Parse QoP options and select mode (auth-int preferred)
   - Store in `digest._auth` for reuse

2. **Calculate Hashes:**
   ```javascript
   hash1 = MD5(username:realm:password)
   hash2 = MD5(method:path[:MD5(entity-body)])
   ```

3. **Calculate Response:**
   - **Without QoP (legacy):**
     ```javascript
     response = MD5(hash1:nonce:hash2)
     ```
   - **With QoP (modern):**
     ```javascript
     response = MD5(hash1:nonce:nc:cnonce:qop:hash2)
     ```

4. **Format Authorization Header:**
   ```
   Digest username="...",realm="...",nonce="...",uri="...",
          response="...",qop="...",nc=...,cnonce="..."[,opaque="..."]
   ```

**Return Value:**
Authorization header string, also sets `options.headers['Authorization']`

**Platform Behavior:**
- All platforms supported
- Uses MD5Stream for hashing

---

#### checkEventForwarding(digestRequest, eventName) - Lines 21-35

**Purpose:** Sets up event forwarding from underlying HTTP request to digest request wrapper.

**Process:**
- Checks if digest request has listeners for specified event
- Creates forwarding function that re-emits events
- Attaches to underlying HTTP request

**Events Forwarded:**
- `'upgrade'` - WebSocket/HTTP upgrade
- `'error'` - Request errors
- `'continue'` - 100-Continue responses
- `'timeout'` - Request timeout
- `'drain'` - Write buffer drained

---

### Usage

#### Basic GET Request

```javascript
var httpDigest = require('http-digest');

// Create digest client
var digest = httpDigest.create('admin', 'password');

// Assign HTTP client (required)
digest.http = require('http');

// Make request
digest.get('http://192.168.1.100:16992/status.xml')
    .on('response', function(response) {
        var data = '';
        response.on('data', function(chunk) {
            data += chunk.toString();
        });
        response.on('end', function() {
            console.log('Response:', data);
        });
    })
    .on('error', function(error) {
        console.error('Error:', error);
    });
```

#### POST Request with Body

```javascript
var digest = httpDigest.create('admin', 'password');
digest.http = require('http');

var request = digest.request({
    method: 'POST',
    hostname: '192.168.1.100',
    port: 16992,
    path: '/api/command',
    headers: {
        'Content-Type': 'application/json'
    }
});

request.on('response', function(response) {
    console.log('Status:', response.statusCode);
});

request.write(JSON.stringify({ command: 'reboot' }));
request.end();
```

#### Specifying QoP Mode

```javascript
var digest = httpDigest.create({
    username: 'admin',
    password: 'password',
    qop: 'auth-int'  // Force auth-int mode
});
digest.http = require('http');

digest.get('http://server/data')
    .on('response', function(res) {
        console.log('Authenticated with auth-int');
    });
```

#### Handling Authentication Failures

```javascript
var digest = httpDigest.create('admin', 'wrongpassword');
digest.http = require('http');

digest.get('http://server/api')
    .on('response', function(response) {
        if (response.statusCode === 200) {
            console.log('Authentication successful');
        }
    })
    .on('error', function(error) {
        console.error('Authentication failed:', error);
        // Error after second 401: "Digest failed too many times"
    });
```

---

### Dependencies

#### Node.js Core Modules

- **`stream`** (line 18)
  - Purpose: Writable stream base class
  - Usage: Request wrapper extends Writable
  - Methods used: `write()`, `final()`, event emission
  - Platform support: Cross-platform

- **`http`** (line 143)
  - Purpose: HTTP client functionality (must be assigned by caller)
  - Usage: `http.request()`, `http.parseUri()`, `http.generateNonce()`
  - Note: Caller must assign to `digest.http` property
  - Platform support: Cross-platform

- **`events`** (line 211)
  - Purpose: EventEmitter for request events
  - Usage: Extends request wrapper with custom events
  - Events: 'response', 'error', 'upgrade', 'continue', 'timeout', 'drain'
  - Platform support: Cross-platform

#### MeshAgent Module Dependencies

- **`MD5Stream`** (line 19)
  - Purpose: MD5 hashing for digest calculation
  - Usage: `MD5Stream.create()`, `md5.syncHash(data)`
  - Methods used:
    - `syncHash(string)` - Returns Buffer containing MD5 hash
    - `toString('hex')` - Converts hash to hex string
  - Platform support: Cross-platform

#### External Dependencies

**None** - This module has no external binary or library dependencies beyond Node.js core and MeshAgent modules.

#### Dependency Summary

| Dependency Type | Module | Required | Platform-Specific |
|----------------|--------|----------|-------------------|
| Node.js Core | stream | Yes | No |
| Node.js Core | http | Yes (assigned by caller) | No |
| Node.js Core | events | Yes | No |
| MeshAgent | MD5Stream | Yes | No |
| External Binary | None | - | - |

---

### Technical Notes

**Request Body Buffering:**

The module buffers all request body data written to the request stream. This buffering is necessary to replay the request body when the server responds with a 401 challenge. Without buffering, the body would be lost after the initial request.

For `auth-int` quality of protection, the buffered body is hashed and included in the digest calculation. This provides integrity protection, ensuring the request body wasn't tampered with during transmission.

**Nonce Counter (NC):**

The nonce counter starts at 0 and increments with each authenticated request using the same server nonce. This counter prevents replay attacks where an attacker intercepts and retries a valid request. The server tracks the NC value and rejects requests with old/duplicate NC values.

Format: 8-character zero-padded hexadecimal (e.g., "00000001", "00000002")

**Client Nonce (CNONCE):**

The client nonce is a random 16-byte hex string generated once per digest instance. It provides additional entropy to prevent dictionary attacks and ensures uniqueness of the digest response even if multiple clients use the same credentials simultaneously.

**QoP Selection Priority:**

When the server offers multiple QoP modes, the module selects based on this priority:
1. User-specified `qop` option (if provided and supported by server)
2. `auth-int` (if available)
3. `auth` (if available)
4. Legacy mode (if no qop offered)

The `auth-int` mode is preferred because it provides integrity protection for the request body. However, it requires the entire request body to be available before authentication, which may not be feasible for streaming uploads.

**Legacy Mode Support:**

When a server doesn't specify `qop` in the WWW-Authenticate header, the module uses legacy digest calculation (RFC 2069) which omits the NC, CNONCE, and QoP fields. This ensures compatibility with older servers that don't support QoP-based authentication.

**Header Parsing:**

The module parses the `WWW-Authenticate` header by splitting on commas and equals signs. Quoted strings have their quotes removed. This simple parsing works for standard-compliant servers but may fail on malformed headers.

**Event Forwarding:**

Not all HTTP events are automatically forwarded. The module only forwards events that are explicitly listened to on the digest request object. This lazy forwarding prevents unnecessary event handler registration on the underlying HTTP request.

**Error Handling:**

If authentication fails twice (second 401 response), the module emits an 'error' event with message "Digest failed too many times" and stops retrying. This prevents infinite retry loops when credentials are incorrect.

**Stateful Authentication:**

Once a digest instance successfully authenticates, the `_auth` object caches the server's realm, nonce, and opaque values. Subsequent requests can generate auth headers immediately without waiting for a 401 challenge, reducing latency.

**MD5 Security Considerations:**

MD5 is cryptographically broken and should not be used for new security protocols. However, HTTP Digest Authentication is a legacy standard (RFC 2617, published 1999) that requires MD5 for compatibility. The protocol is still more secure than Basic authentication (which sends passwords in plaintext) but should be used over TLS/HTTPS when possible.

**Replay Attack Window:**

The nonce counter (NC) prevents replay attacks only within the same nonce period. If the server issues a new nonce, old requests with the previous nonce cannot be replayed. However, requests with the same NC value within the same nonce period could potentially be replayed if the server doesn't track NC values properly.

## Summary

The http-digest.js module is a **cross-platform HTTP Digest Authentication client** supporting all major operating systems (Windows, Linux, macOS, FreeBSD). It implements RFC 2617 digest authentication with automatic challenge handling and transparent retry logic.

**Key features:**
- Automatic 401 challenge detection and retry
- Support for 'auth' and 'auth-int' quality of protection modes
- Legacy mode support (RFC 2069) for older servers
- Nonce counter (NC) management for replay attack prevention
- Client nonce (CNONCE) generation for additional security
- Request body buffering for authentication retries
- Event forwarding (upgrade, error, continue, timeout, drain)
- Drop-in replacement for standard HTTP client requests
- Stateful authentication caching for reduced latency
- Writable stream interface for request body streaming

**QoP modes:**
- **auth:** Authentication only (method + URI hashed)
- **auth-int:** Authentication with integrity protection (method + URI + body hash)
- **legacy:** RFC 2069 mode without QoP (simplified hash)

The module is used within MeshAgent primarily for communicating with Intel AMT (Active Management Technology) interfaces which require digest authentication. It provides secure, password-based authentication without exposing credentials in plaintext, while maintaining compatibility with legacy systems that haven't migrated to modern authentication schemes.
