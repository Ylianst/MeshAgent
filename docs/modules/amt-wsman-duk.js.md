# amt-wsman-duk.js

WSMAN (Web Services for Management) transport layer implementation using Duktape's HTTP client with HTTP Digest authentication. Provides the low-level communication infrastructure for managing Intel AMT devices over the network via the WSMAN protocol.

## Platform

**Supported Platforms:**
- Windows - Full support
- Linux - Full support
- FreeBSD - Full support
- **Cross-platform** - Works on any platform with network connectivity

**Excluded Platforms:**
- **macOS** - Excluded (technically compatible, contextually irrelevant)

**Exclusion Reasoning:**

While **technically cross-platform and fully compatible** (contains no platform-specific code), this module is excluded from macOS builds because:

1. **Intel AMT Hardware Dependency** - Used exclusively for managing Intel AMT devices which are primarily found on:
   - Intel vPro-enabled business desktops and laptops
   - Server platforms with Intel ME (Management Engine)
   - Not typically found on consumer systems or Apple hardware

2. **Limited macOS Context** - macOS machines:
   - Rarely run as management servers in enterprise environments
   - Don't have Intel AMT hardware (Apple Silicon or Intel without vPro)
   - Unlikely to need AMT management capabilities
   - Enterprise management typically uses Windows/Linux servers

3. **Part of AMT Stack** - This module is a dependency for higher-level AMT modules (amt.js, amt-wsman.js) which collectively form the Intel AMT management stack. The entire stack is excluded from macOS builds.

4. **Contextually Irrelevant** - While the network protocol implementation would function correctly on macOS, the AMT management use case doesn't apply to typical macOS deployments in enterprise IT operations.

## Functionality

### Core Purpose

Provides HTTP/HTTPS transport layer for WSMAN protocol communication with Intel AMT devices. Handles:
- HTTP POST requests to AMT device's `/wsman` endpoint
- HTTP Digest authentication (MD5-based challenge-response)
- Request queueing and concurrency control
- TLS/non-TLS connection support
- Response parsing and error handling

### WSMAN Protocol Context

**WSMAN (WS-Management):**
- SOAP-based protocol for system management
- Standard defined by DMTF (Distributed Management Task Force)
- Used by Intel AMT for out-of-band management
- Typical endpoint: `http(s)://amt-device:16992/wsman` or port 16993 for TLS

**Authentication:**
- HTTP Digest authentication (RFC 2617)
- More secure than Basic auth (passwords not sent in cleartext)
- Challenge-response mechanism with MD5 hashing

### Constructor: CreateWsmanComm(options)

**Object-Based Constructor (Lines 33-38):**
```javascript
var wsman = require('amt-wsman-duk')({
    host: '192.168.1.100',
    port: 16992,
    authToken: 'admin:P@ssw0rd',  // or separate user/pass
    tls: 0  // 0 = HTTP, 1 = HTTPS
});
```

**Legacy Positional Constructor (Lines 40-45):**
```javascript
var wsman = require('amt-wsman-duk')(
    '192.168.1.100',  // host
    16992,             // port
    'admin',           // user
    'P@ssw0rd',       // pass
    0                  // tls (0 or 1)
);
```

**Parameters:**
- `host` (string) - IP address or hostname of AMT device
- `port` (number) - WSMAN port (typically 16992 HTTP, 16993 HTTPS)
- `authToken` (string) - Combined `username:password` token (preferred)
- `user` (string) - Username (legacy)
- `pass` (string) - Password (legacy)
- `tls` (number) - 0 for HTTP, 1 for HTTPS

### Request Queue Management (Lines 26-28, 50-66)

**Concurrency Control:**
- `ActiveAjaxCount` - Currently executing requests
- `MaxActiveAjaxCount` - Maximum concurrent requests (default: 1)
- `PendingAjax` - Queue of requests awaiting execution

**Queue Behavior:**
```javascript
obj.MaxActiveAjaxCount = 1;  // Serial execution by default
```

**Why Serial Execution:**
- Many AMT devices can't handle concurrent WSMAN requests
- Prevents race conditions in AMT firmware
- Ensures predictable request ordering
- Can be increased for devices that support concurrency

**Priority Requests (Line 56):**
```javascript
if (pri == 1) {
    obj.PendingAjax.unshift([postdata, callback, tag, url, action]);  // Front of queue
} else {
    obj.PendingAjax.push([postdata, callback, tag, url, action]);     // End of queue
}
```

**Use Case:** High-priority operations (like heartbeats) can jump the queue

### PerformAjax(postdata, callback, tag, pri, url, action) - Line 50

**Purpose:** Queue or immediately execute WSMAN request

**Parameters:**
- `postdata` (string) - SOAP XML request body
- `callback` (function) - Callback function `(responseData, statusCode, tag)`
- `tag` (any) - User-defined data passed through to callback
- `pri` (number) - Priority: 1 = high (front of queue), 0 = normal (back of queue)
- `url` (string) - Optional URL path (default: `/wsman`)
- `action` (string) - Optional SOAP action header

**Behavior:**
1. If no active requests and no queue: Execute immediately
2. If at concurrency limit or queue not empty: Add to queue based on priority
3. Auto-executes next queued request when current completes

### PerformAjaxEx(postdata, callback, tag, url, action) - Line 69

**Purpose:** Actually execute HTTP request (internal method)

**HTTP Request Configuration (Line 84):**
```javascript
var request = {
    delayWrite: true,                           // Delay body write for digest auth
    protocol: (obj.tls == 1 ? 'https:' : 'http:'),
    method: 'POST',
    host: obj.host,
    path: '/wsman',
    port: obj.port,
    rejectUnauthorized: false,                  // Accept self-signed certs
    checkServerIdentity: function (cert) { }    // Skip cert validation
};
```

**Security Note:**
- `rejectUnauthorized: false` - Accepts self-signed certificates common on AMT devices
- Appropriate for AMT since it's typically on trusted local networks
- Would be security risk for internet-facing services

**Digest Authentication Initialization (Lines 76-83):**
```javascript
if (obj.digest == null) {
    if (obj.authToken) {
        obj.digest = require('http-digest').create({ authToken: obj.authToken });
    } else {
        obj.digest = require('http-digest').create(obj.user, obj.pass);
    }
    obj.digest.http = require('http');
}
```

**HTTP Digest Flow:**
1. First request sent without auth
2. Server responds with 401 + challenge nonce
3. http-digest module automatically retries with digest response
4. Subsequent requests include digest header preemptively

### Response Handling (Lines 90-107)

**Success Path (Lines 96-100):**
```javascript
if (response.statusCode != 200) {
    // Error handling
} else {
    response.acc = '';
    response.on('data', function (data2) { this.acc += data2; });
    response.on('end', function () {
        obj.gotNextMessages(response.acc, 'success', { status: response.statusCode }, [postdata, callback, tag]);
    });
}
```

**Response Assembly:**
- Accumulates response chunks in `response.acc`
- Waits for complete response before parsing
- Passes full response body to callback

**Error Path (Line 89, 93-95):**
```javascript
req.on('error', function (e) {
    obj.gotNextMessagesError({ status: 600 }, 'error', null, [postdata, callback, tag]);
});
```

**Status Code 600:** Custom error code for network-level errors (connection refused, timeout, etc.)

### Error Recovery: FailAllError (Line 29, 71)

**Purpose:** Fail-fast mechanism for bulk operation cancellation

**Usage:**
```javascript
obj.FailAllError = 0;     // Normal operation
obj.FailAllError = 500;   // Fail all with HTTP 500
obj.FailAllError = 999;   // Fail all silently (no callbacks)
```

**Behavior:**
- When non-zero: All queued and new requests immediately fail with that status
- Value 999: Special "silent" mode - callbacks not invoked
- Use case: Abort operation when AMT device becomes unreachable

### CancelAllQueries(status) - Line 134

```javascript
obj.CancelAllQueries = function (s) {
    while (obj.PendingAjax.length > 0) {
        var x = obj.PendingAjax.shift();
        x[1](null, s, x[2]);  // Invoke callback with null data and error status
    }
}
```

**Purpose:** Empty request queue and notify all callbacks

**Use Case:** Clean shutdown or connection failure

### Debug Logging (Lines 73, 87, 92, 116)

**Global Debug Flag:**
```javascript
if (globalDebugFlags & 1) {
    console.log("SEND: " + postdata + "\r\n\r\n");
    console.log('Request ' + (obj.RequestCount++));
    console.log('Response: ' + response.statusCode);
    console.log("RECV: " + data + "\r\n\r\n");
}
```

**Activation:** Set `globalDebugFlags = 1` (or any odd number) to enable WSMAN traffic logging

**Output:** Full SOAP XML requests and responses for debugging AMT communication

## Dependencies

### MeshAgent Module Dependencies

#### http-digest (Lines 78, 80)

```javascript
obj.digest = require('http-digest').create({ authToken: obj.authToken });
// or
obj.digest = require('http-digest').create(obj.user, obj.pass);
```

**Purpose:** HTTP Digest authentication implementation (RFC 2617)

**Functionality:**
- Handles MD5-based challenge-response
- Automatically retries requests after 401 challenges
- Maintains authentication state across requests
- Preemptively sends digest header after first successful auth

**Methods Used:**
- `create(user, pass)` or `create({authToken})` - Initialize digest auth
- `request(options)` - Create authenticated HTTP request

**Source:** Part of MeshAgent module collection (not Node.js core)

**Dependency Chain:**
```
amt-wsman-duk.js
└─── http-digest.js
     └─── http (Node.js core)
```

### Node.js Core Module Dependencies

#### http (Line 82)

```javascript
obj.digest.http = require('http');
```

**Purpose:** HTTP/HTTPS client for network communication

**Usage:**
- Passed to http-digest module for request creation
- Handles TCP connection, HTTP protocol, TLS encryption
- Provides streaming request/response interface

**Methods Indirectly Used:**
- `http.request()` - Create HTTP request
- `https.request()` - Create HTTPS request (when tls=1)
- Request event handlers: 'error', 'response'
- Response event handlers: 'data', 'end'

**Type:** Node.js core module (no installation required)

### Dependency Chain Summary

```
amt-wsman-duk.js
├─── http-digest (Lines 78, 80) - Digest authentication
│    └─── HTTP challenge-response implementation
└─── http (Line 82) - HTTP/HTTPS client
     └─── Node.js core networking
```

**Upstream Dependencies:**
Modules that depend on amt-wsman-duk.js:
- **amt-wsman.js** - Higher-level WSMAN protocol implementation
- **amt.js** - Intel AMT management API
- **CSP.js** - Intel Client Service Platform

### Platform Binary Dependencies

**None** - Pure JavaScript implementation with no native binary dependencies

**Network Requirements:**
- TCP/IP connectivity to AMT device
- Access to AMT management ports (16992 HTTP, 16993 HTTPS)
- No firewall blocking between client and AMT device

## Technical Notes

### Duktape Environment

**Comment Line 75:** "We are in a DukTape environement"

**Duktape Context:**
- MeshAgent uses Duktape JavaScript engine (lightweight, embeddable)
- This module designed specifically for Duktape's HTTP client API
- Not compatible with browser XMLHttpRequest or Node.js standard http module directly

**Naming:** The `-duk` suffix indicates "Duktape version" (vs. browser versions)

### HTTP vs HTTPS

**Default AMT Ports:**
- Port 16992 - HTTP (unencrypted)
- Port 16993 - HTTPS (TLS encrypted)

**TLS Configuration:**
- `tls: 0` - HTTP (faster, less secure)
- `tls: 1` - HTTPS (slower, more secure)
- `rejectUnauthorized: false` - Accept self-signed certificates (common on AMT)

**Security Consideration:**
- AMT typically uses self-signed certificates
- In enterprise environments, consider configuring proper certificates
- HTTP acceptable on isolated management networks

### Request Serialization

**Why MaxActiveAjaxCount = 1:**
- Intel AMT firmware has limited request handling capacity
- Concurrent requests can cause firmware timeouts or crashes
- Serial execution ensures reliability
- Can increase for newer AMT versions or testing

### Memory Management

**Response Accumulation (Line 98):**
```javascript
response.on('data', function (data2) { this.acc += data2; });
```

**Consideration:** Large WSMAN responses (e.g., large file transfers) accumulate in memory. For huge responses, streaming would be more efficient, but WSMAN typically sends moderate-sized XML documents.

### Error Code Conventions

**HTTP Status Codes:**
- `200` - Success
- `401` - Authentication required (handled automatically by http-digest)
- `500` - Server error
- `600` - Network error (custom code for connection failures)

**Error Status in Callback:**
```javascript
callback(data, statusCode, tag);
// data = null on error
// statusCode = HTTP status or 600 for network errors
```

### Performance Characteristics

**Latency:**
- Each request: ~50-200ms depending on network and AMT device
- Digest auth adds one extra round-trip on first request
- Serial execution prevents parallel speedup

**Throughput:**
- Limited by AMT device processing speed
- Typically 5-20 operations per second
- Network latency usually not the bottleneck

### Alternative Transport

**Other WSMAN Transports in MeshAgent:**
- **amt-wsman.js** - Browser-compatible version using XMLHttpRequest
- **amt-wsman-duk.js** - This module (Duktape environment)

**Selection:** MeshAgent runtime selects appropriate transport based on environment

## Summary

The amt-wsman-duk.js module provides the HTTP transport layer for WSMAN protocol communication with Intel AMT devices in Duktape JavaScript environments. It implements HTTP Digest authentication, request queueing, concurrency control, and error handling specifically tailored for Intel AMT firmware limitations.

**Placed in modules_macos_NEVER** because:
- Part of Intel AMT management stack (rarely relevant on macOS)
- Intel AMT hardware primarily found on Windows/Linux business PCs and servers
- macOS systems unlikely to run AMT management infrastructure
- Apple hardware doesn't include Intel AMT/vPro technology

**Technical capability:** The module is actually cross-platform and contains no platform-specific code. It would function correctly on macOS for managing remote AMT devices. The exclusion is architectural - the AMT management use case doesn't apply to typical macOS deployments in enterprise environments.

Alternative WSMAN implementations would be needed for other management protocols or non-AMT devices.
