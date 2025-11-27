# wget.js

HTTP download utility module providing wget-like functionality with promise-based async operations, progress tracking, SHA384 hashing, proxy support, and abort capability. Designed for platforms lacking native wget or for consistent cross-platform HTTP downloads.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support with automatic proxy detection from registry
- Linux - Full support
- macOS (darwin) - Full support
- FreeBSD - Full support

## Functionality

### Purpose

The wget module provides reliable HTTP/HTTPS file downloads with advanced features:

- **Promise-based API** - Async/await compatible
- **Progress tracking** - Real-time byte count via events
- **SHA384 verification** - Automatic hash calculation during download
- **Proxy support** - Automatic Windows proxy detection, manual configuration available
- **Abort capability** - Cancel downloads in progress
- **Streaming** - Memory-efficient file writing
- **Error handling** - HTTP status code validation, network error management

This module is used for:
- Agent updates and patches
- Module downloads
- Configuration file retrieval
- Any HTTP resource fetching requiring verification

### Download Flow

When `wget(remoteUri, localFilePath, wgetoptions)` is called:

1. **Setup Phase (lines 32-63):**
   - Creates promise with EventEmitter capabilities
   - Adds `abort()` method and `bytes`/`abort` events
   - Checks if agent control channel is connected
   - If not connected and on Windows: Detects proxy from registry

2. **HTTP Request Phase (lines 65-79):**
   - Parses remote URI
   - Merges any custom options
   - Issues HTTP GET request
   - Sets up error handlers

3. **Response Handling Phase (lines 80-120):**
   - Validates HTTP 200 status code
   - Creates file write stream
   - Creates SHA384 hash stream
   - Creates byte accumulator stream
   - Pipes data through all streams

4. **Completion:**
   - Hash stream emits 'hash' event with SHA384 hex string
   - Promise resolves with hash
   - All streams clean up

### Key Functions

#### wget(remoteUri, localFilePath, wgetoptions) - Lines 30-124

**Purpose:** Downloads a file from HTTP/HTTPS URL to local filesystem with progress tracking and hash verification.

**Parameters:**
- `remoteUri` (string) - Full URL to download (http:// or https://)
- `localFilePath` (string) - Destination file path (absolute or relative)
- `wgetoptions` (object, optional) - Additional HTTP request options

**Process:**

**1. Promise and Event Setup (lines 32-37):**
```javascript
var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
require('events').EventEmitter.call(ret, true)
    .createEvent('bytes')
    .createEvent('abort')
    .addMethod('abort', function () { this._request.abort(); });
```
Creates promise that also functions as EventEmitter with:
- `bytes` event - Emitted as data is received
- `abort` event - Emitted if download is aborted
- `abort()` method - Cancels the download

**2. Proxy Detection (Windows only, lines 39-63):**
```javascript
if (!agentConnected) {
    if (process.platform == 'win32') {
        var reg = require('win-registry');
        if (reg.QueryKey(..., 'ProxyEnable') == 1) {
            var proxyUri = reg.QueryKey(..., 'ProxyServer');
            require('global-tunnel').initialize(options);
        }
    }
}
```

Checks Windows registry for proxy settings:
- Registry path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
- `ProxyEnable` = 1 indicates proxy is enabled
- `ProxyServer` contains proxy address
- Initializes global-tunnel with proxy configuration

**3. HTTP Request Setup (lines 65-79):**
```javascript
var reqOptions = require('http').parseUri(remoteUri);
// Merge custom options
for (var inputOption in wgetoptions) {
    reqOptions[inputOption] = wgetoptions[inputOption];
}

ret._request = http.get(reqOptions);
ret._request.on('error', function (e) { this.promise._rej(e); });
ret._request.on('abort', function () { this.promise.emit('abort'); });
```

Parses URI and creates HTTP GET request with custom options support.

**4. Response Handler (lines 80-120):**
```javascript
ret._request.on('response', function (imsg) {
    if(imsg.statusCode != 200) {
        this.promise._rej('Server responsed with Status Code: ' + imsg.statusCode);
    }
    else {
        // Create streams
        this._file = require('fs').createWriteStream(localFilePath, { flags: 'wb' });
        this._sha = require('SHA384Stream').create();
        this._accumulator = new writable({ ... });

        // Setup hash resolution
        this._sha.on('hash', function (h) {
            this.promise._res(h.toString('hex'));
        });

        // Pipe data through streams
        imsg.pipe(this._file);          // Write to file
        imsg.pipe(this._accumulator);   // Count bytes
        imsg.pipe(this._sha);           // Calculate hash
    }
});
```

Sets up three parallel streams:
- **File stream**: Writes data to disk
- **Accumulator stream**: Tracks byte count, emits progress
- **SHA384 stream**: Calculates hash, resolves promise on completion

**Return Value:**
- Promise that resolves with SHA384 hash (hex string)
- Promise rejects on HTTP errors or network failures
- Promise object has additional methods/events:
  - `abort()` method - Cancels download
  - `bytes` event - Progress updates
  - `abort` event - Abort notification
  - `progress()` method - Returns current byte count

**Platform Behavior:**
- **Windows**: Automatic proxy detection from registry
- **Linux/macOS/FreeBSD**: No automatic proxy detection (manual configuration via options)
- All platforms support custom proxy via `wgetoptions`

**Custom Options:**
Any HTTP request options can be passed via `wgetoptions`:
```javascript
wget(url, path, {
    headers: {'User-Agent': 'MeshAgent'},
    timeout: 30000,
    agent: customAgent
});
```

**Progress Tracking:**
```javascript
var download = wget(url, path);
download.on('bytes', function(totalBytes) {
    console.log('Downloaded: ' + totalBytes + ' bytes');
});
download.then(function(hash) {
    console.log('Hash: ' + hash);
});
```

**Abort Download:**
```javascript
var download = wget(url, path);
download.on('abort', function() {
    console.log('Download aborted!');
});
setTimeout(function() {
    download.abort();
}, 5000);
```

---

#### progress() Method - Line 122

**Purpose:** Returns the current number of bytes downloaded.

```javascript
ret.progress = function () { return (this._totalBytes); };
```

**Return Value:**
- Integer representing total bytes received so far

**Usage:**
```javascript
var download = wget(url, path);
setInterval(function() {
    console.log('Progress: ' + download.progress() + ' bytes');
}, 1000);
```

---

### Dependencies

#### Node.js Core Modules
- `http` (lines 23, 75) - HTTP client functionality:
  - `parseUri(url)` - Parse URL into components
  - `get(options)` - Issue HTTP GET request
- `stream.Writable` (line 24) - Writable stream base class for byte accumulator
- `fs` (line 93) - File system operations:
  - `createWriteStream(path, options)` - Write stream to file

#### MeshAgent Module Dependencies

**Core Required Modules:**

- **`promise`** (line 22)
  - Custom promise implementation
  - Used for async download orchestration
  - Not Node.js native promises
  - Methods: `_res`, `_rej` for resolution/rejection

- **`MeshAgent`** (line 41) - **Optional**
  - Used to check control channel status
  - Property: `isControlChannelConnected`
  - If module not available, caught silently (lines 43-45)
  - Purpose: Skip proxy detection if agent is already connected

- **`events.EventEmitter`** (line 34)
  - Event handling infrastructure
  - Methods:
    - `createEvent(name)` - Define custom events
    - `addMethod(name, fn)` - Add methods to object
  - Events created:
    - `bytes` - Progress updates
    - `abort` - Download cancellation

- **`SHA384Stream`** (line 94) - **Required**
  - Cryptographic hash stream
  - Method: `create()` - Creates hash stream instance
  - Event: `hash` - Emitted with final hash buffer
  - Used for download verification

**Platform-Specific Dependencies:**

- **`win-registry`** (lines 53, 54, 56) - **Windows only**
  - Windows Registry access
  - Methods:
    - `QueryKey(hive, path, value)` - Read registry values
  - Constants:
    - `HKEY.CurrentUser` - Current user registry hive
  - Used for: Proxy detection on Windows

- **`global-tunnel`** (line 60) - **Windows only (when proxy detected)**
  - Global HTTP/HTTPS proxy configuration
  - Method: `initialize(options)` - Configure proxy for all HTTP requests
  - Used when Windows proxy is detected
  - Enables HTTP/HTTPS tunneling through detected proxy

### Technical Notes

**SHA384 vs SHA256:**

The module uses SHA384 instead of the more common SHA256. SHA384:
- Provides stronger collision resistance
- Part of SHA-2 family
- 384-bit hash output (96 hex characters)
- Computationally similar cost to SHA256
- Better security margin for long-term file verification

**Stream Piping Pattern:**

The download uses parallel stream processing:
```javascript
imsg.pipe(this._file);          // Write to disk
imsg.pipe(this._accumulator);   // Track progress
imsg.pipe(this._sha);           // Calculate hash
```

Each stream receives the same data independently, allowing:
- File writing without blocking hash calculation
- Progress tracking without buffering
- Memory-efficient processing (no data duplication in memory)

**Byte Accumulator Implementation:**

Custom writable stream that doesn't buffer data:
```javascript
write: function(chunk, callback) {
    this.promise._totalBytes += chunk.length;
    this.promise.emit('bytes', this.promise._totalBytes);
    return (true);  // Always accept data
}
```

This lightweight stream:
- Counts bytes without storing them
- Emits progress events
- Returns immediately (doesn't apply backpressure)

**Proxy Detection Logic:**

Proxy detection only runs when:
1. Agent control channel is NOT connected
2. Platform is Windows

Rationale: When agent is connected to server, proxy is already configured. Only need to detect proxy for standalone downloads.

**HTTP Status Code Validation:**

Only HTTP 200 (OK) is accepted:
```javascript
if(imsg.statusCode != 200) {
    this.promise._rej('Server responsed with Status Code: ' + imsg.statusCode);
}
```

Other successful codes (201, 204, 206) are treated as errors. This ensures complete file downloads - partial content or redirects would fail.

**Error Propagation:**

Errors can occur at multiple levels:
- Network errors → `request.on('error')`
- HTTP status errors → Status code check
- File system errors → `createWriteStream()` failure
- Stream errors → Propagated through promise chain

All errors reject the promise, ensuring consistent error handling.

**Memory Efficiency:**

The module never loads the entire file into memory:
- HTTP response streams directly to file
- Hash calculated incrementally
- Progress tracked without buffering
- Suitable for downloading large files (GB+)

**Abort Mechanism:**

The `abort()` method calls `request.abort()`:
```javascript
.addMethod('abort', function () { this._request.abort(); });
```

This:
- Cancels the HTTP request
- Triggers 'abort' event on request
- Emits 'abort' event on promise
- Does NOT delete partial file (caller's responsibility)

**Windows Proxy Registry Paths:**

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyEnable = DWORD (1 = enabled, 0 = disabled)
    ProxyServer = String (e.g., "proxy.company.com:8080")
```

These are the same settings used by Internet Explorer and Edge (Legacy).

## Summary

The wget.js module provides cross-platform HTTP/HTTPS download functionality for **Windows, Linux, macOS, and FreeBSD** with advanced features including promise-based async operations, real-time progress tracking, SHA384 hash verification, and abort capability.

**Windows** receives additional functionality through automatic proxy detection from the system registry, while other platforms require manual proxy configuration if needed. All platforms support custom HTTP options for headers, timeouts, and other request parameters.

The module uses memory-efficient streaming to handle downloads of any size, never loading the entire file into memory. It provides comprehensive error handling and verification through SHA384 hashing, making it suitable for critical file downloads like agent updates and security-sensitive transfers.

The module integrates seamlessly with MeshAgent's promise-based architecture while remaining usable as a standalone download utility with no required MeshAgent dependencies beyond the promise and SHA384Stream modules.
