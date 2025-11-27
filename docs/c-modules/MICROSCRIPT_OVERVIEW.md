# MicroScript - Duktape JavaScript Runtime Integration

**133,214 lines** of C code providing JavaScript runtime (Duktape) bindings for MeshAgent, enabling the entire agent to be scripted in JavaScript.

## Architecture

MicroScript integrates the Duktape ECMAScript engine with MeshAgent's C codebase, providing:
- **JavaScript Engine:** Embedded Duktape (99,928 lines in duktape.c)
- **Node.js-like APIs:** Streams, networking, filesystem, child processes
- **Native Bindings:** Access to C functions from JavaScript
- **Module System:** CommonJS require() support

## Core Components

### duktape.c (99,928 lines)
**Purpose:** Complete ECMAScript 5/6 JavaScript engine

**What:** Third-party embedded JS engine (https://duktape.org)
**Why Large:** Full language implementation (parser, bytecode, GC, etc.)
**MeshAgent Use:** Runs all agent logic in JavaScript

**NOT documented here** - see Duktape official docs

---

### ILibDuktape_Helpers.c
**Purpose:** Helper macros and utilities for Duktape bindings

**Key Functions:**
- `ILibDuktape_Push*()` - Push C values to JS stack
- `ILibDuktape_Get*()` - Get JS values as C types
- Error handling helpers
- Property setter/getter helpers

---

### ILibDuktape_ScriptContainer.c
**Purpose:** JavaScript module execution container

**Key Functions:**
- `ILibDuktape_ScriptContainer_New()` - Create JS context
- `ILibDuktape_ScriptContainer_AddModule()` - Register module
- `ILibDuktape_ScriptContainer_Start()` - Run JavaScript

**Use Case:** Main agent startup loads agentcore.js

---

### ILibDuktape_Polyfills.c
**Purpose:** JavaScript polyfills and compatibility

**What:** Implements missing ES5/6 features in Duktape
**Examples:** Promise, Buffer, process object, console

---

### ILibDuktape_EventEmitter.c
**Purpose:** Node.js EventEmitter pattern

**API:**
```javascript
emitter.on('event', callback);
emitter.emit('event', arg1, arg2);
emitter.removeListener('event', callback);
```

**Use Case:** Foundation for all async APIs

---

### Stream Bindings

#### ILibDuktape_ReadableStream.c
**API:** Node.js Readable stream
```javascript
stream.on('data', (chunk) => {});
stream.pause();
stream.resume();
```

#### ILibDuktape_WritableStream.c
**API:** Node.js Writable stream
```javascript
stream.write(data);
stream.end();
stream.on('finish', () => {});
```

#### ILibDuktape_DuplexStream.c
**API:** Bidirectional stream (TCP sockets)

#### ILibDuktape_MemoryStream.c
**API:** In-memory buffer stream

#### ILibDuktape_CompressedStream.c
**API:** gzip/deflate compression stream

#### ILibDuktape_EncryptionStream.c
**API:** AES encryption/decryption stream

#### ILibDuktape_HttpStream.c
**API:** HTTP request/response streaming

---

### Network Bindings

#### ILibDuktape_net.c
**API:** Node.js `net` module (TCP)
```javascript
const net = require('net');
const socket = net.connect(port, host);
socket.on('data', (data) => {});
```

#### ILibDuktape_Dgram.c
**API:** Node.js `dgram` module (UDP)
```javascript
const dgram = require('dgram');
const socket = dgram.createSocket('udp4');
socket.bind(port);
```

---

### Filesystem Bindings

#### ILibDuktape_fs.c
**API:** Node.js `fs` module
```javascript
const fs = require('fs');
fs.readFile(path, (err, data) => {});
fs.writeFile(path, data, callback);
fs.createReadStream(path);
```

**Platforms:** Cross-platform (Windows, Linux, macOS)

---

### Process Bindings

#### ILibDuktape_ChildProcess.c
**API:** Node.js `child_process` module
```javascript
const child = require('child_process').spawn(cmd, args);
child.stdout.on('data', (data) => {});
child.on('exit', (code) => {});
```

---

### Native Function Marshaling

#### ILibDuktape_GenericMarshal.c
**Purpose:** Call C functions from JavaScript (like FFI)

**API:**
```javascript
const lib = require('_GenericMarshal').CreateNativeProxy('library.so');
const func = lib.getMethod('functionName');
const result = func.call(arg1, arg2);
```

**Use Case:** Access platform APIs not wrapped by modules

---

### WebRTC Bindings

#### ILibDuktape_WebRTC.c
**API:** WebRTC data channels
```javascript
const webrtc = require('ILibWebRTC');
const conn = webrtc.createConnection();
const channel = conn.createDataChannel('label');
```

---

### Utility Bindings

#### ILibDuktape_SHA256.c
**API:** SHA256 hashing
```javascript
const hash = require('SHA256Stream');
```

#### ILibDuktape_NetworkMonitor.c
**API:** Network interface monitoring
```javascript
require('NetworkMonitor').on('change', (interfaces) => {});
```

#### ILibDuktape_SimpleDataStore.c
**API:** Key-value persistence
```javascript
const db = require('SimpleDataStore');
db.Put('key', 'value');
```

#### ILibDuktape_Debugger.c
**API:** JavaScript debugger protocol

---

## Module System

### ILibDuktapeModSearch.c / duk_module_duktape.c
**Purpose:** CommonJS `require()` implementation

**Features:**
- Module search paths
- Built-in modules (fs, net, etc.)
- JavaScript modules (.js files)
- Module caching

**Usage:**
```javascript
const net = require('net');  // Built-in C module
const helper = require('./helper.js');  // JS module
```

---

## Design Patterns

### C-to-JS Bridge
```c
// C implementation
duk_ret_t func(duk_context *ctx) {
    const char* arg = duk_require_string(ctx, 0);
    // ... C logic ...
    duk_push_string(ctx, result);
    return 1;  // 1 return value
}

// Register in Duktape
duk_push_c_function(ctx, func, 1);  // 1 argument
duk_put_global_string(ctx, "nativeFunc");
```

### JS-to-C Callbacks
```javascript
// JavaScript
socket.on('data', function(buffer) {
    // C calls this when data arrives
});
```

**C side:**
- Stores callback function reference
- Calls `duk_pcall()` to invoke JS function
- Pushes arguments onto stack

---

## Memory Management

### Garbage Collection
- **Duktape GC:** Mark-and-sweep, automatic
- **C Objects:** Must be freed explicitly in finalizers
- **Finalizers:** `ILibDuktape_CreateFinalizerEx()` ensures cleanup

### Reference Counting
- C objects wrapped in JS get finalizer
- Finalizer calls `free()` when JS object collected

---

## Performance

**Duktape Speed:**
- ~10x slower than V8 (but much smaller)
- Fast enough for agent control logic
- Heavy work done in C (networking, crypto)

**Optimizations:**
- Minimize C-to-JS transitions
- Pre-allocate buffers
- Native modules for hot paths

---

## Security

**Sandboxing:**
- Can disable dangerous functions
- Restricts filesystem access
- No arbitrary code execution by default

**Input Validation:**
- All C bindings validate JS arguments
- Type checking before C calls

---

## Platform Support

**Cross-Platform:**
- Windows (x86, x64, ARM)
- Linux (x86, x64, ARM, MIPS)
- macOS (x86_64, arm64)
- FreeBSD

**Platform-Specific Bindings:**
- Some modules only available on certain platforms
- Gracefully degrade or throw errors

---

## Usage in MeshAgent

| Feature | MicroScript Modules |
|---------|-------------------|
| Agent logic | duktape.c (runs agentcore.js) |
| Networking | ILibDuktape_net.c, ILibDuktape_Dgram.c |
| File I/O | ILibDuktape_fs.c |
| Crypto | ILibDuktape_EncryptionStream.c, ILibDuktape_SHA256.c |
| Processes | ILibDuktape_ChildProcess.c |
| WebRTC | ILibDuktape_WebRTC.c |
| Platform APIs | ILibDuktape_GenericMarshal.c |

**~95% of MeshAgent is JavaScript**, enabled by these bindings.

---

## Documentation

Each microscript module provides a JavaScript API matching Node.js where possible.

For JavaScript API docs, see `/docs/meshagent-modules/` (JavaScript module documentation).

For C binding implementation details, see individual `.c` file comments.

---

**Total LOC:** 133,214 (including duktape.c)
**Files:** 24
**Primary Use:** JavaScript runtime for MeshAgent
**Engine:** Duktape 2.7+ (https://duktape.org)
**Maintained:** Active (2025)
