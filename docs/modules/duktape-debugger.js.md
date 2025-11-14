# duktape-debugger.js

Comprehensive debugger client for the Duktape JavaScript engine. Provides full debugging capabilities including breakpoints, step execution, variable inspection, call stack analysis, and bytecode disassembly. This module implements the Duktape debug protocol for remote debugging of JavaScript code running in the embedded Duktape engine.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support
- macOS (darwin) - Full support
- FreeBSD - Full support

**Excluded Platforms:**
- None - This module is cross-platform

**Exclusion Reasoning:**

This module has no platform exclusions. It implements a protocol-level debugging interface for the Duktape JavaScript engine, which is platform-independent. The module operates entirely at the protocol level, communicating over streams (TCP sockets, named pipes, or other transport mechanisms) without any platform-specific system calls or APIs. All functionality is implemented using standard Node.js `stream` and `events` modules, making it universally compatible.

## Functionality

### Purpose

The duktape-debugger module serves as a complete client-side debugger implementation for Duktape, a lightweight embeddable JavaScript engine. It provides developers with comprehensive debugging capabilities for JavaScript code running in resource-constrained environments:

- **Breakpoint Management:** Set, modify, and delete breakpoints
- **Step Debugging:** Step over, step into, step out of function calls
- **Variable Inspection:** Examine local variables, closures, and object properties
- **Call Stack Analysis:** Navigate and inspect the execution call stack
- **Source Code Management:** Retrieve and cache source code from the debug target
- **Bytecode Disassembly:** Decode and display Duktape bytecode instructions
- **Evaluation:** Execute arbitrary JavaScript expressions in the target context
- **Message Logging:** Capture and display debug output and print statements

This module is typically used:
- During MeshAgent development to debug embedded JavaScript modules
- To troubleshoot runtime issues in production deployments
- For educational purposes to understand JavaScript execution in Duktape
- To analyze performance and execution flow of agent scripts

### Debug Protocol Architecture

The debugger implements a bidirectional binary protocol for communication with Duktape's debug transport:

**Protocol Layers:**
1. **Transport Layer:** Stream-based communication (TCP, pipe, etc.)
2. **Protocol Parser:** Binary message framing and dvalue encoding/decoding
3. **Debugger Logic:** State management, request queueing, event handling
4. **UI Interface:** WebSocket/event-based interface for debug clients

**Message Flow:**
```
Debug Client (Web UI) <--> Debugger Instance <--> Protocol Parser <--> Debug Target (Duktape)
```

### Key Classes and Functions

#### Debugger() - Line 743

**Purpose:** Main debugger class that manages debug sessions and state.

**Constructor Initialization:**
- Extends EventEmitter for event-driven communication
- Initializes connection state (targetStream, parsers, protocol version)
- Sets up execution status tracking (attached, state, location)
- Creates data structures for breakpoints, call stack, locals
- Configures message logging with 100-line scrollback buffer
- Initializes statistics tracking (bytes, messages, dvalues)

**Key Properties:**
```javascript
{
    _ObjectID: 'Debugger',
    web: null,                      // Web UI singleton reference
    targetStream: null,             // Transport connection
    inputParser: null,              // Incoming message parser
    outputParser: null,             // Outgoing message parser
    protocolVersion: null,          // Debug protocol version
    dukVersion: null,               // Duktape version string
    debugger_attached: false,       // Connection status
    handshook: false,               // Handshake completion flag
    reqQueue: [],                   // Request queue
    stats: {                        // Connection statistics
        rxBytes, rxDvalues, rxMessages, rxBytesPerSec,
        txBytes, txDvalues, txMessages, txBytesPerSec
    },
    execStatus: {                   // Current execution state
        attached: false,
        state: 'detached',          // 'running', 'paused', 'detached'
        fileName: '',
        funcName: '',
        line: 0,
        pc: 0                       // Program counter
    },
    breakpoints: [],                // Array of breakpoint objects
    callstack: [],                  // Current call stack
    locals: [],                     // Local variables
    messageLines: [],               // Debug output messages
    messageScrollBack: 100          // Message history limit
}
```

**Events Emitted:**
- `'attached'` - Debug transport connected
- `'detached'` - Debug transport disconnected
- `'status-update'` - Execution status changed
- `'breakpoint-added'` - New breakpoint set
- `'breakpoint-deleted'` - Breakpoint removed
- `'callstack-update'` - Call stack changed
- `'locals-update'` - Local variables updated
- `'print'` - Print output from target
- `'log'` - Log message from target

**Platform Behavior:**
- All platforms supported
- Transport-agnostic (works over any duplex stream)

---

#### DebugProtocolParser(inputStream, outputStream) - Line 392

**Purpose:** Parses and encodes the binary debug protocol used by Duktape.

**Process:**
- Creates input and output parsers for bidirectional communication
- Implements dvalue (debug value) encoding/decoding
- Handles message framing and integrity checking
- Tracks protocol statistics (bytes, messages)
- Emits events for parsed debug messages

**Debug Protocol Encoding:**

The Duktape debug protocol uses "dvalues" for encoding data:

| Type | Initial Byte | Format | Description |
|------|--------------|--------|-------------|
| EOM | 0x00 | 1 byte | End of message marker |
| REQ | 0x01 | 1 byte | Request marker |
| REP | 0x02 | 1 byte | Reply marker |
| ERR | 0x03 | 1 byte | Error marker |
| NFY | 0x04 | 1 byte | Notification marker |
| Integer | 0x10-0x1f | Variable | Small integer (-16 to +15) |
| String | 0x60-0x7f | Length + data | UTF-8 string |
| Buffer | 0x80-0xbf | Length + data | Binary buffer |
| Unused | 0xc0 | 1 byte | Unused marker |
| Undefined | 0xc1 | 1 byte | undefined value |
| Null | 0xc2 | 1 byte | null value |
| True | 0xc3 | 1 byte | Boolean true |
| False | 0xc4 | 1 byte | Boolean false |
| Number | 0xc5 | 9 bytes | IEEE 754 double |
| Object | 0xc6 | Variable | Object with class/pointer |
| Pointer | 0xc7 | Variable | Raw pointer value |
| Lightfunc | 0xc8 | Variable | Lightweight function |
| Heapptr | 0xc9 | Variable | Heap pointer |

**Message Structure:**
```
[CMD_BYTE] [DVALUE1] [DVALUE2] ... [0x00 EOM]
```

**Platform Behavior:**
- All platforms supported
- Binary protocol is platform-independent

---

#### formatDebugValue(v) - Line 240

**Purpose:** Formats debug values into human-readable strings for display.

**Process:**
- Handles all dvalue types (number, string, object, buffer, etc.)
- Formats objects with class name and pointer
- Truncates long strings for display
- Converts buffers to hex representation
- Handles special values (undefined, null, NaN, Infinity)

**Return Format Examples:**
```javascript
formatDebugValue(123)              // "123"
formatDebugValue("hello")          // '"hello"'
formatDebugValue({type: 'object'}) // 'Object 0x12345678'
formatDebugValue(null)             // 'null'
formatDebugValue(undefined)        // 'undefined'
```

---

#### prettyDebugValue(x) - Line 1957

**Purpose:** Pretty-prints debug values with enhanced formatting for UI display.

**Process:**
- Similar to `formatDebugValue()` but with UI-specific formatting
- Handles clipping long values
- Adds visual indicators for special types
- Formats nested structures with indentation

---

#### prettyDebugCommand(cmd) - Line 2115

**Purpose:** Formats debug commands for logging and debugging.

**Process:**
- Takes command object with dvalues
- Converts to human-readable command string
- Useful for protocol debugging and logging

---

#### decodeAndNormalizeSource(data) - Line 2123

**Purpose:** Decodes and normalizes source code from debug target.

**Process:**
- Handles various source encodings (UTF-8, etc.)
- Normalizes line endings (converts CRLF to LF)
- Removes BOM markers if present
- Caches decoded source for performance

**Platform Behavior:**
- All platforms supported
- Handles platform-specific line endings

---

#### decodeBytecodeFromBuffer(buf, consts, funcs) - Line 792

**Purpose:** Disassembles Duktape bytecode into human-readable instructions.

**Process:**
- Reads 32-bit instruction words from buffer
- Handles both little-endian and big-endian byte order
- Decodes opcode and operands
- Resolves constant and function references
- Formats output with program counter, hex encoding, and mnemonic
- Adds inline comments for flags and computed addresses

**Output Format:**
```
PC    HEXCODE    OPCODE       OPERANDS                      ; COMMENTS
00000 01234567   LDCONST      r0, c42                       ; load constant
00001 89abcdef   CALL         r0, 2                         ; call function
00002 fedcba98   JUMP         15 (+13)                      ; jump forward
```

**Platform Behavior:**
- All platforms supported
- Bytecode format is Duktape-specific, not platform-dependent

---

### Debugging Operations

#### Breakpoints

**Setting Breakpoints:**
```javascript
debugger.addBreakpoint(fileName, lineNumber);
```

**Deleting Breakpoints:**
```javascript
debugger.deleteBreakpoint(breakpointIndex);
```

**Breakpoint Object Structure:**
```javascript
{
    fileName: "module.js",
    lineNumber: 42,
    enabled: true
}
```

#### Step Execution

**Step Over:** Execute current line, step over function calls
```javascript
debugger.sendStepOver();
```

**Step Into:** Execute current line, step into function calls
```javascript
debugger.sendStepInto();
```

**Step Out:** Execute until return from current function
```javascript
debugger.sendStepOut();
```

**Resume Execution:** Continue running until next breakpoint
```javascript
debugger.sendResume();
```

**Pause Execution:** Interrupt running program
```javascript
debugger.sendPause();
```

#### Variable Inspection

**Get Local Variables:**
```javascript
debugger.getLocals().then(function(locals) {
    // locals is array of {name, value} objects
});
```

**Evaluate Expression:**
```javascript
debugger.eval("x + y").then(function(result) {
    console.log("Result:", result);
});
```

**Get Call Stack:**
```javascript
debugger.getCallStack().then(function(stack) {
    // stack is array of frame objects
});
```

---

### Usage

#### Basic Debugging Session

```javascript
var Debugger = require('duktape-debugger');
var net = require('net');

// Create debugger instance
var dbg = new Debugger();

// Connect to debug target
var socket = net.connect(9091, 'localhost');
dbg.attach(socket);

// Listen for status updates
dbg.on('status-update', function(status) {
    console.log('Execution state:', status.state);
    console.log('Current location:', status.fileName + ':' + status.line);
});

// Listen for print output
dbg.on('print', function(message) {
    console.log('[Target]:', message);
});

// Set breakpoint
dbg.addBreakpoint('app.js', 10);

// Resume execution
dbg.sendResume();
```

#### Inspecting Variables

```javascript
// When paused at breakpoint
dbg.on('status-update', function(status) {
    if (status.state === 'paused') {
        // Get local variables
        dbg.getLocals().then(function(locals) {
            locals.forEach(function(local) {
                console.log(local.name + ' =', local.value);
            });
        });

        // Get call stack
        dbg.getCallStack().then(function(stack) {
            stack.forEach(function(frame, i) {
                console.log(i + ':', frame.function + ' at ' + frame.fileName + ':' + frame.line);
            });
        });
    }
});
```

#### Evaluating Expressions

```javascript
dbg.eval("Math.sqrt(16) + x").then(function(result) {
    console.log('Evaluation result:', result);
}).catch(function(error) {
    console.error('Evaluation error:', error);
});
```

---

### Dependencies

#### Node.js Core Modules

- **`stream`** (Line 392+)
  - Purpose: Stream-based protocol parsing
  - Usage: Extends Writable stream for input parsing
  - Methods used: `write()`, `on('data')`, `on('end')`, `on('close')`
  - Platform support: Cross-platform

- **`events`** (Line 745)
  - Purpose: EventEmitter functionality
  - Usage: Debugger class extends EventEmitter
  - Events: `'attached'`, `'detached'`, `'status-update'`, `'breakpoint-added'`, etc.
  - Platform support: Cross-platform

#### MeshAgent Module Dependencies

**None** - This module has no MeshAgent-specific dependencies. It operates as a standalone debug client that can connect to any Duktape instance with debug transport enabled.

#### External Dependencies

**None** - This module has no external binary or library dependencies beyond Node.js core modules.

#### Dependency Summary

| Dependency Type | Module | Required | Platform-Specific |
|----------------|--------|----------|-------------------|
| Node.js Core | stream | Yes | No |
| Node.js Core | events | Yes | No |
| MeshAgent | None | - | - |
| External Binary | None | - | - |

---

### Technical Notes

**Binary Protocol Implementation:**

The Duktape debug protocol is a compact binary protocol designed for efficiency in embedded environments. The protocol uses variable-length encoding for integers and strings to minimize bandwidth usage. The parser maintains state across multiple `write()` calls to handle partial messages, making it suitable for streaming transports like TCP sockets.

**Dvalue Encoding Efficiency:**

Small integers (-16 to +15) encode in a single byte, while larger integers use variable-length encoding. Strings and buffers include length prefixes to avoid null-termination overhead. This makes the protocol suitable for low-bandwidth debug connections.

**State Management:**

The debugger maintains persistent state including breakpoints, call stack, and variable information. This state persists across debug transport reconnections, allowing the web UI to reconnect without losing debug context. When the transport reconnects, the debugger re-sends its state to the target.

**Request Queue:**

Debug requests are queued and sent sequentially to the target. Each request waits for a reply before the next request is sent. This prevents race conditions and ensures commands are executed in order. The queue is implemented using promise chaining.

**Endianness Handling:**

Bytecode disassembly supports both little-endian and big-endian instruction encoding. The debugger detects the target's endianness during the initial handshake and adjusts decoding accordingly. This allows debugging of cross-compiled bytecode on different architectures.

**Source Code Caching:**

Source files retrieved from the debug target are cached in memory to avoid repeated requests. The cache stores normalized source (with consistent line endings) for efficient line-to-bytecode mapping. Cache entries are keyed by filename and remain valid for the duration of the debug session.

**Message Scrollback:**

Debug output messages are stored in a circular buffer with configurable size (default 100 lines). This prevents unbounded memory growth while maintaining sufficient history for debugging. When the buffer fills, the oldest messages are discarded.

**Statistics Tracking:**

The protocol parsers track detailed statistics including bytes transferred, message counts, and dvalue counts. Transfer rates (bytes per second) are calculated using periodic sampling. These statistics are useful for performance analysis and protocol debugging.

**WebSocket Integration:**

The debugger is designed to integrate with a WebSocket-based web UI. The `uiMessage()` method formats events for transmission to the web client. The debugger emits granular events for each state change, allowing the UI to update incrementally rather than polling for changes.

**Error Handling:**

Protocol errors (malformed messages, unexpected dvalues) are caught and logged without crashing the debugger. The debugger attempts to resynchronize by searching for the next message boundary (EOM marker). Transport errors trigger a clean disconnection and emit a 'transport-close' event.

**Performance Considerations:**

The protocol parser is optimized for throughput, processing multiple messages per `write()` call when possible. Buffer copying is minimized by using slices and views. The parser avoids string concatenation for binary data, working directly with Buffer objects.

## Summary

The duktape-debugger.js module is a **complete cross-platform debugger client** for the Duktape JavaScript engine, supporting all major operating systems (Windows, Linux, macOS, FreeBSD). It implements the full Duktape debug protocol, providing comprehensive debugging capabilities for embedded JavaScript applications.

**Key features:**
- Full breakpoint management (add, delete, enable, disable)
- Step debugging (over, into, out, resume, pause)
- Variable and expression inspection
- Call stack navigation and analysis
- Source code retrieval and caching
- Bytecode disassembly with instruction decoding
- Binary protocol implementation with dvalue encoding
- Statistics tracking and performance monitoring
- WebSocket-ready event-driven architecture
- Persistent state across transport reconnections
- Message logging with configurable scrollback
- Request queuing for reliable command execution

The module operates entirely at the protocol level, making it platform-independent and suitable for debugging JavaScript code in any environment where Duktape is deployed. Within MeshAgent, this debugger enables developers to troubleshoot embedded agent modules and scripts running in the Duktape engine, providing visibility into execution flow, variable state, and program logic.
