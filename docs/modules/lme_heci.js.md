# lme_heci.js

Local MEI (Management Engine Interface) protocol implementation providing APF (Intel Authentication and Protocol Framework) tunneling over HECI. Implements port forwarding, channel management, and window-based flow control for TCP/IP redirection through Intel Management Engine.

## Platform

**Supported Platforms:**
- Windows - Full support (via heci.js)
- Linux - Full support (via heci.js)
- macOS - Not supported (requires heci.js with Intel MEI)
- FreeBSD - Not supported

**Excluded Platforms:**
- macOS - Indirect dependency on Intel MEI hardware via heci.js
- Apple Silicon - No Intel Management Engine
- Non-Intel systems - Requires MEI driver and hardware

**Placement in modules_macos_NEVER:**

This module is in `modules_macos_NEVER` because:

1. **Hardware Dependency Chain** - Depends on heci.js which requires MEI hardware:
   - Line 121: `var heci = require('heci')` - Loads heci.js module
   - Line 124: `this._LME = heci.create()` - Creates HECI session
   - Line 352: `this._LME.connect(heci.GUIDS.LME, ...)` - Connects to LME service GUID
   - heci.js explicitly excluded from macOS
   - Cannot function without underlying MEI hardware

2. **Protocol Architecture** - Implements Intel AMT Local MEI protocol:
   - APF (Authentication and Protocol Framework) is Intel proprietary
   - Designed specifically for Intel Management Engine
   - Port forwarding through MEI requires Intel hardware
   - Not applicable to non-Intel architectures

3. **Use Case** - Intel AMT remote management only:
   - Provides TCP/IP tunneling through Management Engine
   - Enables remote access to local services via port forwarding
   - Enterprise management feature (not for macOS)
   - Requires Intel vPro or equivalent (absent on Macs)

4. **Framework Dependencies** - Part of Intel AMT stack:
   - Works with amt-mei.js and related modules
   - All downstream modules also Intel-specific
   - Complete architecture designed for Windows/Linux management scenarios

**Technical Note:** While protocol implementation is platform-agnostic, module cannot initialize on macOS due to hard dependency on heci.js with MEI hardware requirement.

## Functionality

### Core Purpose

Implements LME (Local Management Engine) protocol over HECI for port forwarding and channel management:
- Establishes HECI connection to LME service
- Implements APF (Authentication and Protocol Framework) protocol
- Manages bidirectional TCP/IP channels through Management Engine
- Implements flow control with transmit/receive windows
- Handles service requests, global requests, and channel operations
- Provides socket-like interface to remote clients

### Constructor: lme_heci()

**Usage:**
```javascript
var lme_heci = require('lme_heci');
var lms = new lme_heci();
```

**Events:**
- `'error'` - Connection error (Line 118)
- `'connect'` - Connected to LME service (Line 119)

**Initialization (Lines 115-352):**
1. Creates event emitter (Line 117)
2. Creates HECI session (Line 124)
3. Sets initial RX window size (Line 122)
4. Connects to LME service GUID (Line 352)
5. Registers data handler for APF commands (Line 131)

### APF Protocol Implementation

APF command codes (Lines 6-21):
```javascript
APF_DISCONNECT = 1
APF_SERVICE_REQUEST = 5
APF_SERVICE_ACCEPT = 6
APF_USERAUTH_REQUEST = 50
APF_USERAUTH_FAILURE = 51
APF_USERAUTH_SUCCESS = 52
APF_GLOBAL_REQUEST = 80
APF_REQUEST_SUCCESS = 81
APF_REQUEST_FAILURE = 82
APF_CHANNEL_OPEN = 90
APF_CHANNEL_OPEN_CONFIRMATION = 91
APF_CHANNEL_OPEN_FAILURE = 92
APF_CHANNEL_WINDOW_ADJUST = 93
APF_CHANNEL_DATA = 94
APF_CHANNEL_CLOSE = 97
APF_PROTOCOLVERSION = 192
```

### Service Request Handler (Lines 142-159)

**Command:** APF_SERVICE_REQUEST (value 5)

Handles service connection requests:
1. Parses service name (Lines 143-144)
2. Checks for supported services:
   - 'pfwd@amt.intel.com' - Port forward service
   - 'auth@amt.intel.com' - Authentication service
3. Responds with APF_SERVICE_ACCEPT (value 6) (Lines 148-152)

**Response Format (Lines 148-151):**
```javascript
outBuffer = Buffer.alloc(5 + nameLen);
outBuffer.writeUInt8(6, 0);              // APF_SERVICE_ACCEPT
outBuffer.writeUInt32BE(nameLen, 1);    // Service name length
outBuffer.write(name.toString(), 5);    // Service name
```

### Global Request Handler (Lines 160-195)

**Command:** APF_GLOBAL_REQUEST (value 80)

Handles global service requests:

**tcpip-forward (Lines 166-185):**

Establishes port forwarding on specified port:
1. Parses port number (Lines 167-168)
2. Creates TCP server on localhost (Line 174)
   ```javascript
   this[name][port] = require('net').createServer();
   this[name][port].listen({ port: port, host: "127.0.0.1" });
   ```
3. Binds connection handler (Lines 177-181):
   - Accepts incoming TCP connections
   - Calls bindDuplexStream for each connection (Line 180)
4. Responds with port number (Lines 182-184)

**Response Format:**
```javascript
outBuffer = Buffer.alloc(5);
outBuffer.writeUInt8(81, 0);              // APF_REQUEST_SUCCESS
outBuffer.writeUInt32BE(port, 1);        // Port number
```

**cancel-tcpip-forward (Line 187):** Stub implementation

**udp-send-to@amt.intel.com (Line 189):** Stub implementation

### Channel Open Confirmation Handler (Lines 196-240)

**Command:** APF_CHANNEL_OPEN_CONFIRMATION (value 91)

Processes successful remote channel open:
1. Parses channel IDs and window size (Lines 197-199)
2. Creates lme_object for channel (Line 322)
3. Creates buffered stream wrapper (Line 208)
4. Sets up readable handler (Lines 210-223):
   - Monitors transmit window (Line 212)
   - Sends APF_CHANNEL_DATA packets (Lines 215-221)
   - Handles window exhaustion

5. Sets up drain handler (Lines 224-227):
   - Resumes socket on buffer drain
6. Pipes socket data (Lines 228-231):
   - Queues pending bytes
   - Buffers data if window exceeded
7. Sets up end handler (Lines 232-238):
   - Sends APF_CHANNEL_CLOSE on socket end
   - Sends remaining channel ID

### Protocol Version Handler (Lines 243-254)

**Command:** APF_PROTOCOLVERSION (value 192)

Responds with protocol version information:
```javascript
outBuffer = Buffer.alloc(93);
outBuffer.writeUInt8(192, 0);              // APF_PROTOCOLVERSION
outBuffer.writeUInt32BE(1, 1);            // Major version
outBuffer.writeUInt32BE(0, 5);            // Minor version
outBuffer.writeUInt32BE(reason, 9);       // Reason code
```

### Channel Window Adjust Handler (Lines 255-270)

**Command:** APF_CHANNEL_WINDOW_ADJUST (value 93)

Updates transmit window for data flow:
1. Parses channel ID and bytes to add (Lines 256-257)
2. Increases txWindow (Line 260)
3. Triggers readable event if data buffered (Lines 261-263)

### Channel Data Handler (Lines 271-292)

**Command:** APF_CHANNEL_DATA (value 94)

Receives data from remote channel:
1. Parses channel ID and data length (Lines 272-273)
2. Extracts payload (Line 274)
3. Writes to socket (Lines 277-286)
4. Queues window adjustment response (Line 281)

**Response Format:**
```javascript
outBuffer = Buffer.alloc(9);
outBuffer.writeUInt8(93, 0);              // APF_CHANNEL_WINDOW_ADJUST
outBuffer.writeUInt32BE(channelId, 1);   // Remote channel ID
outBuffer.writeUInt32BE(bytesRead, 5);   // Bytes consumed
```

### Channel Close Handler (Lines 293-310)

**Command:** APF_CHANNEL_CLOSE (value 97)

Closes remote channel:
1. Ends local socket (Line 297)
2. Retrieves remote channel ID (Line 298)
3. Sends APF_CHANNEL_CLOSE response (Lines 299-304)
4. Cleans up channel reference (Line 300)

### Duplex Stream Binding

**bindDuplexStream(duplexStream, remoteFamily, localPort) - Lines 315-350**

Converts TCP socket to channel-based duplex stream:
1. Creates lme_object (Line 322)
2. Creates MemoryStream buffer (Line 324)
3. Writes APF_CHANNEL_OPEN packet (Lines 325-345):
   ```javascript
   buffer.writeUInt8(0x5A);               // APF_CHANNEL_OPEN
   buffer.writeUInt32BE(15);              // Service name length
   buffer.write('forwarded-tcpip');       // Service name
   buffer.writeUInt32BE(socket.lme.ourId);// Channel ID
   buffer.writeUInt32BE(INITIAL_RXWINDOW_SIZE);  // Initial RX window
   buffer.writeUInt32BE(0xFFFFFFFF);      // Maximum packet size
   ```
   - Repeats origin address/port twice (Lines 331-345)

4. Sends CHANNEL_OPEN to remote (Line 346)
5. Registers socket in sockets map (Line 348)
6. Pauses socket pending confirmation (Line 349)

**Response Flow:**
1. Remote receives CHANNEL_OPEN
2. Remote sends CHANNEL_OPEN_CONFIRMATION
3. Handler calls bindDuplexStream completion
4. Socket resumed and ready for data

### Flow Control

**Transmit Window (txWindow):**
- Initialized from remote confirmation (Line 205)
- Decreased on data send (Line 220)
- Increased on window adjust (Line 260)
- Blocks sends when zero (Line 212)

**Receive Window (rxWindow):**
- Initialized to INITIAL_RXWINDOW_SIZE (Line 329)
- Adjusted by remote window adjust commands
- Not explicitly managed (assumed large)

**Initial RX Window (Line 122):**
```javascript
this.INITIAL_RXWINDOW_SIZE = 4096;
```

Default 4KB receive window for each channel.

### Stream Buffering

**stream_bufferedWrite (Lines 35-112):**

Custom buffered stream for queuing:
- Accumulates writes in buffer array
- Implements read(size) to extract chunks
- Emits 'readable' when data available
- Emits 'drain' when buffer emptied
- Handles partial reads with offset tracking (Lines 78-93)

**Methods:**
- isEmpty() - Check if buffer empty (Line 51)
- isWaiting() - Check if read pending (Line 55)
- write(chunk) - Queue data (Line 59)
- read(size) - Extract up to size bytes (Line 71)

### lme_object Structure

**Properties (Lines 24-32):**
- ourId - Unique channel ID (incrementing)
- amtId - Remote channel ID (from confirmation)
- LME_CHANNEL_STATUS - Connection state
- txWindow - Bytes can send before window adjust
- rxWindow - Bytes can receive (not actively used)
- localPort - TCP server port for this channel

### Error Handling

**HECI Error (Line 126):**
```javascript
this._LME.on('error', function (e) { this.LMS.emit('error', e); });
```

Propagates HECI errors to LMS consumers.

**Socket End (Lines 232-238):**
```javascript
socket.on('end', function () {
    var outBuffer = Buffer.alloc(5);
    outBuffer.writeUInt8(APF_CHANNEL_CLOSE, 0);
    outBuffer.writeUInt32BE(this.lme.amtId, 1);
    this.HECI.write(outBuffer);
});
```

## Dependencies

### Node.js Core Modules

#### events (Line 117)

```javascript
var emitterUtils = require('events').inherits(this);
emitterUtils.createEvent('error');
emitterUtils.createEvent('connect');
```

**Purpose:** Event emitter support

**Methods:**
- inherits(obj) - Add EventEmitter functionality
- createEvent(name) - Define custom event

#### net (Line 174)

```javascript
this[name][port] = require('net').createServer();
this[name][port].listen({ port: port, host: "127.0.0.1" });
this[name][port].on('connection', function (socket) { ... });
```

**Purpose:** TCP server for port forwarding

**Methods:**
- createServer() - Create TCP server
- listen(options) - Start listening
- on('connection', callback) - Accept connections

#### stream (Line 58)

```javascript
var duplex = require('stream').Duplex;
```

**Purpose:** Not directly used; inherited through events

### MeshAgent Module Dependencies

#### heci (Line 121)

```javascript
var heci = require('heci');
this._LME = heci.create();
this._LME.connect(heci.GUIDS.LME, { noPipeline: 0 });
```

**Purpose:** Low-level HECI device access

**Methods/Properties:**
- create() - Create HECI session
- GUIDS.LME - LME service GUID Buffer
- connect(guid, options) - Connect to service
- write(buffer) - Send data to service
- on('data', callback) - Receive data
- on('connect', callback) - Connection established
- on('error', callback) - Connection error

**Import:** Line 121

#### MemoryStream (Line 2)

```javascript
var MemoryStream = require('MemoryStream');
var buffer = new MemoryStream();
buffer.writeUInt8(value);
buffer.writeUInt32BE(value);
buffer.write(string);
buffer.buffer;
```

**Purpose:** Constructs APF protocol packets

**Methods:**
- writeUInt8(value) - Write 1-byte integer
- writeUInt32BE(value) - Write 4-byte big-endian integer
- write(string) - Write string bytes
- buffer - Get accumulated bytes as Buffer

**Import:** Line 2, Line 324

### Dependency Chain

```
lme_heci.js
├─── heci (Line 121)
│    ├─── GUIDS.LME (Line 352)
│    └─── create() / connect() (Lines 124, 352)
├─── events (Line 117)
│    └─── EventEmitter functionality
├─── net (Line 174)
│    └─── TCP server for port forwarding
├─── MemoryStream (Line 2)
│    └─── APF packet construction
└─── stream (inherited)
     └─── Duplex stream support
```

### Platform Binary Dependencies

**Inherited from heci.js:**
- **Windows:** SetupAPI.dll, Kernel32.dll, MEI driver
- **Linux:** /dev/mei device, Linux kernel MEI driver

**Network Dependencies:**
- TCP/IP stack for port forwarding
- localhost (127.0.0.1) loopback interface

## Technical Notes

### APF Protocol Overview

APF (Authentication and Protocol Framework) is Intel's embedded protocol for Management Engine communication:
- Message-oriented (not stream-based)
- Variable-length packets with type code in first byte
- Binary format with integer fields

### Channel ID Management

**ourId (Line 326):**
- Assigned by LMS (this side)
- Incremented for each new channel
- Sent in CHANNEL_OPEN to remote
- Returned in CHANNEL_OPEN_CONFIRMATION as rChannel

**amtId (Line 203):**
- Assigned by remote (AMT/LME)
- Received in CHANNEL_OPEN_CONFIRMATION
- Used in subsequent CHANNEL_DATA/CLOSE messages

### Window-Based Flow Control

**Transmit Window (txWindow):**
- Limits bytes that can be sent
- Decremented when data sent
- Incremented by CHANNEL_WINDOW_ADJUST
- Prevents buffer overflow on remote side

**Receive Window (rxWindow):**
- Theoretical limit on bytes can receive
- Set to INITIAL_RXWINDOW_SIZE (4096) at connect
- Not actively managed (remote sends WINDOW_ADJUST)
- Would need WINDOW_ADJUST response if exhausted (not implemented)

### Port Forwarding Mechanism

**Sequence:**
1. Client requests tcpip-forward on port (GLOBAL_REQUEST)
2. LMS creates TCP server on localhost:port
3. External client connects to localhost:port
4. LMS receives connection in connection handler (Line 177)
5. Calls bindDuplexStream with TCP socket
6. Sends CHANNEL_OPEN to remote AMT/LME
7. Remote accepts with CHANNEL_OPEN_CONFIRMATION
8. Data piped between TCP socket and remote channel

### Service Name Convention

Service names follow Intel AMT conventions:
- 'pfwd@amt.intel.com' - Port forward service
- 'auth@amt.intel.com' - Authentication service
- Format: <service>@<domain>

## Summary

The lme_heci.js module implements APF protocol handling over Intel HECI, providing TCP/IP port forwarding through the Management Engine. It manages channel-based communication with window-based flow control, handles service and global requests, and bridges TCP sockets to remote channels via the LME service.

**Placed in modules_macos_NEVER** because:
- Hard dependency on heci.js (line 121)
- heci.js requires Intel Management Engine hardware
- APF protocol designed exclusively for Intel MEI
- Port forwarding only relevant on Intel management systems
- macOS has no MEI hardware for tunneling

**Core functionality:**
- APF protocol implementation and command dispatch
- TCP server creation for port forwarding
- Channel-based duplex stream management
- Window-based flow control for data transfer
- HECI bridge between TCP clients and remote Management Engine

Used for Intel AMT local management scenarios where remote services need to be accessed through Management Engine port forwarding tunnels.
