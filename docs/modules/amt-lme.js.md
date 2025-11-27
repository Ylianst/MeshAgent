# amt-lme.js

Intel AMT Local Manageability Engine (LME) implementation providing bidirectional port forwarding between the local operating system and Intel AMT firmware using the Application Protocol Framework (APF). Enables local applications to communicate with AMT-managed ports and receive AMT event notifications through HECI channels.

## Platform

**Supported Platforms:**
- Windows (x86/x64) - Full support via HECI device driver
- Linux (x86/x64) - Full support via `/dev/mei` or `/dev/mei0` character devices

**Excluded Platforms:**
- **macOS (darwin)** - Not supported

**Exclusion Reasoning:**

macOS hardware fundamentally lacks the required Intel AMT infrastructure:

1. **No Intel Management Engine** - Apple Mac computers do not include Intel's Management Engine (ME) firmware, which is a prerequisite for LME functionality. The ME is embedded in the chipset of Intel vPro-enabled business PCs but is absent from all Mac hardware.

2. **Missing HECI Interface** - LME requires the Host Embedded Controller Interface (HECI) to communicate with Intel's Management Engine. Line 128 (`var heci = require('heci')`) creates a HECI connection that will fail on macOS because:
   - No `/dev/mei*` devices exist on macOS
   - No Windows-style HECI device paths are available
   - The underlying `heci` module explicitly throws errors on non-Windows/Linux platforms

3. **APF Protocol Hardware Dependency** - The Application Protocol Framework (APF) defined in lines 24-39 is a firmware-level protocol implemented in Intel's Management Engine. This protocol operates below the OS layer and requires specific chipset hardware not present in Mac systems.

4. **LME GUID Hardware Binding** - Line 468 (`this._LME.connect(heci.GUIDS.LME, { noPipeline: 0 })`) attempts to connect to the LME subsystem using a hardware GUID that only exists on systems with Intel AMT-capable chipsets.

5. **Apple's Alternative Technologies** - Mac systems use Apple's proprietary system management architecture instead of Intel AMT/vPro technologies.

**Technical Evidence:**
- Line 128: `require('heci')` - Fails on macOS (see heci.js documentation)
- Line 468: Attempts connection to LME GUID (only exists on vPro hardware)
- Line 23: References Intel's APF documentation specific to AMT hardware

## Functionality

### Core Purpose

The LME module implements Intel AMT's Local Manageability Engine protocol, which enables:

1. **Local Port Forwarding** - Bidirectional TCP port redirection between host OS and AMT firmware
2. **AMT Event Notifications** - Receive WSMAN-formatted event notifications from AMT
3. **Network Socket Bridging** - Connect local TCP sockets to AMT-managed network ports
4. **Management Protocol Transport** - Provide communication channel for AMT management operations

### Application Protocol Framework (APF) - Lines 24-39

**Protocol Constants:**

The module implements Intel's APF as documented in the [Intel AMT Port Forwarding Protocol Reference Manual](https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/HTMLDocuments/MPSDocuments/Intel%20AMT%20Port%20Forwarding%20Protocol%20Reference%20Manual.pdf):

| Constant | Value | Purpose |
|----------|-------|---------|
| `APF_DISCONNECT` | 1 | Disconnect notification |
| `APF_SERVICE_REQUEST` | 5 | Service capability request |
| `APF_SERVICE_ACCEPT` | 6 | Service acceptance response |
| `APF_USERAUTH_REQUEST` | 50 | Authentication request |
| `APF_USERAUTH_FAILURE` | 51 | Authentication failure |
| `APF_USERAUTH_SUCCESS` | 52 | Authentication success |
| `APF_GLOBAL_REQUEST` | 80 | Global configuration request |
| `APF_REQUEST_SUCCESS` | 81 | Request successful |
| `APF_REQUEST_FAILURE` | 82 | Request failed |
| `APF_CHANNEL_OPEN` | 90 | Open new channel |
| `APF_CHANNEL_OPEN_CONFIRMATION` | 91 | Channel opened successfully |
| `APF_CHANNEL_OPEN_FAILURE` | 92 | Channel open failed |
| `APF_CHANNEL_WINDOW_ADJUST` | 93 | Flow control window adjustment |
| `APF_CHANNEL_DATA` | 94 | Channel data transfer |
| `APF_CHANNEL_CLOSE` | 97 | Close channel |
| `APF_PROTOCOLVERSION` | 192 | Protocol version negotiation |

---

### LME Channel Object - Lines 42-50

**Constructor:** `lme_object()`

**Purpose:** Represents a single LME channel with flow control and state tracking

**Properties:**
- `ourId` - Local channel identifier (auto-incremented from `lme_id`)
- `amtId` - AMT firmware's channel identifier
- `LME_CHANNEL_STATUS` - Channel state ('LME_CS_FREE', 'LME_CS_CONNECTED')
- `txWindow` - Transmit window size for flow control
- `rxWindow` - Receive window size for flow control
- `localPort` - Local TCP port number
- `errorCount` - Error counter for this channel

---

### Buffered Write Stream - Lines 52-111

**Constructor:** `stream_bufferedWrite()`

**Purpose:** Custom duplex stream with buffered writes for flow control

**Events:**
- Writable: `close`, `drain`, `error`, `finish`, `pipe`, `unpipe`
- Readable: `readable`

**Methods:**

#### isEmpty() - Line 67
Returns `true` if internal buffer is empty

#### isWaiting() - Line 70
Returns `true` if stream is waiting for read operations

#### write(chunk) - Line 73
Buffers data chunks for transmission
- **Parameters:** `chunk` - Buffer to write
- **Returns:** `true` if buffer is empty, `false` if backpressure needed
- **Behavior:** Copies chunk to internal buffer and emits `readable` event

#### read([size]) - Line 81
Reads data from internal buffer
- **Parameters:** `size` (optional) - Number of bytes to read
- **Returns:** Buffer containing requested data
- **Behavior:**
  - Reads up to `size` bytes or all available data
  - Handles partial buffer reads with offset tracking
  - Schedules immediate drain/readable event emission (lines 101-108)

---

### Main LME HECI Class - Lines 114-469

**Constructor:** `lme_heci(options)`

**Purpose:** Main interface for LME communication over HECI

**Parameters:**
- `options.debug` - If `true`, enables LMS debug mode (binds to ports 16892/16893)

**Events:**
- `error` - HECI communication errors
- `connect` - LME connection established and first port bound
- `notify` - AMT event notifications received
- `bind` - Port binding status updates

**Properties:**
- `INITIAL_RXWINDOW_SIZE` - 4096 bytes (line 129)
- `_LME` - HECI connection instance
- `_ObjectID` - "lme" identifier

---

### Connection Management

#### Constructor Initialization - Lines 114-138

**Process:**
1. Creates event emitters for error, connect, notify, bind
2. Implements `newListener` handler for late subscribers (lines 121-125)
3. Enables debug mode if requested (sets `lme_port_offset = -100`)
4. Creates HECI connection instance (line 132)
5. Sets metadata for debugging (`descriptorMetadata = "amt-lme"`)

#### HECI Connection - Lines 139-434

**Connection Event Handler - Lines 139-434:**

The `connect` event handler implements the complete APF protocol state machine:

**Protocol Version Negotiation - Lines 278-289:**
- Command: `APF_PROTOCOLVERSION` (192)
- Receives AMT's protocol version (major, minor, reason)
- Responds with version 1.0 confirmation
- Packet format: `[0xC0, major(4), minor(4), reason(4)]`

**Service Request Handling - Lines 152-166:**
- Command: `APF_SERVICE_REQUEST` (5)
- AMT requests services: `pfwd@amt.intel.com` or `auth@amt.intel.com`
- Responds with `APF_SERVICE_ACCEPT` (6) if service supported

**Global Request Processing - Lines 167-236:**

##### tcpip-forward - Lines 172-221
**Purpose:** Bind local TCP ports for AMT access
- Extracts port number from request
- Creates TCP server on requested port (or offset port in debug mode)
- Binds to `127.0.0.1` (normal) or `0.0.0.0` (debug mode)
- On successful bind:
  - Stores binding in `this._binded[port]`
  - Emits `bind` event with binding status
  - Emits first `connect` event (line 203-206)
- On connection: Calls `bindDuplexStream()` to establish LME channel
- Responds with `APF_REQUEST_SUCCESS` containing port number

##### cancel-tcpip-forward - Lines 222-226
**Purpose:** Remove TCP port forwarding
- Responds with `APF_REQUEST_SUCCESS`

##### udp-send-to@amt.intel.com - Lines 227-231
**Purpose:** UDP forwarding (not supported)
- Responds with `APF_REQUEST_FAILURE`

---

### Channel Management

#### Channel Open Confirmation - Lines 237-277

**Command:** `APF_CHANNEL_OPEN_CONFIRMATION` (91)

**Purpose:** AMT confirms channel is ready for data transfer

**Process:**
1. Extracts channel IDs and window size (lines 238-240)
2. Updates socket's LME object:
   - Sets `amtId` to AMT's channel ID
   - Sets `rxWindow` and `txWindow` to AMT's window size
   - Changes status to `LME_CS_CONNECTED`
3. Creates buffered stream for flow-controlled writes (line 248)
4. Sets up stream event handlers:
   - `readable` - Transmits data respecting `txWindow` (lines 250-261)
   - `drain` - Resumes socket reading (lines 262-264)
   - Socket `data` - Writes to buffered stream with backpressure (lines 265-267)
   - Socket `end` - Sends `APF_CHANNEL_CLOSE` to AMT (lines 268-273)
5. Resumes socket data flow (line 274)

**Flow Control:**
- Reads up to `txWindow` bytes from buffered stream
- Sends `APF_CHANNEL_DATA` packet with data
- Decrements `txWindow` by bytes sent
- Waits for `APF_CHANNEL_WINDOW_ADJUST` to replenish window

#### Channel Window Adjust - Lines 290-301

**Command:** `APF_CHANNEL_WINDOW_ADJUST` (93)

**Purpose:** AMT increases transmit window (flow control)

**Process:**
1. Identifies channel by recipient ID
2. Adds bytes to channel's `txWindow`
3. Triggers buffered stream read if data pending and stream waiting

#### Channel Data Receive - Lines 302-350

**Command:** `APF_CHANNEL_DATA` (94)

**Purpose:** Receive data from AMT on channel

**Two Channel Types:**

##### Outbound Channels (Local → AMT) - Lines 306-316
**Usage:** Data from AMT to local socket
- Queues pending byte count for flow control
- Writes data to local socket
- On write completion: Sends `APF_CHANNEL_WINDOW_ADJUST` back to AMT

##### Inbound Channels (AMT → Local) - Lines 317-346
**Usage:** AMT event notifications
- Accumulates HTTP/WSMAN data in `channel.data`
- Parses HTTP when complete (line 322)
- Extracts WSMAN event using `amt-xml` parser (line 326)
- Emits `notify` event with parsed WSMAN data (line 329)
- Sends `APF_CHANNEL_CLOSE` after processing
- Implements periodic window adjustments (lines 337-345)

#### Channel Open Failure - Lines 351-362

**Command:** `APF_CHANNEL_OPEN_FAILURE` (92)

**Purpose:** AMT rejected channel open request

**Process:**
1. Identifies channel by recipient ID
2. Closes and removes socket from `sockets` or `insockets`

#### Channel Close - Lines 363-380

**Command:** `APF_CHANNEL_CLOSE` (97)

**Purpose:** AMT is closing channel

**Process:**
1. Ends local socket
2. Removes from tracking
3. Sends `APF_CHANNEL_CLOSE` confirmation back to AMT

#### Channel Open Request - Lines 381-423

**Command:** `APF_CHANNEL_OPEN` (90)

**Purpose:** AMT requests to open channel to local system

**Process:**
1. Parses channel parameters:
   - Channel type (e.g., "forwarded-tcpip")
   - Channel sender ID
   - Initial window size
   - Target host and port
   - Originator IP and port
2. Creates inbound socket object in `this.insockets`
3. Sends `APF_CHANNEL_OPEN_CONFIRMATION` with:
   - AMT's sender channel ID
   - Our receiver channel ID
   - Initial window size: 4000 bytes
   - Reserved field: 0xFFFFFFFF

**Use Case:** AMT sending events/notifications to local system

---

### Public Methods

#### bindDuplexStream(duplexStream, remoteFamily, localPort) - Lines 436-466

**Purpose:** Bind a local TCP socket to an AMT channel

**Parameters:**
- `duplexStream` - TCP socket or duplex stream
- `remoteFamily` - 'IPv4' or 'IPv6'
- `localPort` - Local port number

**Process:**
1. Initializes socket properties (lines 437-444)
2. Creates LME object for channel tracking
3. Builds `APF_CHANNEL_OPEN` packet (lines 445-461):
   - Command byte: 0x5A (90)
   - Channel type: "forwarded-tcpip"
   - Channel ID and window size
   - Source and destination addresses (IPv4 or IPv6)
4. Sends packet to AMT via HECI
5. Registers socket in `this._LME.sockets` array
6. Pauses socket until AMT confirms channel open

**Buffer Format:**
```
Byte 0: 0x5A (APF_CHANNEL_OPEN)
Bytes 1-4: String length (15)
Bytes 5-19: "forwarded-tcpip"
Bytes 20-23: Our channel ID
Bytes 24-27: Initial RX window (4096)
Bytes 28-31: 0xFFFFFFFF
[Repeated 2x:]
  Bytes: IP length + IP string
  Bytes: Port (4 bytes)
```

---

### Helper Functions

#### parseHttp(httpData) - Lines 471-478

**Purpose:** Extract HTTP body from complete HTTP response

**Parameters:**
- `httpData` - String containing HTTP response

**Returns:** HTTP body content or `null` if incomplete

**Process:**
1. Finds `\r\n\r\n` header separator
2. Parses headers using `http-headers` module
3. Extracts `Content-Length` header
4. Returns body only if all bytes received

#### _lmsNotifyToCode(notify) - Lines 480-485

**Purpose:** Convert WSMAN notification to event code

**Parameters:**
- `notify` - Parsed WSMAN notification object

**Returns:** Event code string (MessageID + first argument) or `null`

**Example:** `"MessageID-Argument1"`

---

## Dependencies

### JavaScript Module Dependencies

#### require('MemoryStream') - Line 17
**Type:** JavaScript module
**Purpose:** Efficient binary buffer building for APF packets
**Usage:** Building channel open packets (line 445)

#### require('events').inherits() - Lines 53, 115
**Type:** Core Node.js module
**Purpose:** Event emitter functionality
**Usage:** Creating `error`, `connect`, `notify`, `bind` events

#### require('heci') - Line 128
**Type:** Binary native module
**Purpose:** HECI/MEI hardware interface
**Platform:** Windows/Linux only
**macOS Status:** Not available - fails module load
**Usage:**
- Creating HECI connection (line 132)
- Connecting to LME GUID (line 468)

#### require('amt-xml') - Line 21
**Type:** JavaScript module (optional)
**Purpose:** Parse WSMAN XML event notifications
**Usage:** Converting AMT events to JavaScript objects (line 326)
**Graceful Degradation:** Module continues without XML parsing if unavailable

#### require('net') - Line 188
**Type:** Core Node.js module
**Purpose:** TCP server and socket creation
**Usage:** Creating TCP servers for port forwarding

#### require('http-headers') - Line 474
**Type:** JavaScript module
**Purpose:** HTTP header parsing
**Usage:** Extracting Content-Length from AMT event notifications

---

## Binary Dependencies

### HECI/MEI Driver

**Windows:**
- Driver: Intel MEI/AMT driver
- Device Path: `\\.\HECI` or similar
- Requirement: Intel Management Engine Interface driver installed

**Linux:**
- Device: `/dev/mei` or `/dev/mei0`
- Requirement: `mei_me` kernel module loaded
- Permissions: Read/write access to MEI device node

**macOS:**
- **Not Available** - No HECI hardware or drivers exist

---

## Relationship to Other AMT Modules

### Direct Dependencies

1. **heci** - Low-level HECI hardware interface
   - LME uses HECI to communicate with Management Engine
   - Connection established via `heci.GUIDS.LME` (line 468)

2. **amt-xml** - WSMAN event parsing
   - Parses AMT event notifications received on inbound channels
   - Optional dependency for event processing

### Integration with AMT Stack

**LME's Role in AMT Architecture:**

```
┌─────────────────────────────────────────┐
│         Local Application               │
└──────────────┬──────────────────────────┘
               │ TCP Socket
┌──────────────▼──────────────────────────┐
│         amt-lme.js (This Module)        │
│  - Port forwarding                      │
│  - Event notification                   │
└──────────────┬──────────────────────────┘
               │ APF Protocol
┌──────────────▼──────────────────────────┐
│         heci (Binary Module)            │
│  - HECI/MEI driver interface            │
└──────────────┬──────────────────────────┘
               │ Hardware Interface
┌──────────────▼──────────────────────────┐
│   Intel Management Engine (Hardware)    │
│  - LME firmware subsystem               │
│  - Network port management              │
└─────────────────────────────────────────┘
```

**Complementary Modules:**

1. **amt-mei.js (amt_heci.js)** - PTHI (Platform Transaction Host Interface)
   - Different HECI GUID: `heci.GUIDS.AMT` vs `heci.GUIDS.LME`
   - Purpose: AMT provisioning and management commands
   - LME Purpose: Port forwarding and event transport

2. **amt-wsman.js** - Remote WSMAN over HTTP/HTTPS
   - LME provides local transport for WSMAN events
   - amt-wsman provides network transport for WSMAN operations
   - LME parses WSMAN notifications using `amt-xml`

3. **amt.js** - High-level AMT management
   - May use LME for local event subscriptions
   - Complements remote management with local notifications

---

## Hardware Requirements

### Required Hardware Components

1. **Intel vPro Chipset**
   - Must include Intel Active Management Technology (AMT)
   - Business-class Intel chipsets only (consumer chipsets lack AMT)

2. **Intel Management Engine (ME)**
   - Firmware subsystem embedded in chipset
   - Contains LME (Local Manageability Engine) firmware
   - Provides APF protocol implementation

3. **HECI/MEI Interface**
   - Hardware communication channel between CPU and ME
   - Exposed as device to operating system
   - Required for all local AMT communication

4. **LME-Capable AMT Firmware**
   - AMT version 6.0 or later recommended
   - LME subsystem must be enabled in firmware
   - Provisioned AMT required for full functionality

### Hardware Detection

The module does not explicitly check for hardware capabilities. Detection occurs implicitly through:

1. **HECI Module Load** - `require('heci')` fails if no HECI hardware/driver
2. **HECI Connection** - `connect(GUIDS.LME)` fails if ME not present
3. **APF Protocol** - First port binding validates LME firmware is operational

---

## Debug Mode

### LMS Debug Mode - Line 19, 126, 191-194

**Activation:** Pass `{ debug: true }` to constructor

**Behavior Changes:**
- `lme_port_offset = -100`
- TCP servers bind to:
  - Port 16992 instead of 16992 (offset: 16992 - 100)
  - Port 16993 instead of 16993 (offset: 16993 - 100)
  - Binds to `0.0.0.0` (all interfaces) instead of `127.0.0.1`

**Purpose:** Test LME functionality with Intel's LMS (Local Manageability Service) running

**Use Case:** Development and debugging when LMS is already using standard ports

---

## Usage Example

```javascript
var lme = require('amt-lme');

// Create LME connection
var lmeConnection = new lme();

// Handle connection established
lmeConnection.on('connect', function() {
    console.log('LME connected to Intel AMT');
});

// Handle port bindings
lmeConnection.on('bind', function(bindings) {
    console.log('Bound ports:', bindings);
    // bindings = { 16992: true, 16993: true }
});

// Handle AMT event notifications
lmeConnection.on('notify', function(wsmanEvent, options, eventCode) {
    console.log('AMT Event:', eventCode);
    console.log('From:', options.source + ':' + options.sourcePort);
    console.log('WSMAN Data:', wsmanEvent);
});

// Handle errors
lmeConnection.on('error', function(err) {
    console.error('LME Error:', err);
});

// Bind custom duplex stream
var net = require('net');
var socket = new net.Socket();
socket.connect(80, 'example.com', function() {
    lmeConnection.bindDuplexStream(socket, 'IPv4', 16992);
});
```

---

## Port Forwarding Architecture

### Standard AMT Ports

**Port 16992 (0x4290):**
- Used for AMT management communication
- HTTP-based WSMAN transport
- Typically forwarded by LME for local access

**Port 16993 (0x4291):**
- Secure HTTPS WSMAN transport
- TLS-encrypted AMT communication
- Requires valid AMT certificates

### Flow Control Mechanism

LME implements sophisticated flow control to prevent buffer overflow:

1. **Window-Based Flow Control:**
   - Each channel has `txWindow` and `rxWindow`
   - Initial window: 4096 bytes (INITIAL_RXWINDOW_SIZE)
   - Data transmission limited by available window

2. **Window Adjustment Protocol:**
   - Receiver sends `APF_CHANNEL_WINDOW_ADJUST` after consuming data
   - Increases sender's transmit window
   - Prevents memory exhaustion in firmware or application

3. **Backpressure Handling:**
   - Buffered stream pauses socket reading when buffer full
   - Resumes when buffer drains
   - Prevents data loss and memory pressure

---

## Security Considerations

1. **Localhost Binding** - Normal mode binds to `127.0.0.1` only (line 192)
   - Prevents network exposure of AMT ports
   - Local applications only

2. **Debug Mode Risk** - Debug mode binds to `0.0.0.0` (line 194)
   - Exposes AMT ports to network
   - Should only be used in trusted environments

3. **No Authentication** - APF protocol layer has no built-in authentication
   - Security relies on AMT firmware authentication
   - Local access implies physical/system access

4. **Event Notification Security** - WSMAN events may contain sensitive data
   - Applications should validate event sources
   - Sanitize event data before logging/display

---

## Known Limitations

1. **Single LME Connection** - AMT 7.x and earlier only support one LME connection
   - Line 427-431: Changed behavior to wait for first bind before emitting connect
   - Newer AMT versions allow multiple connections but first must bind successfully

2. **UDP Not Supported** - `udp-send-to@amt.intel.com` returns failure (lines 227-231)

3. **IPv6 Support Limited** - Handles IPv6 addresses but firmware support varies

4. **Error Recovery** - Limited retry logic for channel failures
   - Application must handle reconnection

5. **WSMAN Parsing Optional** - If `amt-xml` unavailable, events not parsed
   - Graceful degradation but reduced functionality
