# heciRedirector.js

WebSocket-based network redirection layer for HECI (Host Embedded Controller Interface) services, enabling remote access to local Intel Management Engine services through HTTP upgrade tunnels. Provides both client and server implementations for HECI protocol tunneling over WebSocket.

## Platform

**Supported Platforms:**
- Windows - Full support (depends on heci.js)
- Linux - Full support (depends on heci.js)
- macOS - Not supported (depends on heci.js which requires MEI hardware)
- FreeBSD - Not supported

**Excluded Platforms:**
- macOS - Indirect dependency on heci.js which requires Intel MEI hardware
- Apple Silicon - No Intel Management Engine
- Non-Intel systems - Requires underlying heci.js module

**Placement in modules_macos_NEVER:**

This module is in `modules_macos_NEVER` because:

1. **Dependency Chain** - Depends entirely on heci.js module:
   - Line 149: `require('heci').create()` - Creates HECI session
   - Line 156, 160: Uses `require('heci').GUIDS.AMT/LME` - Service GUIDs
   - heci.js explicitly excluded from macOS (Intel MEI hardware required)
   - Cannot function without underlying HECI support

2. **Hardware Abstraction** - Acts as network bridge to hardware-dependent services:
   - Redirects network connections to local MEI services
   - HECI connection required on both client and server side
   - Network layer doesn't change hardware requirements

3. **Service Architecture** - Part of Intel AMT/LME management stack:
   - Extends AMT service accessibility over network
   - Redirects to PTHI or LME services (both Intel-specific)
   - Architecture assumes Intel Management Engine presence

4. **Use Case** - Enterprise remote management only:
   - Used to expose local HECI services via network
   - Not relevant for macOS consumer/business systems
   - Requires Intel vPro or equivalent (not on Macs)

**Technical Note:** While this module is platform-agnostic in its WebSocket implementation, it cannot function on macOS due to hard dependency on heci.js, which requires Intel Management Engine hardware.

## Functionality

### Core Purpose

Provides network redirection infrastructure for HECI services:
- **Server Mode (Lines 123-181)**: Listens for WebSocket connections and creates local HECI sessions
- **Client Mode (Lines 19-122)**: Connects via WebSocket to remote HECI redirection server
- **Bidirectional Tunneling**: Pipes data between network stream and local HECI device
- **Command Protocol**: JSON-based messaging for service selection and connection setup
- **Event Forwarding**: Propagates HECI events across network boundary

### Constructor and Module Export

**Module.exports - Line 184:**

```javascript
module.exports = new heciRedirector();
```

Exports singleton instance with two methods: redirect() and listen()

### Server Implementation: listen(options)

**Usage (Lines 123-181):**

```javascript
var heciRedir = require('heciRedirector');
heciRedir.listen({ port: 16992, host: '127.0.0.1' });
```

**Parameters:**
- options.port (number) - Port to listen on
- options.host (string) - Host to bind to

**Process Flow (Lines 126-181):**

1. **Server Creation (Line 126):**
   ```javascript
   this._server = require('http').createServer();
   ```
   Creates HTTP server for WebSocket upgrade

2. **Upgrade Handler (Lines 130-180):**
   Fired when HTTP Upgrade request received
   ```javascript
   this._server.on('upgrade', function onUpgrade(req, sck, head) { ... })
   ```

3. **WebSocket Establishment (Line 132):**
   ```javascript
   this.redirector.WS = sck.upgradeWebSocket();
   ```
   Converts socket to WebSocket protocol

4. **Command Processing (Lines 135-179):**
   Listens for JSON commands from client:
   - Parses JSON string chunks (Line 139)
   - Routes to command handlers (Line 140-176)

5. **Connect Command (Lines 147-167):**
   ```javascript
   case 'Connect':
       this.heci = require('heci').create();
       this.heci.WS = this;
       switch(cmd.Data.Service) {
           case 'AMT': this.heci.connect(require('heci').GUIDS.AMT, ...); break;
           case 'LME': this.heci.connect(require('heci').GUIDS.LME, ...); break;
       }
   ```

   **Process:**
   - Creates HECI session (Line 149)
   - Connects to specified service (AMT or LME) (Lines 156, 160)
   - Sets up error handler (Line 168)
   - Establishes bidirectional pipe (Line 173)

6. **Event Handling (Lines 169-175):**
   ```javascript
   this.heci.once('error', function onHeciError(e) { ... });
   this.heci.on('connect', function onHeciConnect() {
       this.WS.write(JSON.stringify({ Command: 'Event', Name: 'connect' }));
       this.pipe(this.WS).pipe(this, { end: false });
   });
   ```

   **Actions:**
   - Sends connect event to client (Line 172)
   - Establishes duplex pipe between HECI and WebSocket (Line 173)
   - Handles disconnect (Line 174)

### Client Implementation: redirect(options)

**Usage (Lines 19-122):**

```javascript
var heciRedir = require('heciRedirector');
heciRedir.redirect({
    protocol: 'ws:',
    method: 'GET',
    path: '/heciRedirect',
    host: 'remote-server',
    port: 16992
});
```

**Parameters:**
- options.protocol - 'ws:' or 'wss:' for WebSocket
- options.host - Remote server hostname
- options.port - Remote server port
- options.path - '/heciRedirect' path

**Module Registration (Lines 121-122, 26-120):**

Creates heciRedirect object and registers as module:
```javascript
addModuleObject('heci', heciRedirect);
```

**Client Object Structure (Lines 26-120):**

**create() Method (Lines 27-116):**

Creates redirected HECI session:
1. **Stream Creation (Lines 31-45):**
   Creates duplex stream for read/write
   ```javascript
   var retVal = new stream.Duplex({
       read: function() { ... },
       write: function(chunk, callback) { ... }
   });
   ```

2. **Write Handler (Lines 36-40):**
   Sends data through WebSocket:
   ```javascript
   this.request._WS.WriteDrains.push(callback);
   this.request._WS.write(chunk, function onWriteFlushed() {
       this.WriteDrains.shift().apply(this, []);
   });
   ```

3. **HTTP Request (Line 51):**
   ```javascript
   retVal.request = require('http').request(this.options);
   ```
   Creates HTTP client request for upgrade

4. **Upgrade Handler (Lines 58-95):**
   Processes WebSocket upgrade:
   ```javascript
   retVal.request.on('upgrade', function onclientUpgrade(resp, sck, head) {
       this._WS = sck;
       this._WS.WriteDrains = [];
       sck.on('data', function onClientRedirectData(chunk) { ... });
   });
   ```

5. **Data Reception (Lines 64-88):**
   Processes incoming data:
   ```javascript
   sck.on('data', function onClientRedirectData(chunk) {
       if (typeof chunk == 'string') {
           // JSON command/event
           var cmd = JSON.parse(chunk);
           switch(cmd.Command) {
               case 'Event':
                   this.redirector.emit(cmd.Name, cmd.Data);
                   break;
           }
       } else {
           // Binary HECI data
           if(!this.redirector.push(chunk)) this.pause();
       }
   });
   ```

6. **Connect Method (Lines 97-107):**
   ```javascript
   utils.addMethod('connect', function _connect(target, options) {
       var cmd = { Command: 'Connect', Data: { Service: target, Options: options } };
       if (!this._WS) { this.connectcmd = cmd; }
       else { this._WS.write(JSON.stringify(cmd)); }
   });
   ```

   **Behavior:**
   - Stores connect command if WebSocket not ready (Line 102)
   - Sends immediately if WebSocket ready (Line 105)
   - Queues command execution at startup (Lines 90-94)

7. **Disconnect Method (Lines 108-114):**
   ```javascript
   retVal.disconnect = function disconnect() {
       this.request._WS.end();
       delete this.request._WS;
       this.request._WS = null;
   };
   ```

### Command Protocol

**JSON Message Format:**

**Client → Server (Connect):**
```javascript
{
    Command: 'Connect',
    Data: {
        Service: 'AMT' | 'LME',
        Options: { noPipeline: 0, ... }
    }
}
```

**Server → Client (Events):**
```javascript
{
    Command: 'Event',
    Name: 'connect' | 'error',
    Data: <optional error message or null>
}
```

**Data Transfer:**
- Binary chunks sent as raw data (not JSON)
- String chunks parsed as JSON commands
- Alternating message types handled by type detection (Line 66, 137)

### GUID and Service Support

**Supported Services (Lines 118, 152-161):**

```javascript
GUIDS: { LME: 'LME', AMT: 'AMT' }
```

Mapped to actual GUIDs in heci.js:
- AMT: PTHI (Platform to Host Interface) service
- LME: LME (Local MEI) service

### Event Flow

**Server → Client Events:**
1. HECI 'connect' → JSON Event message (Line 172)
2. HECI 'error' → JSON Event message with error (Line 168)
3. HECI data → Binary data chunks (Line 152 piping)

**Client → Server Events:**
1. Client.on('connect') → Fired when server sends connect event
2. Client.on('error') → Fired when server sends error event

### Backpressure Handling

**Client Write (Lines 36-40):**
- Queues flush callbacks in WriteDrains array
- Calls shift() and applies on WebSocket drain

**Server Piping (Line 173):**
- Standard Node.js pipe with { end: false }
- Automatic backpressure handling
- Stream pauses on buffer overflow

## Dependencies

### Node.js Core Modules

#### stream (Line 30)

```javascript
var stream = require('stream');
var retVal = new stream.Duplex({ ... });
```

**Purpose:** Duplex stream base class for bidirectional I/O

**Methods:**
- Duplex constructor - Create read/write stream
- push() - Add data to readable side (client)
- write() - Write to writable side (client)

#### http (Line 51, 126)

```javascript
require('http').request(options)  // Client
require('http').createServer()     // Server
```

**Purpose:** HTTP server and client for WebSocket upgrade

**Client Methods (Line 51-96):**
- request(options) - Create HTTP client request
- on('upgrade', callback) - Handle HTTP Upgrade response
- end() - Close connection

**Server Methods (Line 126-181):**
- createServer() - Create HTTP server
- listen(options) - Start listening
- on('upgrade', callback) - Handle upgrade requests

### MeshAgent Module Dependencies

#### heci (Line 149, 156, 160)

```javascript
var heci = require('heci');
this.heci = heci.create();
this.heci.connect(heci.GUIDS.AMT | heci.GUIDS.LME, options);
```

**Purpose:** Local HECI device access (server-side only)

**Methods:**
- create() - Create HECI session
- GUIDS.AMT - AMT service GUID
- GUIDS.LME - LME service GUID

**Import Location:**
- Server: Line 149
- Not used on client (client connects to remote server)

#### events (Line 53)

```javascript
var utils = require('events').inherits(retVal);
```

**Purpose:** Event emitter support for client stream

**Methods:**
- inherits(obj) - Add EventEmitter methods to object
- createEvent(name) - Define custom event
- addMethod(name, func) - Add property method

### Dependency Chain

```
heciRedirector.js
├─── stream (Node.js core)
│    └─── Duplex stream base
├─── http (Node.js core)
│    ├─── Client request (for remote connection)
│    └─── Server (for listening)
├─── heci (MeshAgent modules, server-side only)
│    ├─── GUIDS (AMT/LME service identifiers)
│    └─── create() (device access)
└─── events (Node.js core)
     └─── EventEmitter functionality
```

### Platform Binary Dependencies

**Server-Side:**
- Underlying heci.js dependencies (SetupAPI.dll on Windows, /dev/mei on Linux)

**Client-Side:**
- Standard HTTP/WebSocket support (no special binary dependencies)

## Technical Notes

### WebSocket Upgrade Sequence

**Client:**
1. Creates HTTP request (Line 51)
2. Sets up upgrade handler (Line 58)
3. Calls request.end() (Line 115) to trigger upgrade
4. Socket converted to WebSocket on successful upgrade

**Server:**
1. Listens for HTTP Upgrade requests (Line 130)
2. Converts socket to WebSocket (Line 132)
3. Waits for Connect command
4. Creates HECI session and pipes streams

### JSON vs Binary Protocol

**Type Detection (Line 66, 137):**
```javascript
if (typeof chunk == 'string') {
    // JSON command/event
} else {
    // Binary HECI data
}
```

**Rationale:**
- JSON for control messages (commands, events)
- Binary for actual device data
- Differentiation by JavaScript type, not payload markers

### Bidirectional Piping

**Server (Line 173):**
```javascript
this.pipe(this.WS).pipe(this, { end: false });
```

**Result:**
- HECI reads → WebSocket writes (line 173 first pipe)
- WebSocket reads → HECI writes (line 173 second pipe)
- { end: false } prevents close propagation

### Queue Management

**Connect Command Queueing (Lines 90-94, 102):**
```javascript
if (!this._WS) { this.connectcmd = cmd; }
// Later, when WebSocket ready (Line 93):
this._WS.write(JSON.stringify(this.redirector.connectcmd));
```

**Use Case:** Handle case where connect() called before WebSocket established

### Error Propagation

**Server Error (Line 168):**
```javascript
this.heci.once('error', function onHeciError(e) {
    this.end(JSON.stringify({ Command: 'Event', Name: 'error', Data: e.toString() }));
});
```

**Flow:**
1. HECI connection error
2. Sent as JSON Event to client
3. WebSocket closed
4. Client receives error in stream

## Summary

The heciRedirector.js module extends local HECI service accessibility to remote clients via WebSocket tunnels, implementing both server-side and client-side redirection logic. The server listens for network connections, establishes local HECI sessions, and pipes data between WebSocket and device stream. The client connects remotely and presents a duplex stream interface to the redirected HECI service.

**Placed in modules_macos_NEVER** because:
- Hard dependency on heci.js module (lines 149-160)
- heci.js requires Intel Management Engine hardware
- Server-side functionality completely unavailable on macOS
- No MEI hardware means no services to redirect
- Architecture assumes Intel platform presence

**Core functionality:**
- Network access to local HECI services
- WebSocket-based tunneling protocol
- JSON command/event messaging with binary data passthrough
- Bidirectional stream piping
- Service selection (AMT or LME)

Used in distributed management scenarios where remote clients need access to local Intel AMT/LME services exposed through a network bridge.
