# heci.js

Host Embedded Controller Interface (HECI) communication layer providing duplex stream access to Intel Management Engine (MEI/AMT) services. Implements cross-platform abstraction for low-level hardware device I/O on Windows and Linux systems with support for asynchronous I/O and overlapped operations.

## Platform

**Supported Platforms:**
- Windows - Full support with SetupAPI and overlapped I/O
- Linux - Full support with /dev/mei device interface
- macOS - Not supported (no Intel MEI hardware)
- FreeBSD - Not supported

**Excluded Platforms:**
- macOS - No Intel Management Engine Interface hardware
- Apple Silicon Macs - No MEI support
- Non-Intel systems - Requires MEI driver

**Placement in modules_macos_NEVER:**

This module is in `modules_macos_NEVER` because:

1. **Hardware Dependency** - HECI requires Intel Management Engine (MEI) hardware interface, which is:
   - Found on Intel-based Windows and Linux systems with Management Engine
   - Completely absent from macOS systems (both Intel and Apple Silicon)
   - Not part of Apple's hardware architecture

2. **Platform-Specific Implementation** - The module contains explicit platform checks:
   - Line 23-40: Windows platform initialization using SetupAPI
   - Line 91-95: Linux platform I/O using /dev/mei device
   - Line 219: Explicit rejection of non-Windows/Linux platforms
   - Lines 213-218: Linux-only descriptorPath validation

3. **Driver Requirements** - Windows MEI driver dependencies:
   - SetupAPI.dll kernel-level driver enumeration
   - Overlapped I/O mechanism specific to Windows
   - Device enumeration GUIDs (Lines 225, 587)
   - Not available on macOS

4. **Lower-level Hardware Access** - Part of Intel AMT stack:
   - HECI is foundation layer for PTHI (Platform to Host Interface)
   - Required by amt-mei.js, lme_heci.js, and other AMT modules
   - These higher-level modules are also excluded from macOS

**Technical Note:** The module is platform-specific and cannot function on macOS due to hardware and driver requirements. The absence of MEI hardware on all macOS systems makes this exclusion permanent and architectural.

## Functionality

### Core Purpose

Provides a duplex stream interface to Intel Management Engine services (AMT, LME) through Host Embedded Controller Interface (HECI). Handles:
- Device discovery and enumeration
- File handle creation and overlapped I/O operations
- Read/write operations with queueing and flow control
- IOCTL command execution for service connection
- Asynchronous event-driven architecture
- Cross-platform abstractions for Windows and Linux

### Stream Interface

**Duplex Stream (Lines 58-166):**

The module returns a duplex stream that implements both readable and writable sides:
- Inherits from Node.js Stream.Duplex
- Buffered write operations with flush support
- Descriptor-based event monitoring
- Automatic queue management

### Constructor: heci_create()

**Usage:**
```javascript
var heci = require('heci');
var session = heci.create();
```

**Return Value:**
- Returns duplex stream object with event emitters
- Properties: bufferMode, _ioctls, _pendingWrites, MaxBufferSize
- Methods: connect(), descriptorPath(), createDescriptor(), disconnect(), doIoctl()

### Key Methods

**connect(guid, options) - Lines 176-210**

Initiates connection to HECI service using service GUID:
```javascript
session.connect(require('heci').GUIDS.AMT, { noPipeline: 0 });
```

**Parameters:**
- `guid` (Buffer) - 16-byte service GUID (AMT or LME)
- `options` (Object) - Optional configuration (noPipeline, etc.)

**Process:**
1. Executes CLIENT_CONNECT IOCTL with GUID
2. Retrieves MaxBufferSize from device
3. Sets up read/write overlapped operations (Windows)
4. Emits 'connect' event on success or 'error' on failure
5. Automatically starts read loop

**descriptorPath() - Lines 211-270**

Locates HECI device path:
- **Windows (Lines 221-262)**: Uses SetupAPI to enumerate device interfaces for HECI GUID
  - SetupDiGetClassDevsA (Line 226)
  - SetupDiEnumDeviceInterfaces (Line 238)
  - SetupDiGetDeviceInterfaceDetailA (Line 241, 254)
  - Returns device path from interface detail

- **Linux (Lines 214-217)**: Checks standard MEI device nodes
  - /dev/mei0 (primary)
  - /dev/mei (fallback)

**createDescriptor(path) - Lines 271-288**

Opens device handle:
- **Windows (Lines 279-280)**: CreateFileA with overlapped I/O flag
  - GENERIC_READ | GENERIC_WRITE permissions
  - FILE_FLAG_OVERLAPPED for async operations
  - Returns HANDLE value

- **Linux (Lines 274-275)**: fs.openSync with O_RDWR | O_NONBLOCK

**doIoctl(code, inputBuffer, outputBuffer, callback) - Lines 361-392**

Executes device I/O control command:

**Parameters:**
- `code` (number) - IOCTL command code (HECI_VERSION, CLIENT_CONNECT)
- `inputBuffer` (Buffer) - Command input data
- `outputBuffer` (Buffer) - Result buffer (overwritten with response)
- `callback` (function) - Callback(status, outputBuffer, ...parms)
- Additional parameters passed through to callback

**Windows Implementation (Lines 394-452):**
1. Queues IOCTL request to _ioctls array
2. Calls _send() for first IOCTL
3. Uses DeviceIoControl with overlapped operation
4. Awaits completion via DescriptorEvents
5. Invokes callback with results

**Linux Implementation (Lines 373-383):**
1. Copies inputBuffer to outputBuffer
2. Calls native ioctl() immediately
3. Synchronous response returned in callback

**disconnect() - Lines 297-360**

Cleanup and resource release:
- Removes descriptor event listeners
- Closes file handles (Windows: CloseHandle, Linux: fs.closeSync)
- Cancels pending I/O operations
- Clears overlapped operation structures
- Called automatically on stream destruction ('~' event, Line 566)

### Write Operation Flow

**_processWrite() - Lines 454-479**

Executes pending write:
- **Windows (Lines 459-475)**: WriteFile with overlapped operation
  - Queues descriptor event handler
  - Sets ERROR_IO_PENDING check

- **Linux (Lines 477-478)**: fs.write with async callback

**_processWrite_signaled(status) - Lines 501-530**

Windows write completion handler:
- Checks overlapped result status
- Pops item from _pendingWrites queue
- Continues next write or signals flush
- Respects noPipeline option (Line 513)

**_processWrite_linux_signaled(status, bytesWritten, buffer, options) - Lines 480-500**

Linux write completion handler:
- Pops from _pendingWrites on success
- Handles noPipeline flow control
- Invokes flush callback when queue empty

### Read Operation Flow

**_read(size) - Lines 84-165**

Initiates asynchronous read (Windows):
1. Allocates read buffer if needed (Line 88)
2. Calls ReadFile with overlapped operation
3. Sets up descriptor event listener
4. Waits for data signal

**Read Completion (Lines 104-158):**
- GetOverlappedResult retrieves bytes read
- Slices buffer to actual data size
- Calls push() to emit readable event
- Handles noPipeline synchronization (Lines 120-136)
- Continues next read or stops on end

**_processRead() - Lines 561-565**

Linux read operation:
- Calls fs.read with async callback
- Processes data through _processRead_readSet_sink

**_processRead_readSet_sink(status, bytesRead, buffer, options) - Lines 531-560**

Linux read completion:
- Slices buffer to bytes read
- Pushes to stream
- Handles noPipeline synchronization
- Continues reading on backpressure

### IOCTL Support

**IOCTL Constants (Lines 570-580):**

```javascript
Windows:
- HECI_VERSION = 0x8000E000
- CLIENT_CONNECT = 0x8000E004

Linux:
- HECI_VERSION = 0x00
- CLIENT_CONNECT = 0x01
```

**GUID Support (Lines 582-588):**

```javascript
- AMT: 2800F812B7B42D4BACA846E0FF65814C (hex)
- LME: DBA4336776047B4EB3AFBCFC29BEE7A7 (hex)
- HECI (Windows only): 34FFD1E25834A94988DA8E6915CE9BE5 (hex)
```

### Event Model

**Events Emitted:**
- `'connect'` (Line 208) - Successfully connected to service
- `'error'` (Line 185) - Connection or I/O error

**Stream Events:**
- Standard Node.js duplex stream events
- 'readable', 'writable', 'end', 'close'

### Platform Abstraction

**Windows-Specific (Lines 23-40, 63-78, 197-205, 289-296, 459-475):**
- _GenericMarshal for native API calls
- SetupAPI enumeration
- Event-based overlapped I/O
- Multiple handles (main + read + write)

**Linux-Specific (Lines 91-95, 213-217, 273-276, 373-383, 477-478, 561-565):**
- File descriptor I/O
- /dev/mei device interface
- NONBLOCK flag for async operations
- Single descriptor with callback-based async

### Support Detection

**Module.exports.supported - Lines 592-605**

Getter property that checks if HECI is available:
```javascript
if (require('heci').supported) {
    // HECI is available on this system
}
```

**Test:** Attempts to find descriptorPath and create descriptor. Returns true only if both succeed.

## Dependencies

### Node.js Core Modules

#### stream (Line 20)

```javascript
var duplex = require('stream').Duplex;
```

**Purpose:** Duplex stream base class for read/write operations

**Usage:**
- Provides Stream.Duplex constructor
- Event emitter inheritance via EventEmitter
- Buffer backpressure handling

**Methods:**
- Constructor for creating bidirectional streams
- push() method for readable side
- write() callbacks for writable side

#### fs (Line 215, 275, 306)

```javascript
require('fs').existsSync(path)
require('fs').openSync(path, flags)
require('fs').closeSync(fd)
require('fs').read(fd, options, callback)
require('fs').write(fd, buffer, callback, options)
```

**Platform:** Linux only

**Purpose:** File system operations for /dev/mei device

**Methods Used:**
- existsSync() - Check for MEI device nodes
- openSync() - Open MEI device
- closeSync() - Close file descriptor
- read() - Asynchronous read with callback
- write() - Asynchronous write with callback

### MeshAgent Module Dependencies

#### _GenericMarshal (Line 25, 32)

```javascript
var GM = require('_GenericMarshal');
var setup = GM.CreateNativeProxy('SetupAPI.dll');
var kernel32 = GM.CreateNativeProxy('Kernel32.dll');
```

**Platform:** Windows only

**Purpose:** Access to Windows native APIs

**Methods:**
- CreateNativeProxy(dllName) - Load DLL and create proxy
- CreateMethod(methodName) - Define native method
- CreateVariable(size) - Allocate unmanaged memory
- CreatePointer() - Create pointer type
- PointerSize - 4 (32-bit) or 8 (64-bit)

**SetupAPI Methods (Lines 27-30):**
- SetupDiGetClassDevsA() - Enumerate device class
- SetupDiEnumDeviceInterfaces() - Enumerate device interfaces
- SetupDiGetDeviceInterfaceDetailA() - Get device path
- SetupDiDestroyDeviceInfoList() - Cleanup

**Kernel32 Methods (Lines 33-39):**
- CreateFileA() - Open device file handle
- CreateEventA() - Create manual reset event
- ReadFile() - Async read with overlapped I/O
- WriteFile() - Async write with overlapped I/O
- DeviceIoControl() - Execute device command
- GetOverlappedResult() - Get async operation result
- CloseHandle() - Close handle/event

#### DescriptorEvents (Line 102, 305, 318, 332, 346, 399, 464, 466)

```javascript
require('DescriptorEvents').addDescriptor(handle, metadata)
require('DescriptorEvents').removeDescriptor(handle)
require('DescriptorEvents').descriptorAdded(handle)
```

**Purpose:** Event notification for Windows handle completion

**Usage:**
- Register event handles for completion notification
- Receive signaled events
- Remove handles on cleanup
- Check if handle already registered

**Events:**
- 'signaled' - Fired when handle signaled
- Status: 'NONE' (success), or error string

#### events (Line 173)

```javascript
require('events').EventEmitter.call(ret, true)
```

**Purpose:** Event emitter mixin for stream object

**Methods:**
- EventEmitter() - Constructor
- createEvent(name) - Define custom event
- addMethod(name, function) - Add property method with event

#### ioctl (Line 379)

```javascript
require('ioctl')(fd, code, buffer)
```

**Platform:** Linux only

**Purpose:** Execute device I/O control command

**Parameters:**
- fd (number) - File descriptor
- code (number) - IOCTL command code
- buffer (Buffer) - Command data (modified in place)

**Return:** Status code (0 = success)

### Dependency Chain

```
heci.js
├─── stream (Node.js core)
│    └─── EventEmitter
├─── fs (Node.js core, Linux only)
│    └─── /dev/mei device
├─── _GenericMarshal (Windows only)
│    ├─── SetupAPI.dll
│    └─── Kernel32.dll
├─── DescriptorEvents (Windows only)
│    └─── Handle completion signals
├─── events (Node.js core)
│    └─── EventEmitter
└─── ioctl (Linux only)
     └─── /dev/mei ioctl
```

### Platform Binary Dependencies

**Windows:**
- SetupAPI.dll - Device enumeration and interface access
- Kernel32.dll - File I/O and event synchronization
- MEI driver - Intel Management Engine Interface driver
- User-mode access to MEI device

**Linux:**
- /dev/mei or /dev/mei0 - MEI device node
- Linux kernel MEI driver module
- libioctl or kernel support for ioctl

## Technical Notes

### Device Enumeration (Windows)

The module uses SetupAPI to locate HECI devices:
1. Gets device class from HECI GUID (Line 225)
2. Enumerates all device interfaces in class
3. Retrieves interface detail including device path
4. Opens device with CreateFileA

**HECI GUID (Line 587):** 34FFD1E25834A94988DA8E6915CE9BE5

### Overlapped I/O (Windows)

Asynchronous operations use overlapped handles:
- Separate read and write handles (Lines 199-202)
- Manual-reset events for signaling (Line 201-202)
- GetOverlappedResult checks operation completion
- Callback-based event handling via DescriptorEvents

**Event Structure (Line 199-200):**
- 32 bytes on 64-bit systems
- 20 bytes on 32-bit systems
- Contains OVERLAPPED_IO structure with hEvent

### Buffer Management

**Read Buffer (Line 88, 562):**
- Allocated once using MaxBufferSize
- Reused for all read operations
- Sliced to actual bytes read before pushing

**Write Queue (Line 170, 456):**
- _pendingWrites array holds pending operations
- Each element: { buffer, flush } pair
- Processed sequentially from queue

### Pipeline Control

**noPipeline Option (Line 120, 486, 512):**

When set:
- Only one operation outstanding at a time
- Read completion blocks next write (Line 122-134)
- Write completion must happen before next read
- Used for strict request-response protocols

### Error Handling

**Status Codes:**
- Windows HECI: Status from GetOverlappedResult
- Linux HECI: Status from ioctl()
- 0 = success
- Non-zero = failure

**Error Callback:**
```javascript
callback(status, outputBuffer, ...parms)
// status = 0 on success, error code on failure
```

### MaxBufferSize

Retrieved during connect (Line 194):
```javascript
MaxBufferSize = buffer.readUInt32LE()
```

Defines maximum:
- Per-packet size for read/write
- Fragmentation requirement for large transfers
- Typically 4096 bytes

## Summary

The heci.js module provides the foundational duplex stream interface to Intel Management Engine services on Windows and Linux systems. It abstracts platform differences (SetupAPI/Kernel32 on Windows, /dev/mei on Linux) and implements asynchronous I/O patterns suitable for embedded controller communication.

**Placed in modules_macos_NEVER** because:
- Requires Intel Management Engine hardware (absent on macOS)
- Windows SetupAPI enumeration not available on macOS
- Linux /dev/mei device interface not available on macOS
- Platform-specific implementation makes macOS adaptation impossible
- Apple systems use different hardware architecture

**Core functionality:**
- Device discovery and enumeration
- Async read/write with overlapped I/O (Windows) or callbacks (Linux)
- IOCTL command execution for service connection
- Duplex stream abstraction for consumer code
- Event-driven architecture with completion notifications

Used by higher-level modules (amt-mei.js, lme_heci.js) to access PTHI and LME services on Intel platforms.
