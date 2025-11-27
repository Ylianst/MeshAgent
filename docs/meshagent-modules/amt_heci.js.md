# amt_heci.js

JavaScript interface for communicating with Intel Active Management Technology (Intel AMT) firmware through the Host Embedded Controller Interface (HECI). Enables local applications to query AMT provisioning status, retrieve version information, obtain UUIDs, manage certificates, and control AMT features such as remote access connections and unprovisioning operations.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via HECI device driver interface
- Linux - Full support via `/dev/mei` or `/dev/mei0` character devices

**Excluded Platforms:**
- **macOS (darwin)** - Not supported and explicitly excluded

**Exclusion Reasoning:**

macOS hardware fundamentally lacks HECI hardware interfaces:

1. **No Intel AMT Hardware Support** - Apple Mac computers do not include the Intel Management Engine (ME) firmware and associated HECI hardware interface that Intel AMT requires. This is a hardware-level exclusion, not a software limitation.

2. **HECI Interface Unavailable** - The HECI (Host Embedded Controller Interface) is a hardware communication channel between the host OS and Intel's Management Engine. Mac systems don't have this hardware component, making the entire module non-functional on macOS.

3. **Apple's Custom Firmware** - Mac computers use Apple's proprietary firmware and system management technologies rather than Intel's reference platform designs that include AMT capabilities.

4. **No Device Driver Path** - The `heci.js` dependency (lines 24, 213-219) explicitly checks for Windows device paths or Linux `/dev/mei*` devices. On line 219, it throws `'HECI not supported'` for any platform other than Windows or Linux, confirming macOS is intentionally excluded.

**Technical Evidence from heci.js:**
- Lines 23-40: Platform-specific initialization only for Windows (SetupAPI/Kernel32 DLLs)
- Lines 213-219: `descriptorPath()` method throws error for non-Windows/Linux platforms
- Lines 273-277: `createDescriptor()` method throws error for non-Windows/Linux platforms
- Lines 585-588: HECI GUID only defined for Windows platform

## Functionality

### Core Purpose

The module acts as a high-level wrapper around low-level HECI communications, implementing Intel AMT's proprietary command protocol for local management. It provides asynchronous command/response functionality with request queuing to serialize AMT commands and ensure proper response matching.

### Connection Management (Lines 19-48)

**Initialization:**
- Creates HECI connection to AMT firmware using the AMT GUID (`2800F812B7B42D4BACA846E0FF65814C`)
- Establishes event-driven communication with automatic data handling
- Implements "no pipeline" mode to prevent command interleaving
- Emits `connect` and `error` events for application monitoring

**Event Handling:**
- `connect` event - Fired when HECI session established
- `error` event - Fired on connection or communication errors
- Data event - Internal handler for processing AMT responses

### Version & Identification

#### getVersion(callback) - Lines 70-86

**Command:** 26 (0x1A)

**Purpose:** Retrieves AMT firmware version information including BIOS version and component versions

**Returns:** Object containing:
- `BiosVersion` - 65-byte BIOS version string
- `Versions` - Array of component version objects with:
  - `description` - Component name
  - `version` - Version string

---

#### getUuid(callback) - Lines 88-105

**Command:** 92 (0x5C)

**Purpose:** Retrieves the unique identifier for this AMT instance

**Returns:** Formatted UUID string (e.g., `12345678-1234-1234-1234-1234567890ab`)

**Format:** Standard UUID format with byte order conversion (lines 97-101):
- Big-endian conversion for time fields
- Little-endian for node and clock sequence

### Provisioning State

#### getProvisioningState(callback) - Lines 107-121

**Command:** 17 (0x11)

**Purpose:** Determines current AMT provisioning state

**Returns:** Object with:
- `state` - Numeric state (0-2)
- `stateStr` - String representation:
  - `"PRE"` - Pre-provisioning (not yet configured)
  - `"IN"` - In provisioning (configuration in progress)
  - `"POST"` - Post-provisioning (fully configured)

---

#### getProvisioningMode(callback) - Lines 122-137

**Command:** 8 (0x08)

**Purpose:** Identifies provisioning mode and legacy status

**Returns:** Object with:
- `mode` - Numeric mode (0-3)
- `modeStr` - String representation:
  - `"NONE"` - Not provisioned
  - `"ENTERPRISE"` - Enterprise mode (certificate-based)
  - `"SMALL_BUSINESS"` - Small business mode
  - `"REMOTE_ASSISTANCE"` - Remote assistance mode
- `legacy` - Boolean indicating legacy mode

### Control & Configuration

#### getEHBCState(callback) - Lines 138-149

**Command:** 132 (0x84)

**Purpose:** Checks Enhanced Host-Based Configuration state

**Returns:** Object with:
- `EHBC` - Boolean flag indicating EHBC enabled/disabled

---

#### getControlMode(callback) - Lines 150-164

**Command:** 107 (0x6B)

**Purpose:** Determines current control mode

**Returns:** Object with:
- `controlMode` - Numeric mode (0-3)
- `controlModeStr` - String representation:
  - `"NONE_RPAT"` - No remote control
  - `"CLIENT"` - Client control mode
  - `"ADMIN"` - Administrator control mode
  - `"REMOTE_ASSISTANCE"` - Remote assistance active

### Network & Hardware

#### getMACAddresses(callback) - Lines 165-174

**Command:** 37 (0x25)

**Purpose:** Retrieves dedicated and host MAC addresses

**Returns:** Object with:
- `DedicatedMAC` - Hex string format `xx:xx:xx:xx:xx:xx`
- `HostMAC` - Hex string format `xx:xx:xx:xx:xx:xx`

**Usage:** Useful for identifying AMT network interface vs host interface

---

#### getDnsSuffix(callback) - Lines 175-187

**Command:** 54 (0x36)

**Purpose:** Retrieves configured DNS suffix for AMT

**Returns:** DNS suffix string or null if not configured

### Certificate Management

#### getHashHandles(callback) - Lines 188-202

**Command:** 44 (0x2C)

**Purpose:** Retrieves list of certificate hash handles stored in AMT

**Returns:** Array of handle integers

---

#### getCertHashEntry(handle, callback) - Lines 203-228

**Command:** 45 (0x2D)

**Purpose:** Retrieves detailed information for specific certificate hash

**Parameters:**
- `handle` - Certificate hash handle (from getHashHandles)

**Returns:** Object with:
- `isDefault` - Boolean, true if default certificate
- `isActive` - Boolean, true if currently active
- `hashAlgorithm` - Numeric hash algorithm identifier (1-4)
- `hashAlgorithmStr` - String representation:
  - `"MD5"` (1)
  - `"SHA1"` (2)
  - `"SHA256"` (3)
  - `"SHA512"` (4)
- `hashAlgorithmSize` - Hash size in bytes
- `certificateHash` - Buffer containing hash value
- `name` - Certificate name/identifier

---

#### getCertHashEntries(callback) - Lines 229-246

**Purpose:** Convenience method that retrieves all certificate hash entries

**Implementation:** Recursively calls `getCertHashEntry()` for all handles from `getHashHandles()`

**Returns:** Array of certificate hash entry objects

### Security & Accounts

#### getLocalSystemAccount(callback) - Lines 247-254

**Command:** 103 (0x67)

**Purpose:** Retrieves local system account credentials

**Returns:** Object with:
- `user` - Username string (32 bytes)
- `pass` - Password string (32 bytes)
- `raw` - Raw buffer (68 bytes total)

**Security Note:** Credentials returned in plaintext - requires local admin/root access to HECI device

### Provisioning Operations

#### unprovision(mode, callback) - Lines 255-264

**Command:** 16 (0x10)

**Purpose:** Triggers AMT unprovisioning with specified mode

**Parameters:**
- `mode` - Integer specifying unprovision mode

**Returns:** Status code from AMT firmware

**Effect:** Resets AMT to unconfigured state

### Configuration Control

#### startConfiguration(callback) - Lines 265-269

**Command:** 41 (0x29)

**Purpose:** Initiates AMT configuration session

**Usage:** Must be called before making configuration changes

---

#### stopConfiguration(callback) - Lines 270-274

**Command:** 94 (0x5E)

**Purpose:** Terminates AMT configuration session

**Usage:** Called after completing configuration changes

### Remote Access

#### openUserInitiatedConnection(callback) - Lines 275-279

**Command:** 68 (0x44)

**Purpose:** Opens user-initiated remote connection to management server

**Usage:** Establishes connection to Intel vPro management platform

---

#### closeUserInitiatedConnection(callback) - Lines 280-284

**Command:** 69 (0x45)

**Purpose:** Closes user-initiated remote connection

---

#### getRemoteAccessConnectionStatus(callback) - Lines 285-297

**Command:** 70 (0x46)

**Purpose:** Retrieves current remote access connection status

**Returns:** Object with:
- `status` - Overall connection status
- `networkStatus` - Network connectivity state
- `remoteAccessStatus` - Remote access state
- `remoteAccessTrigger` - What triggered the connection
- `mpsHostname` - Management Presence Server hostname
- `raw` - Raw response data

### Protocol Information

#### getProtocolVersion(callback) - Lines 298-313

**Purpose:** Retrieves HECI protocol version

**Implementation:** Uses direct IOCTL call (`HECI_VERSION`) instead of AMT command

**Returns:** Version string in format `major.minor.hotfix.build`

**Note:** This queries the HECI driver version, not AMT firmware version

## Protocol Implementation

### Command Structure (Lines 56-68)

The module implements Intel's AMT HECI command protocol:

**Header Format (12 bytes):**
- Bytes 0-3: Magic/version (`01010000` hex)
- Bytes 4-7: Command ID (with bit flags)
- Bytes 8-11: Payload length

**Command Encoding:**
- Bit 26 (0x04000000): Request flag (always set for outgoing commands)
- Bit 23 (0x800000): Response flag (set for incoming responses)
- Bits 0-22: Command number (0x7FFFFF mask)

**Response Handling (Lines 50-54):**
- Byte 4-7: Command ID with response flag
- Bytes 12-15: Status code
- Bytes 16+: Response data

### Request Queuing (Line 17, 30, 61)

Uses the `queue` module to serialize AMT commands:
- Ensures one command executes at a time
- Matches responses to requests via queue position
- Supports optional parameters passed through callback chain
- Prevents race conditions in command/response handling

## Dependencies

### MeshAgent Module Dependencies

#### queue (Line 17)

```javascript
var Q = require('queue');
```

**Purpose:** Request queue implementation for serializing AMT commands

**Usage:**
- Line 30: Creates queue instance `this._amt.rq = new Q()`
- Line 61: `enQueue()` - Adds command to queue
- Line 40: `deQueue()` - Removes completed command
- Line 51: `peekQueue()` - Views queue head without removing

**Why needed:** AMT firmware can only process one command at a time

---

#### events (Line 20)

```javascript
require('events').inherits(this)
```

**Purpose:** Provides event emitter functionality via prototype inheritance

**Usage:**
- Line 21-22: Creates `error` and `connect` events
- Enables event-driven communication model

**Type:** Node.js core module wrapper

---

#### heci (Line 24)

```javascript
var heci = require('heci');
```

**Purpose:** Low-level HECI hardware interface module

**Critical Dependency:** This is the binary/native module that provides actual hardware access

**Usage:**
- Line 26: Creates HECI session instance
- Line 48: Connects to AMT GUID with no-pipeline option
- Line 302: Performs direct IOCTL for protocol version

**Platform-Specific:** Only available on Windows and Linux

### Node.js Core Module Dependencies

**Buffer (Lines 63, 207, 250, 258)**
- Binary data manipulation for HECI protocol
- Methods: `Buffer.from()`, `Buffer.alloc()`, `Buffer.concat()`
- Purpose: Construct command headers and payloads

**Implicit Dependencies (via heci module):**
- `stream.Duplex` - HECI session implements duplex stream
- `fs` - File system operations for device access on Linux
- `events` - Event emitter base class

### Platform Binary Dependencies

#### HECI Hardware Driver

**Windows:**
- Accessed via `CreateFileA()` API to HECI device path (heci.js lines 280-287)
- Device name typically: `\\.\HECI` or similar
- Requires Intel MEI/HECI driver installed

**Linux:**
- Accessed via file descriptor to `/dev/mei` or `/dev/mei0` (heci.js lines 213-218, 275-276)
- Requires appropriate device permissions (typically root/admin)
- Kernel module: `mei_me` must be loaded

#### Windows-Specific DLLs (via heci.js)

**SetupAPI.dll** (Lines 26-30 of heci.js):
- `SetupDiGetClassDevsA()` - Device enumeration
- `SetupDiEnumDeviceInfo()` - Iterate devices
- `SetupDiGetDeviceRegistryPropertyA()` - Read device properties
- `SetupDiDestroyDeviceInfoList()` - Cleanup

**Kernel32.dll** (Lines 32-39 of heci.js):
- `CreateFileA()` - Open HECI device
- `CloseHandle()` - Close device handle
- `DeviceIoControl()` - Send IOCTL commands
- `ReadFile()`/`WriteFile()` - Data transfer

#### Linux-Specific

**ioctl system call** (Line 379 of heci.js):
- Direct device control operations
- HECI_VERSION ioctl for version queries
- Requires kernel support for MEI devices

### Intel AMT Firmware Dependency

**Intel Management Engine (ME) Firmware:**
- Version Requirements: Buffer sizes suggest AMT 6.0+ support
  - `BiosVersionLen = 65` (line 27)
  - `UnicodeStringLen = 20` (line 28)
- GUID: AMT service GUID `2800F812-B7B4-2D4B-ACA8-46E0FF65814C`
- Hardware: Intel chipset with AMT provisioning enabled

### Dependency Chain Summary

```
amt_heci.js
├─── queue (Line 17) - Request serialization
├─── events (Line 20) - Event emitter
└─── heci (Line 24) - CRITICAL native module
     ├─── stream.Duplex - Communication interface
     ├─── fs - Linux device access
     ├─── events - Event system
     ├─── _GenericMarshal (Windows) - FFI to native DLLs
     ├─── ioctl (Linux) - System call wrapper
     └─── Hardware/Firmware
          ├─── Windows: SetupAPI.dll + Kernel32.dll
          ├─── Linux: /dev/mei* character device
          └─── Intel ME Firmware with AMT service
```

## Technical Notes

### Error Handling

- All commands include status checking in callbacks (various lines checking `header.Status == 0`)
- Connection errors propagated via `error` event (line 32)
- HECI module throws exceptions for unsupported platforms

### Data Encoding

- Multi-byte integers use little-endian format (`readUInt32LE`, `readUInt16LE`)
- Big-endian used for specific UUID components (line 97: `readUInt16BE`)
- Strings assume UTF-8 encoding unless Unicode string length specified

### Security Considerations

- Local system account credentials retrieved in plaintext (lines 247-254)
- Requires local administrator/root access for HECI device access
- No authentication required once HECI connection established (hardware-level trust)
- HECI communication bypasses OS security - direct firmware access

### Memory Management

- Response buffers allocated per command
- No memory pooling - each command allocates fresh buffers
- Automatic garbage collection when callbacks complete

## Summary

The amt_heci.js module provides a comprehensive JavaScript interface to Intel AMT firmware through the HECI hardware interface. It exposes 20+ high-level methods covering version information, provisioning state, certificate management, network configuration, and remote access control.

**macOS is excluded** because:
- Mac hardware completely lacks HECI hardware interfaces
- No Intel Management Engine firmware on Mac systems
- Apple uses proprietary system management instead of Intel AMT
- The heci.js dependency explicitly throws errors on non-Windows/Linux platforms
- This is a fundamental hardware limitation, not a software issue

The module is essential for local AMT management operations on Windows and Linux systems with Intel vPro hardware, but serves no purpose on macOS where the required hardware doesn't exist.
