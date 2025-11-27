# amt-mei.js

Simplified alias/wrapper for amt_heci.js providing Intel AMT Platform Transaction Host Interface (PTHI) communication. This module is functionally identical to amt_heci.js and exists for naming compatibility - "MEI" (Management Engine Interface) is an alternative name for "HECI" (Host Embedded Controller Interface).

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via HECI device driver interface
- Linux - Full support via `/dev/mei` or `/dev/mei0` character devices

**Excluded Platforms:**
- **macOS (darwin)** - Not supported

**Exclusion Reasoning:**

macOS lacks the required Intel Management Engine hardware:

1. **No Intel AMT/ME Hardware** - Apple Mac computers do not include the Intel Management Engine (ME) firmware that AMT requires. This is a fundamental hardware-level exclusion affecting all ME/HECI-dependent modules.

2. **Missing HECI/MEI Interface** - The HECI (Host Embedded Controller Interface), also called MEI (Management Engine Interface), is a hardware communication channel that does not exist on Mac systems. Line 40 (`var heci = require('heci')`) will fail to load on macOS.

3. **Platform Detection in heci Module** - The underlying `heci` binary module explicitly checks platform and throws errors for non-Windows/Linux systems:
   - **heci.js line 219:** `throw 'HECI not supported'` for unsupported platforms
   - **heci.js lines 273-277:** `createDescriptor()` throws error for macOS
   - **heci.js lines 585-588:** HECI GUIDs only defined for Windows

4. **Apple's Custom Management** - Mac computers use Apple's proprietary firmware and system management instead of Intel's reference platform technologies.

**Technical Evidence:**
- Line 40: `require('heci')` - Binary module unavailable on macOS
- Line 26: Attempts connection to AMT GUID (hardware-specific identifier)
- Lines 213-219 in heci.js: Explicit platform exclusion

---

## Functionality

### Core Purpose

This module is a **naming alias** for amt_heci.js. Both modules provide identical functionality for communicating with Intel AMT firmware through the PTHI (Platform Transaction Host Interface).

**Why Two Names?**

Intel's interface has been called both:
- **HECI** - Host Embedded Controller Interface (original name)
- **MEI** - Management Engine Interface (newer name)

Both terms refer to the same hardware interface. This module exists for compatibility with code expecting the "MEI" naming convention.

---

## Complete Implementation

The entire module consists of a single line (line 485):

```javascript
module.exports = amt_heci;
```

**What This Does:**
- Requires amt_heci.js (the full implementation)
- Exports it unchanged as amt-mei

---

## Full Feature Set

Since this module exports amt_heci.js directly, it provides all PTHI functionality:

### Version & Identification Methods

1. **getVersion(callback)** - Line 142 in amt_heci.js
   - Command: 26 (0x1A)
   - Returns BIOS version and component versions

2. **getUuid(callback)** - Line 171 in amt_heci.js
   - Command: 92 (0x5C)
   - Returns AMT unique identifier

3. **getProtocolVersion(callback)** - Line 422 in amt_heci.js
   - Uses HECI IOCTL
   - Returns HECI protocol version

### Provisioning State Methods

4. **getProvisioningState(callback)** - Line 190 in amt_heci.js
   - Command: 17 (0x11)
   - Returns: PRE, IN, or POST provisioning state

5. **getProvisioningMode(callback)** - Line 205 in amt_heci.js
   - Command: 8 (0x08)
   - Returns: NONE, ENTERPRISE, SMALL_BUSINESS, or REMOTE_ASSISTANCE

6. **getEHBCState(callback)** - Line 221 in amt_heci.js
   - Command: 132 (0x84)
   - Returns Emergency Host Boot Control state

7. **getControlMode(callback)** - Line 233 in amt_heci.js
   - Command: 107 (0x6B)
   - Returns control mode: NONE_RPAT, CLIENT, ADMIN, or REMOTE_ASSISTANCE

### Network Configuration Methods

8. **getMACAddresses(callback)** - Line 248 in amt_heci.js
   - Command: 37 (0x25)
   - Returns dedicated and host MAC addresses

9. **getDnsSuffix(callback)** - Line 258 in amt_heci.js
   - Command: 54 (0x36)
   - Returns DNS suffix string

10. **getLanInterfaceSettings(index, callback)** - Line 344 in amt_heci.js
    - Command: 72 (0x48)
    - Returns LAN interface configuration (DHCP, IP, MAC)

### Certificate Management Methods

11. **getHashHandles(callback)** - Line 271 in amt_heci.js
    - Command: 44 (0x2C)
    - Returns array of certificate hash handles

12. **getCertHashEntry(handle, callback)** - Line 286 in amt_heci.js
    - Command: 45 (0x2D)
    - Returns certificate hash details (algorithm, hash, name)

13. **getCertHashEntries(callback)** - Line 312 in amt_heci.js
    - Retrieves all certificate hash entries
    - Chains multiple getCertHashEntry calls

### Account Management Methods

14. **getLocalSystemAccount(callback)** - Line 331 in amt_heci.js
    - Command: 103 (0x67)
    - Returns local system account username and password

### Provisioning Control Methods

15. **unprovision(mode, callback)** - Line 379 in amt_heci.js
    - Command: 16 (0x10)
    - Unprovisions AMT (modes: full or partial)

16. **startConfiguration(callback)** - Line 389 in amt_heci.js
    - Command: 41 (0x29)
    - Begins configuration mode

17. **stopConfiguration(callback)** - Line 394 in amt_heci.js
    - Command: 94 (0x5E)
    - Stops configuration mode

18. **startConfigurationHBased(certHash, hostVpn, dnsSuffixList, callback)** - Line 440 in amt_heci.js
    - Command: 139 (0x8B)
    - Starts hash-based provisioning
    - Supports SHA256 and SHA384 certificate hashes

### Remote Access Methods

19. **openUserInitiatedConnection(callback)** - Line 399 in amt_heci.js
    - Command: 68 (0x44)
    - Opens CIRA (Client Initiated Remote Access) connection

20. **closeUserInitiatedConnection(callback)** - Line 404 in amt_heci.js
    - Command: 69 (0x45)
    - Closes CIRA connection

21. **getRemoteAccessConnectionStatus(callback)** - Line 409 in amt_heci.js
    - Command: 70 (0x46)
    - Returns network status, remote access status, trigger, and MPS hostname

---

## Dependencies

### JavaScript Module Dependencies

#### require('queue') - Line 17
**Type:** JavaScript module
**Purpose:** Command queue for serializing PTHI requests
**Usage:** Ensures commands execute in order (global singleton `g_internal._rq`)

#### require('events').inherits() - Line 37
**Type:** Core Node.js module
**Purpose:** Event emitter functionality
**Usage:** Provides `error` event for PTHI communication failures

#### require('heci') - Line 40
**Type:** Binary native module
**Purpose:** Low-level HECI/MEI hardware interface
**Platform:** Windows/Linux only
**macOS Status:** Not available - module load fails
**Usage:**
- Creating HECI connection (line 51)
- Connecting to AMT GUID (line 26, 138)
- IOCTL operations (line 427)

#### require('MeshAgent') - Line 41
**Type:** Optional JavaScript module
**Purpose:** Console message forwarding to MeshCentral
**Usage:** Sending diagnostic messages via `SendCommand`
**Graceful Degradation:** Wrapped in try/catch, continues without MeshAgent

---

## Binary Dependencies

### HECI/MEI Driver

**Windows:**
- **Driver:** Intel Management Engine Interface driver
- **Device:** `\\.\HECI` or `\\.\MEI`
- **Requirement:** Intel MEI driver installed and running

**Linux:**
- **Device:** `/dev/mei` or `/dev/mei0`
- **Kernel Module:** `mei_me` (Management Engine Interface)
- **Permissions:** Read/write access to MEI device node
- **Typical Setup:**
  ```bash
  # Check if MEI device exists
  ls -l /dev/mei*

  # Check if kernel module loaded
  lsmod | grep mei
  ```

**macOS:**
- **Status:** Not available
- **Reason:** No HECI/MEI hardware on Mac computers

---

## Relationship to Other AMT Modules

### Module Naming Hierarchy

```
amt_heci.js (actual implementation)
    ↓
amt-mei.js (this module - naming alias)
```

Both modules export the exact same constructor and functionality.

### Integration with AMT Stack

**PTHI's Role in AMT Architecture:**

```
┌─────────────────────────────────────────┐
│      Local Management Application       │
└──────────────┬──────────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
┌───▼─────────┐  ┌────────▼─────────┐
│ amt-mei.js  │  │  amt_heci.js     │  (Same Implementation)
│ (alias)     │  │  (main)          │
└───┬─────────┘  └────────┬─────────┘
    │                     │
    └──────────┬──────────┘
               │ PTHI Protocol
┌──────────────▼──────────────────────────┐
│         heci (Binary Module)            │
│  - HECI/MEI driver interface            │
└──────────────┬──────────────────────────┘
               │ Hardware Interface
┌──────────────▼──────────────────────────┐
│   Intel Management Engine (Hardware)    │
│  - PTHI firmware subsystem              │
│  - AMT provisioning engine              │
└─────────────────────────────────────────┘
```

### Complementary Modules

1. **amt-lme.js** - Local Manageability Engine
   - Different HECI GUID: `heci.GUIDS.LME` vs `heci.GUIDS.AMT`
   - Purpose: Port forwarding and event notifications
   - PTHI Purpose: Management commands and queries

2. **amt-wsman.js** - Web Services Management
   - Protocol: HTTP/HTTPS-based WSMAN
   - PTHI provides local alternative for some operations
   - WSMAN provides comprehensive remote management

3. **amt.js** - High-level AMT wrapper
   - Builds on amt-wsman.js for network management
   - May use PTHI for local provisioning queries

4. **heci** - Hardware interface
   - Binary module providing HECI device access
   - Both amt-mei.js and amt-lme.js depend on heci
   - Different GUID connections for different subsystems

---

## Hardware Requirements

### Required Hardware Components

1. **Intel vPro Platform**
   - Business-class Intel chipset with AMT support
   - Consumer chipsets do not include AMT/ME

2. **Intel Management Engine (ME)**
   - Firmware subsystem in chipset
   - Implements PTHI command processing
   - Version 6.0+ recommended

3. **HECI/MEI Interface**
   - Hardware communication channel
   - PCI device exposed to OS
   - Required for all ME communication

### Hardware Identification

**Windows:**
```
Device Manager → System Devices → Intel Management Engine Interface
PCI Device ID: 8086:xxxx (various ME controller IDs)
```

**Linux:**
```bash
# Check for MEI PCI device
lspci | grep -i "management engine"

# Check for MEI character device
ls -l /dev/mei*

# Verify kernel module
lsmod | grep mei_me
```

**macOS:**
```
Not present - Mac hardware does not include ME/HECI
```

---

## Global Singleton Architecture

### Why Global State? - Lines 18, 45-112

The module uses a global singleton (`g_internal`) to ensure only one PTHI connection exists across all instances:

**Reasons for Singleton:**

1. **Hardware Limitation** - HECI can typically only support one connection to PTHI at a time
2. **Command Serialization** - PTHI requires sequential command/response handling
3. **Resource Conservation** - Avoid multiple HECI connections competing for ME resources

**Singleton Components:**

```javascript
g_internal = {
    _rq: new Q(),              // Command queue
    _amt: null,                // HECI connection
    errorCount: 0,             // Retry counter
    _setupPTHI: function()     // Connection initializer
}
```

**Behavior:**

- First `amt_heci()` instance creates `g_internal`
- Subsequent instances reuse same `g_internal`
- All instances share the same command queue
- Commands from different instances execute sequentially

---

## Command Queue System

### Request Serialization - Lines 17, 47, 122-140

**Purpose:** Ensure only one PTHI command executes at a time

**Queue Entry Structure:**
```javascript
{
    cmd: commandId,          // Numeric command ID
    func: callback,          // Callback function
    optional: [args],        // Additional callback arguments
    send: buffer             // Binary command packet to send
}
```

**Flow:**

1. **Command Submission** - `sendCommand()` adds to queue (line 134)
2. **First Command** - If queue empty, connects HECI and starts sending
3. **Command Send** - First command sent on connect (line 106)
4. **Response Handling** - Callback invoked, command dequeued (line 82-87)
5. **Next Command** - If queue not empty, send next command (lines 99-102)
6. **Disconnect** - If queue empty, disconnect HECI (lines 89-96)

**Error Handling:**

- HECI errors trigger retry mechanism (lines 57-72)
- Up to 20 retries with 250ms delay (lines 22-32)
- After 20 failures, emits error event (line 31)

---

## Command Protocol

### PTHI Packet Format

**Command Packet (16 bytes + data):**
```
Bytes 0-3:   [0x01, 0x01, 0x00, 0x00]  // Protocol header
Bytes 4-7:   Command ID | 0x04000000   // Command with flag
Bytes 8-11:  Data length                // Length of following data
Bytes 12-15: [0x00, 0x00, 0x00, 0x00]  // Reserved
Bytes 16+:   Command-specific data      // Optional payload
```

**Response Packet:**
```
Bytes 0-3:   [varies]                   // Response header
Bytes 4-7:   Command ID | 0x00800000   // Response flag
Bytes 8-11:  [varies]                   // Response-specific
Bytes 12-15: Status code                // 0 = success
Bytes 16+:   Response data              // Command-specific
```

### Command/Response Matching - Lines 116-120

**getCommand(chunk):**
- Extracts command ID from response
- Checks response bit (0x800000)
- Returns parsed response object:
  ```javascript
  {
      IsResponse: true/false,
      Command: commandId,
      Status: statusCode,
      Data: responseBuffer
  }
  ```

---

## Connection Lifecycle

### Initialization Sequence

1. **Constructor Call** - `new amt_heci()` or `require('amt-mei')()`
2. **Global Setup** - Create `g_internal` if first instance (line 45)
3. **First Command** - Application calls any method (e.g., `getVersion()`)
4. **HECI Setup** - `_setupPTHI()` called (line 137)
5. **HECI Connect** - Connect to AMT GUID with noPipeline=1 (line 138)
6. **Event Handlers** - Error and data handlers installed (lines 57-103)
7. **Command Send** - First command sent from queue (line 106)
8. **Response Processing** - Data event fires, callback invoked (lines 76-87)
9. **Next Command or Disconnect** - Continue or close HECI (lines 89-102)

### Auto-Reconnect on Error - Lines 20-33, 57-72

If HECI connection fails but queue has pending commands:

1. Error event handler checks if queue empty (line 60)
2. If queue not empty, retry connection (line 70)
3. Retry function waits 250ms (line 27)
4. Attempts reconnect to AMT GUID (line 26)
5. Increments error counter (line 22)
6. After 20 failures, emits error to application (line 31)

---

## Usage Examples

### Basic Usage (Identical for amt-mei and amt_heci)

```javascript
// Using amt-mei naming
var amtMei = require('amt-mei');
var mei = new amtMei();

mei.getVersion(function(version) {
    if (version) {
        console.log('BIOS Version:', version.BiosVersion);
        version.Versions.forEach(function(component) {
            console.log(component.Description + ':', component.Version);
        });
    }
});

// Using amt_heci naming (identical functionality)
var amtHeci = require('amt_heci');
var heci = new amtHeci();

heci.getVersion(function(version) {
    // Same as above
});
```

### Provisioning State Check

```javascript
var mei = require('amt-mei')();

mei.getProvisioningState(function(state) {
    console.log('Provisioning State:', state.stateStr);
    // Output: "PRE", "IN", or "POST"
});

mei.getProvisioningMode(function(mode) {
    console.log('Provisioning Mode:', mode.modeStr);
    console.log('Legacy Mode:', mode.legacy);
});
```

### Hash-Based Provisioning

```javascript
var mei = require('amt-mei')();
var crypto = require('crypto');

// Calculate SHA256 hash of server certificate
var certPem = '-----BEGIN CERTIFICATE-----\n...';
var certDer = Buffer.from(
    certPem.replace(/-----.*-----/g, '').replace(/\n/g, ''),
    'base64'
);
var certHash = crypto.createHash('sha256').update(certDer).digest();

mei.startConfigurationHBased(
    certHash,
    false,  // hostVpn
    ['example.com', 'corp.example.com'],  // DNS suffixes
    function(result) {
        if (result.status === 0) {
            console.log('Provisioning started');
            console.log('AMT Certificate Hash:', result.hash);
        } else {
            console.log('Provisioning failed, status:', result.status);
        }
    }
);
```

### Multiple Commands (Queued Automatically)

```javascript
var mei = require('amt-mei')();

// All commands execute in order
mei.getUuid(function(uuid) {
    console.log('UUID:', uuid.uuid);
});

mei.getMACAddresses(function(macs) {
    console.log('Dedicated MAC:', macs.DedicatedMAC);
    console.log('Host MAC:', macs.HostMAC);
});

mei.getControlMode(function(mode) {
    console.log('Control Mode:', mode.controlModeStr);
});

// Commands execute sequentially, sharing single HECI connection
```

---

## Error Handling

### Error Event

```javascript
var mei = require('amt-mei')();

mei.on('error', function(err) {
    console.error('PTHI Error:', err);
    // Possible errors:
    // - "HECI not supported" (wrong platform)
    // - "PTHI Connection could not be established" (no ME hardware)
    // - HECI communication errors
});
```

### Status Codes (Lines 487-498)

Common AMT status codes in responses:

| Code | Name | Meaning |
|------|------|---------|
| 0 | AMT_STATUS_SUCCESS | Operation successful |
| 1 | AMT_STATUS_INTERNAL_ERROR | Internal firmware error |
| 3 | AMT_STATUS_INVALID_AMT_MODE | Wrong AMT mode for operation |
| 4 | AMT_STATUS_INVALID_MESSAGE_LENGTH | Malformed command |
| 23 | AMT_STATUS_MAX_LIMIT_REACHED | Resource limit exceeded |
| 36 | AMT_STATUS_INVALID_PARAMETER | Bad parameter value |
| 47 | AMT_STATUS_RNG_GENERATION_IN_PROGRESS | RNG busy |
| 48 | AMT_STATUS_RNG_NOT_READY | RNG not initialized |
| 49 | AMT_STATUS_CERTIFICATE_NOT_READY | Certificate not provisioned |
| 2053 | AMT_STATUS_INVALID_HANDLE | Invalid certificate handle |
| 2068 | AMT_STATUS_NOT_FOUND | Resource not found |

---

## Key Differences from amt-lme

While both use HECI, they serve different purposes:

| Feature | amt-mei (PTHI) | amt-lme (LME) |
|---------|----------------|---------------|
| **GUID** | `heci.GUIDS.AMT` | `heci.GUIDS.LME` |
| **Purpose** | AMT management commands | Port forwarding & events |
| **Protocol** | PTHI (Intel proprietary) | APF (Intel port forward) |
| **Transport** | Command/Response | Stream-based channels |
| **Use Case** | Provisioning, status | Network access, notifications |
| **Connection** | On-demand (auto-disconnect) | Persistent |
| **Queuing** | Sequential command queue | Multiple parallel channels |

---

## Platform-Specific Notes

### Windows
- Requires Intel Management Engine Interface driver
- HECI device typically at `\\.\HECI`
- Driver auto-installs on most Intel platforms
- Check Device Manager for "Intel Management Engine Interface"

### Linux
- Requires `mei_me` kernel module
- Device typically `/dev/mei0` (or `/dev/mei`)
- May require udev rules for permissions:
  ```
  # /etc/udev/rules.d/90-mei.rules
  KERNEL=="mei*", MODE="0660", GROUP="amt"
  ```
- Verify with: `ls -l /dev/mei*`

### macOS
- **Not Supported**
- No HECI hardware on any Mac model
- `require('heci')` will fail
- Use network-based AMT access (amt-wsman.js) if needed

---

## Performance Considerations

1. **Serial Execution** - Commands execute one at a time
   - Each command waits for previous completion
   - Batch operations can be slow

2. **Connection Overhead** - HECI connects/disconnects per command batch
   - Minimal overhead for multiple consecutive commands
   - Some delay between separate API calls

3. **Retry Delays** - Failed connections retry with 250ms delay
   - Up to 5 seconds total retry time (20 × 250ms)

4. **Queue Memory** - All pending commands stored in memory
   - Large numbers of queued commands consume memory
   - No queue size limit implemented

---

## Security Considerations

1. **Local Access Required** - PTHI only accessible with local system access
   - Requires HECI device permissions
   - Typically requires administrator/root privileges

2. **Sensitive Data Exposure** - Methods return sensitive information:
   - `getLocalSystemAccount()` returns plaintext credentials
   - `getCertHashEntries()` exposes certificate information
   - Applications should protect this data

3. **Provisioning Control** - Full provisioning control available:
   - `unprovision()` can remove AMT configuration
   - `startConfigurationHBased()` can reprovision system
   - Should be restricted to privileged users

4. **No Authentication** - PTHI protocol has no authentication layer
   - Security relies on OS-level HECI device permissions
   - Local physical/system access assumed

---

## Troubleshooting

### Module Load Failure

**Error:** `Cannot find module 'heci'`

**Solutions:**
- Verify platform is Windows or Linux (not macOS)
- Check if heci binary module exists in node_modules
- Rebuild native modules: `npm rebuild`

### HECI Connection Failure

**Error:** `PTHI Connection could not be established`

**Solutions:**
- Verify Intel ME driver installed (Windows) or mei_me module loaded (Linux)
- Check device exists: `ls /dev/mei*` (Linux) or Device Manager (Windows)
- Verify AMT enabled in BIOS/firmware
- Check HECI device permissions

### Command Timeout

**Symptoms:** Callbacks never execute, no errors

**Solutions:**
- Check if AMT firmware responding
- Verify HECI device not in use by another application
- Restart MEI driver/service
- Check `dmesg` (Linux) or Event Viewer (Windows) for ME errors

### Invalid Status Codes

**Symptoms:** Callback receives status ≠ 0

**Solutions:**
- Check AMT provisioning state (must be POST for most operations)
- Verify AMT firmware version supports command
- Check command parameters match AMT version
- Consult status code table (lines 487-498)
