# amt.js

Comprehensive JavaScript communication stack for interacting with Intel Active Management Technology (Intel AMT) via WS-Management (WSMAN) protocol. This module wraps WSMAN operations into high-level JavaScript functions to manage, configure, and monitor Intel AMT-enabled devices remotely, enabling out-of-band management capabilities for enterprise systems.

## Platform

**Supported Platforms:**
- Windows (x86/x64) - Full support
- Linux (x86/x64) - Full support

**Excluded Platforms:**
- **macOS** - Not supported

**Exclusion Reasoning:**

macOS is excluded due to fundamental hardware limitations:

1. **No Intel AMT Hardware** - Apple Mac computers do not contain Intel AMT firmware or the Intel Management Engine (ME) required to support AMT functionality. Intel AMT is a firmware-based technology built into Intel vPro chipsets found in business-class PCs.

2. **Missing HECI/MEI Interface** - Intel AMT requires the Host Embedded Controller Interface (HECI), also known as MEI (Management Engine Interface), to communicate with the Management Engine. Mac hardware does not expose this interface.

3. **Architecture Difference** - Even Intel-based Macs (pre-Apple Silicon) do not include the enterprise chipset features required for Intel AMT/vPro. This is by design - Apple uses custom firmware and system management technologies.

4. **Hardware Capability, Not Software** - This is a fundamental hardware capability difference. Intel AMT exists in the chipset firmware layer, independent of the operating system. No amount of software can add AMT capability to Mac hardware.

The module contains no explicit `process.platform` checks because platform compatibility is enforced at the binary module layer (HECI/MEI drivers). Attempting to use this module on macOS will fail when requiring dependent modules like `amt-mei`, `heci`, or `amt-lme`.

## Functionality

### What is Intel AMT?

Intel Active Management Technology (AMT) is an out-of-band management platform built into Intel vPro chipsets that provides:

- **Remote Power Control** - Power on/off/reset even when OS is down
- **Remote Console Access** - KVM (Keyboard/Video/Mouse) redirection
- **Hardware Inventory** - Detailed hardware information collection
- **System Event Logging** - Monitoring and audit trail
- **Remote Provisioning** - Automated configuration
- **Security Features** - TLS, authentication, audit logging
- **Serial-over-LAN (SOL)** - Remote serial console access
- **IDE Redirection (IDER)** - Remote boot from ISO images

### Core Module Capabilities

The module provides a comprehensive wrapper around Intel AMT's WS-Management interface, exposing 150+ methods organized into three schema namespaces:

1. **AMT Schema** - `http://intel.com/wbem/wscim/1/amt-schema/1/`
2. **CIM Schema** - `http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/`
3. **IPS Schema** - `http://intel.com/wbem/wscim/1/ips-schema/1/`

### WSMAN Operations (Lines 55-87)

**Core Protocol Methods:**
- `Subscribe/UnSubscribe` - Event subscription management
- `Get` - Retrieve configuration objects
- `Put` - Update configuration objects
- `Create/Delete` - Manage configuration instances
- `Exec/ExecWithXml` - Execute methods on AMT objects
- `Enum` - Enumerate collections of objects

### Agent Presence Watchdog (Lines 202-212)

**Purpose:** Monitor agent health and trigger actions on failure

**Methods:**
- Register agent presence with AMT firmware
- Assert agent is alive (heartbeat)
- Configure watchdog actions for agent failure scenarios

### Audit & Event Logging (Lines 223-228, 481-508, 710-791)

**Capabilities:**
- Read AMT audit logs with full event parsing
- Export audit signatures for compliance
- Track security events (authentication, authorization)
- Monitor provisioning changes
- Record remote session activity
- Parse 60+ audit event types including:
  - Security administration events
  - Access control changes
  - Network time updates
  - KVM session activity
  - TLS authentication events
  - Provisioning state changes
  - Firmware updates

**Event Entity Types (25+ categories):**
- Users, security services, time sources
- Network interfaces, wireless profiles
- Certificates, Kerberos settings
- Power management, boot options
- Remote access configuration

### Authentication & Authorization (Lines 231-241)

**User Management:**
- User ACL (Access Control List) management
- Kerberos authentication configuration
- Digest authentication setup
- Admin account management
- Realm-based access control

### Power Management (Lines 188-190, 320)

**Remote Power Control:**
- Power state changes (on/off/reset/sleep)
- Power scheme configuration
- Boot order management
- Wake-on-LAN configuration

### Remote Access Services (Lines 270-274)

**Remote Desktop & Console:**
- KVM (Keyboard/Video/Mouse) redirection control
- Serial-over-LAN (SOL) management
- IDE redirection for remote boot from ISO
- User consent configuration

### Network Configuration (Lines 250, 295-298)

**Network Management:**
- Ethernet port settings
- WiFi profile management
- Link preference configuration (wired/wireless priority)
- VPN routing configuration

### Certificate Management (Lines 262-269)

**PKI Operations:**
- Certificate enrollment and management
- Trusted root certificate store
- PKCS#10 certificate request generation
- Key pair generation
- Certificate chain validation

### Provisioning & Setup (Lines 275-285, 366-370)

**AMT Configuration:**
- Host-based setup service
- Remote provisioning operations
- TLS-PSK (Pre-Shared Key) configuration
- MEBx (Management Engine BIOS Extension) password management
- Unprovision operations

### System Information (Lines 481-578)

**Event Log Parsing:**
- System firmware error tracking
- Progress event monitoring
- Hardware sensor data
- Message log retrieval
- 25+ entity types with detailed parsing

### Status Code Translation (Lines 384-475)

**Error Handling:**
- Comprehensive error code mapping (70+ codes)
- Human-readable status strings
- Return value interpretation
- Common error scenarios documented

### Batch Operations (Lines 127-173)

**Efficient Data Collection:**
- Batch enumeration for collecting multiple objects
- Batch GET operations
- Error handling with continuation logic
- Reduces network round-trips for remote operations

## Dependencies

### MeshAgent Module Dependencies

**Direct Dependencies: None**

The `amt.js` module is pure JavaScript with no direct module dependencies. However, it requires a WSMAN transport layer to function.

**Typical Dependency Chain (from CSP.js lines 79-81):**

```javascript
transport = require('amt-wsman-duk');  // WSMAN transport layer
wsman = require('amt-wsman');          // WSMAN protocol implementation
amt = require('amt');                  // This module
```

**Indirect Dependencies (from usage context):**

1. **`amt-wsman`** - `/modules/amt-wsman.js`
   - Provides WS-Management protocol wrapper
   - Required for all WSMAN operations
   - Line 30: `obj.xmlParser = require('amt-xml');`

2. **`amt-wsman-duk`** - `/modules/amt-wsman-duk.js`
   - Transport layer for WSMAN communication
   - Handles HTTP/HTTPS connections to AMT

3. **`amt-xml`** - `/modules/amt-xml.js`
   - XML parser for WSMAN responses
   - Converts WSMAN XML to JavaScript objects

4. **`amt-mei`** - Platform Binary (Windows/Linux only)
   - Management Engine Interface for local AMT access
   - HECI driver wrapper
   - Used for local AMT communication

5. **`amt-lme`** - Platform Binary (Windows/Linux only)
   - LAN Management Engine interface
   - Local management service (LMS) connection

6. **`heci`** - Platform Binary (Windows/Linux only)
   - Host Embedded Controller Interface driver
   - Communicates with Intel Management Engine
   - Required for local AMT operations
   - Line 26 (from amt-mei context): `p.connect(require('heci').GUIDS.AMT, { noPipeline: 1 });`

### Node.js Core Module Dependencies

**None directly in amt.js** - The module uses only pure JavaScript with Buffer operations.

**Related modules use:**
- `events` (in amt-mei.js)
- `http` (in CSP.js for local AMT communication)
- `queue` (in amt-mei.js)

### Platform Binary Dependencies

**Windows:**
- Intel MEI/HECI kernel driver
- Intel Management Engine firmware
- Intel vPro chipset with AMT support

**Linux:**
- Intel MEI kernel module (`mei_me`)
- `/dev/mei` or `/dev/mei0` character device
- Intel Management Engine firmware

**Hardware Requirements:**
- Intel processor with vPro technology
- Intel chipset with Management Engine
- AMT firmware version 6.0+ (modern systems use 11.x-16.x)
- Network interface with AMT support
- BIOS/UEFI with Intel AMT enabled

**macOS:**
- **Not applicable** - Mac hardware lacks all required components

## Key Architecture Notes

### Module Export (Line 1017)

```javascript
module.exports = AmtStackCreateService;
```

### Constructor (Line 27)

```javascript
function AmtStackCreateService(wsmanStack)
```

- Takes a WSMAN stack object as parameter
- Returns an object with 150+ AMT management methods
- Implements async callback pattern for all operations

### No Platform Checks

This module contains no `process.platform` checks because:
1. It's pure JavaScript - platform-agnostic code
2. Platform compatibility is enforced at the binary module layer (HECI/MEI)
3. Attempting to use on macOS will fail when requiring `amt-mei`, `heci`, or `amt-lme`

### Copyright & Licensing (Lines 1-15)

- Copyright 2018-2021 Intel Corporation
- Apache License, Version 2.0
- Written by Ylian Saint-Hilaire

## Usage Context

The module is primarily used by:

1. **`CSP.js`** - Client Setup Provider for automated AMT configuration
2. **`meshcmd.js`** - Command-line tool for AMT management operations
3. **MeshAgent** - The main agent software for remote management

### Example Initialization Pattern

```javascript
// From CSP.js
transport = require('amt-wsman-duk');
wsman = require('amt-wsman');
amt = require('amt');

var wsmanStack = new wsman(new transport(options));
var amtStack = new amt(wsmanStack);

// Now use AMT stack methods
amtStack.GetVersion(function(stack, name, response) {
    console.log('AMT Version:', response);
});
```

### Modular Architecture

This design allows the AMT communication stack to work both:
- **Locally** - Via HECI interface using amt-mei/heci modules
- **Remotely** - Via network WSMAN using amt-wsman-duk transport

## Summary

The amt.js module is a comprehensive, pure JavaScript implementation of Intel AMT management functionality. It provides 150+ methods covering all aspects of AMT management from power control to security configuration. While the module itself is platform-agnostic JavaScript, it requires Intel AMT-capable hardware and supporting binary modules that are only available on Windows and Linux.

**macOS is excluded** because:
- Mac hardware lacks Intel Management Engine firmware
- No HECI/MEI hardware interface available
- Apple uses proprietary system management technologies
- This is a hardware limitation, not a software restriction
- Required binary modules (heci, amt-mei, amt-lme) do not support macOS
