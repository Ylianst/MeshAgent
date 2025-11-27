# DeviceManager.js

Windows-specific device management module that provides comprehensive access to hardware device information through the Windows Setup API and Configuration Manager API. Enables enumeration and querying of installed hardware devices, their properties, drivers, and operational status.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support

**Excluded Platforms:**
- **macOS** - Explicitly excluded
- **Linux** - Explicitly excluded
- **FreeBSD** - Explicitly excluded
- **All non-Windows platforms** - Explicitly excluded

**Exclusion Reasoning:**

**Line 123:** `if (process.platform != 'win32') { throw ('Only Supported on Windows'); }`

The module throws an exception immediately upon instantiation on any non-Windows platform. This is an intentional design decision based on:

1. **Windows-Specific APIs** - The module relies entirely on Windows-specific DLLs:
   - **SetupAPI.dll** - Windows Setup and device installation API
   - **CfgMgr32.dll** - Windows Configuration Manager API
   - **Kernel32.dll** - Windows core system functions

2. **No Cross-Platform Equivalent** - The Windows device management model is fundamentally different from Linux (sysfs/udev) and macOS (IOKit):
   - Windows uses Registry-based device trees
   - Windows Setup API has no direct equivalent on other platforms
   - Device property keys and structures are Windows-specific

3. **Architecture-Specific Implementation** - Uses Windows-specific concepts:
   - Device Information Sets (HDEVINFO)
   - Device Instance IDs
   - Setup Class GUIDs
   - Registry property types (REG_SZ, REG_MULTI_SZ, etc.)

4. **Platform-Specific Purpose** - Designed specifically for Windows device troubleshooting and Intel Management Engine detection on Windows systems

**macOS Alternative:** Would require complete rewrite using IOKit framework and Core Foundation APIs

**Linux Alternative:** Would require sysfs parsing, udev integration, or dbus communication

## Functionality

### Core Method: getDevices(options)

The module provides a single primary method that enumerates and retrieves detailed information about all hardware devices on a Windows system.

### Device Information Retrieved

For each device, the module can retrieve:

**Hardware Identification:**
- `hwid` - Hardware ID (unique vendor/product identifier)
- `locationPath` - Physical location path in the device tree

**Device Description:**
- `friendlyName` - User-friendly device name
- `description` - Technical device description
- `class` - Device class (e.g., "System", "Network", "Display", "USB", "Disk")
- `manufacturer` - Manufacturer name (e.g., "Intel Corporation", "Microsoft")

**Driver Information:**
- `version` - Driver version in format `major.minor.build.revision`

**Device Status:**

- `installState` - Installation state with possible values:
  - `INSTALLED` - Device is properly installed and configured
  - `NEED_REINSTALL` - Device needs reinstallation
  - `FAILED` - Installation failed
  - `INCOMPLETE` - Installation incomplete
  - `UNKNOWN` - Unknown state

- `status` - Operational status:
  - `ENABLED` - Device is functioning normally
  - `HAS_PROBLEM` - Generic problem detected
  - Specific problem codes (see below)

### Problem Code Mapping (Lines 64-116)

The module includes comprehensive mapping of 50+ Windows device problem codes:

**Configuration Issues:**
- `NOT_CONFIGURED` - Device not configured
- `BOOT_CONFIG_CONFLICT` - Boot configuration conflict
- `NEED_RESTART` - System restart required
- `REGISTRY` - Registry corruption

**Driver Problems:**
- `DEVLOADER_FAILED` - Device loader failed
- `DRIVER_FAILED_LOAD` - Driver failed to load
- `DRIVER_FAILED_PRIOR_UNLOAD` - Driver failed to unload properly
- `DRIVER_BLOCKED` - Driver blocked by policy
- `UNSIGNED_DRIVER` - Unsigned driver
- `OUT_OF_MEMORY` - Insufficient memory for driver

**Resource Conflicts:**
- `NORMAL_CONFLICT` - Resource conflict
- `CANT_SHARE_IRQ` - IRQ sharing conflict
- `IRQ_TRANSLATION_FAILED` - IRQ translation failed
- `DUPLICATE_DEVICE` - Duplicate device detected

**Hardware Problems:**
- `HARDWARE_DISABLED` - Hardware disabled in firmware
- `DEVICE_NOT_THERE` - Device not present
- `DISABLED` - Device disabled by user/system
- `DISABLED_SERVICE` - Related service disabled

**Installation Issues:**
- `FAILED_INSTALL` - Installation failed
- `REINSTALL` - Reinstallation required
- `FAILED_DRIVER_ENTRY` - Driver entry point failed
- `WILL_BE_REMOVED` - Marked for removal

And 30+ additional specific error conditions covering power management, system setup, device topology, registry corruption, phantom devices, and more.

### Filtering Options

The `getDevices(options)` method supports filtering by:

**By Manufacturer:**
```javascript
getDevices({ manufacturer: 'Intel Corporation' })  // Exact match
getDevices({ manufacturer: 'Intel*' })             // Wildcard match
```

**By Device Class:**
```javascript
getDevices({ class: 'System' })   // All system devices
getDevices({ class: 'Network' })  // All network adapters
```

**Combined Filtering:**
```javascript
getDevices({ manufacturer: 'Intel*', class: 'System' })
```

## Known Usage in Codebase

### CSP.js (Intel ME Management) - Line 319

```javascript
var Devices = require('DeviceManager').getDevices({
    manufacturer: 'Intel*',
    class: 'System'
});
```

**Purpose:** Detect Intel Management Engine Interface driver

**Use Case:**
- Checks if Intel MEI driver is installed
- Verifies driver version meets requirements
- Confirms driver is functioning (status check)
- Part of Intel Client Service Platform (CSP) functionality

**Typical Output:**
```javascript
[{
    friendlyName: 'Intel(R) Management Engine Interface',
    description: 'Intel(R) Management Engine Interface',
    manufacturer: 'Intel Corporation',
    class: 'System',
    hwid: 'PCI\\VEN_8086&DEV_9D3A',
    version: '2102.100.0.1044',
    installState: 'INSTALLED',
    status: 'ENABLED'
}]
```

## Technical Implementation

### Memory Management

**Dynamic Buffer Allocation:**
- Handles `ERROR_INSUFFICIENT_BUFFER (122)` errors gracefully
- Initial buffer size: 1024 bytes
- Automatically resizes buffers as needed
- Prevents buffer overflow issues

**Buffer Growth Strategy:**
1. Attempt operation with initial buffer
2. If insufficient, get required size from Windows API
3. Allocate new buffer with required size
4. Retry operation

### Data Structures

**SP_DEVINFO_DATA (Device Information):**
- 32-bit systems: 28 bytes
- 64-bit systems: 32 bytes
- Contains: structure size, class GUID, device instance, reserved

**SP_DRVINFO_DATA (Driver Information):**
- 32-bit systems: 796 bytes
- 64-bit systems: 800 bytes
- Contains: driver type, description, manufacturer, provider, version, file date

**DEVPROPKEY (Device Property Key):**
- 20 bytes total
- 16-byte GUID + 4-byte property ID
- Used for querying device properties

### Architecture Support

**Pointer Size Detection:**
```javascript
if (this._marshal.PointerSize == 4) {
    // 32-bit Windows
    devInfoData = Buffer.alloc(28);
} else {
    // 64-bit Windows
    devInfoData = Buffer.alloc(32);
}
```

**Structure Alignment:**
- Handles different structure sizes between architectures
- Adjusts offsets based on pointer size
- Ensures correct data alignment

### Error Handling

**Windows Error Codes:**
- `ERROR_NO_MORE_ITEMS (259)` - End of enumeration
- `ERROR_INSUFFICIENT_BUFFER (122)` - Buffer too small
- `ERROR_INVALID_DATA (13)` - Invalid device data

**Error Recovery:**
- Graceful handling of missing properties
- Continues enumeration on individual device errors
- Returns partial results on non-fatal errors

## Dependencies

### Native Module Dependencies

#### _GenericMarshal (Line 125)

```javascript
this._marshal = require('_GenericMarshal');
```

**Purpose:** FFI (Foreign Function Interface) library for calling Windows DLLs

**Capabilities:**
- Enables JavaScript to call native Windows DLL functions
- Provides memory marshaling between JavaScript and native code
- Handles pointer arithmetic and structure packing
- Type conversion between JavaScript and C types

**Source:** `/microscript/ILibDuktape_GenericMarshal.c`

### Windows System DLL Dependencies

#### Kernel32.dll (Line 127)

```javascript
this._kernel32 = this._marshal.CreateNativeProxy('Kernel32.dll');
this._kernel32.CreateMethod('GetLastError');
```

**Methods Used:**
- `GetLastError()` - Retrieves last Windows error code

**Purpose:** Error handling and diagnostics

---

#### SetupAPI.dll (Lines 129-143) - Primary Device Interface

```javascript
this._setupapi = this._marshal.CreateNativeProxy('SetupAPI.dll');
```

**Methods Used:**

**Device Enumeration:**
- `SetupDiGetClassDevsA()` - Creates device information set
- `SetupDiEnumDeviceInfo()` - Iterates through devices in set
- `SetupDiDestroyDeviceInfoList()` - Cleanup/free resources

**Property Retrieval:**
- `SetupDiGetDevicePropertyW()` - Retrieves device properties (Unicode)
- `SetupDiGetDevicePropertyKeys()` - Gets available property keys
- `SetupDiGetDeviceRegistryPropertyA()` - Reads registry properties (ANSI)

**Driver Information:**
- `SetupDiBuildDriverInfoList()` - Builds list of compatible drivers
- `SetupDiEnumDriverInfoA()` - Enumerates driver information

**Installation Parameters:**
- `SetupDiGetDeviceInstallParamsA()` - Gets installation parameters
- Used to check install state (INSTALLED, NEED_REINSTALL, etc.)

---

#### CfgMgr32.dll (Lines 144-145) - Configuration Manager

```javascript
this._cfgmgr32 = this._marshal.CreateNativeProxy('CfgMgr32.dll');
this._cfgmgr32.CreateMethod('CM_Get_DevNode_Status');
```

**Methods Used:**
- `CM_Get_DevNode_Status()` - Retrieves device node status and problem code

**Purpose:** Advanced device status queries beyond Setup API capabilities

### Windows API Constants

#### Device Enumeration Flags (Lines 149-150)

- `DIGCF_PRESENT (0x02)` - Only enumerate devices currently present
- `DIGCF_ALLCLASSES (0x04)` - Include all device setup classes

**Usage:** Combined as `DIGCF_PRESENT | DIGCF_ALLCLASSES` for comprehensive enumeration

#### Device Registry Properties (SPDRP_*) - Lines 23-59

36+ property constants for querying device information:

**Identity Properties:**
- `SPDRP_DEVICEDESC (0)` - Device description
- `SPDRP_HARDWAREID (1)` - Hardware IDs
- `SPDRP_CLASS (7)` - Device class
- `SPDRP_MFG (11)` - Manufacturer
- `SPDRP_FRIENDLYNAME (12)` - Friendly name
- `SPDRP_LOCATION_INFORMATION (13)` - Location

**Driver Properties:**
- `SPDRP_DRIVER (9)` - Driver key
- `SPDRP_ENUMERATOR_NAME (22)` - Enumerator name

**Hardware Properties:**
- `SPDRP_PHYSICAL_DEVICE_OBJECT_NAME (14)` - PDO name
- `SPDRP_CAPABILITIES (15)` - Device capabilities
- `SPDRP_BUSNUMBER (21)` - Bus number
- `SPDRP_DEVTYPE (25)` - Device type

**Configuration:**
- `SPDRP_CONFIGFLAGS (10)` - Configuration flags
- `SPDRP_REMOVAL_POLICY (31)` - Removal policy
- `SPDRP_INSTALL_STATE (34)` - Install state

And 20+ more properties covering power data, security, UI, base container ID, etc.

#### Device Node Status Flags (Lines 61-62)

- `DN_HAS_PROBLEM (0x00000400)` - Device has a problem
- `DN_DISABLEABLE (0x00002000)` - Device can be disabled

**Usage:** Bitmask checking with `CM_Get_DevNode_Status()` results

### Dependency Chain Summary

```
DeviceManager.js
├─── _GenericMarshal (Line 125) - FFI library
│    └─── Native marshaling layer
├─── Kernel32.dll (Line 127) - Windows core
│    └─── GetLastError() - Error retrieval
├─── SetupAPI.dll (Lines 129-143) - Device enumeration
│    ├─── SetupDiGetClassDevsA() - Create device set
│    ├─── SetupDiEnumDeviceInfo() - Enumerate devices
│    ├─── SetupDiGetDevicePropertyW() - Get properties
│    ├─── SetupDiGetDeviceRegistryPropertyA() - Registry properties
│    ├─── SetupDiBuildDriverInfoList() - Driver info
│    ├─── SetupDiEnumDriverInfoA() - Enumerate drivers
│    └─── SetupDiDestroyDeviceInfoList() - Cleanup
└─── CfgMgr32.dll (Lines 144-145) - Configuration Manager
     └─── CM_Get_DevNode_Status() - Advanced status
```

## License

**Apache License 2.0**
Copyright 2018 Intel Corporation

## Summary

DeviceManager.js is a sophisticated Windows-only module providing deep integration with Windows device management APIs. It offers comprehensive hardware inventory capabilities including device properties, driver information, and operational status with detailed problem code mapping.

**Explicitly excludes all non-Windows platforms** because:
- Relies entirely on Windows-specific DLLs (SetupAPI.dll, CfgMgr32.dll, Kernel32.dll)
- Uses Windows-specific device management model and data structures
- Throws exception on line 123 for any platform other than win32
- No cross-platform equivalent - would require complete rewrite for macOS (IOKit) or Linux (sysfs/udev)
- Intentionally designed for Windows hardware management only

The module is currently used for Intel Management Engine Interface driver detection but could be leveraged for broader hardware management tasks on Windows systems. Alternative approaches would be required for device management on macOS and Linux platforms.
